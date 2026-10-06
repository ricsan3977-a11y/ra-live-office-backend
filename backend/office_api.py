#!/usr/bin/env python3
"""R&A Live Office backend — office-api-v1.

Serves:
  GET /api/office/state   canonical snapshot (JSON)
  GET /api/office/events  live event stream (SSE)
  GET /...                static frontend (local dev; Netlify serves it in prod)

Stdlib only. READ-ONLY: no POST/PUT/DELETE routes exist. Never fabricates:
any unreadable section is reported offline, never invented.

Run:  python3 backend/office_api.py [port]   (default 8787)
"""
from __future__ import annotations

import datetime
import glob
import json
import os
import queue
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
FRONTEND_DIR = os.path.join(PROJECT, "frontend")
DATA_ROOT = os.path.expanduser("~/workspace")
VERSION = "office-api-v1"
POLL_SECONDS = 20

# ---------------------------------------------------------------- readers

def _today_ct() -> str:
    return datetime.datetime.now(
        datetime.timezone(datetime.timedelta(hours=-5))).strftime("%Y-%m-%d")


def _read_text(path: str) -> str | None:
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return None


_ACCT_RE = re.compile(
    r"\*\*Account:\*\*\s*equity\s*\$(?P<equity>[\d,+.\-]+)\s*\|\s*"
    r"cash\s*\$(?P<cash>[\d,+.\-]+)\s*\|\s*"
    r"day P&L\s*\$(?P<pnl>[\d,+.\-]+)\s*\|\s*"
    r"open positions\s*(?P<pos>\d+)\s*\|\s*"
    r"Guardian halt:\s*(?P<halt>\w+)")


def _parse_brief_account(text: str) -> dict | None:
    m = _ACCT_RE.search(text or "")
    if not m:
        return None
    num = lambda s: float(s.replace(",", ""))
    return {"equity": num(m.group("equity")), "cash": num(m.group("cash")),
            "day_pnl": num(m.group("pnl")),
            "open_positions": int(m.group("pos")),
            "guardian_halt": m.group("halt").strip().lower() in
                             ("yes", "true", "halted")}


def _latest_brief(agent_dir: str) -> tuple[str | None, str | None]:
    bdir = os.path.join(DATA_ROOT, agent_dir, "briefs")
    today = os.path.join(bdir, _today_ct() + ".md")
    if os.path.exists(today):
        return today, _today_ct()
    cands = sorted(glob.glob(os.path.join(bdir, "*.md")))
    if cands:
        return cands[-1], os.path.basename(cands[-1])[:-3]
    return None, None


def read_futures() -> dict:
    """30 paper agents from briefs + eval_state.json. Offline on any gap."""
    try:
        names = json.load(open(os.path.join(
            DATA_ROOT, "trading-agent", "agent_names.json")))
    except OSError:
        return {"status": "offline", "note": "agent_names.json unreadable"}
    agents = []
    for letter in sorted(names, key=lambda x: (len(x), x)):
        info = names[letter]
        adir = info.get("dir", "trading-agent")
        bpath, bdate = _latest_brief(adir)
        acct = _parse_brief_account(_read_text(bpath)) if bpath else None
        estate = None
        try:
            estate = json.load(open(os.path.join(
                DATA_ROOT, adir, "eval_state.json")))
        except OSError:
            estate = None
        if acct is None:
            return {"status": "offline",
                    "note": f"no parseable brief for agent {letter}"}
        est = estate or {}
        # Rooms are computed only from real eval fields; else null.
        realized = est.get("realized_today")
        dll = est.get("daily_loss_limit")
        daily_room = (max(0.0, dll + realized)
                      if isinstance(dll, (int, float))
                      and isinstance(realized, (int, float)) else None)
        last_eq = est.get("last_equity")
        floor = est.get("trailing_floor")
        dd_room = ((last_eq - floor)
                   if isinstance(last_eq, (int, float))
                   and isinstance(floor, (int, float)) else None)
        agents.append({
            "id": letter, "name": info.get("name", letter),
            "agent_id": letter, "agent_name": info.get("name", letter),
            "account_id": letter,
            "equity": acct["equity"], "cash": acct["cash"],
            "day_pnl": acct["day_pnl"],
            "open_positions": acct["open_positions"], "position": None,
            "position_status": ("OPEN" if acct["open_positions"] > 0
                                else "IDLE"),
            "guardian_halt": acct["guardian_halt"],
            "guardian_status": ("HALTED" if acct["guardian_halt"]
                                else "ACTIVE"),
            "eval_state": est.get("eval_status", "UNKNOWN"),
            "strategy": None, "symbol": None, "direction": None,
            "entry": None, "current": None, "stop": None, "target": None,
            "realized_pnl": realized, "unrealized_pnl": None, "net_r": None,
            "daily_loss_room": daily_room, "drawdown_room": dd_room,
            "position_cap_usage": None,
            "fidelity": None, "concentration": None,
            "last_event_ts": None,
            "brief_date": bdate,
        })
    desk = {"equity": round(sum(a["equity"] for a in agents), 2),
            "day_pnl": round(sum(a["day_pnl"] for a in agents), 2),
            "open_positions": sum(a["open_positions"] for a in agents),
            "n_agents": len(agents)}
    return {"status": "live", "as_of_brief": _today_ct(),
            "agents": agents, "desk": desk}


def read_crypto() -> dict:
    # Canonical spec §1: crypto has no live connected feed. C9 runs are
    # shadow/qualification evidence, not a live department feed.
    return {"status": "not_connected",
            "note": "NOT CONNECTED / SHADOW DATA UNAVAILABLE"}


def read_p11() -> dict:
    path = os.path.join(DATA_ROOT, "trading-agent",
                        "casebook_records.jsonl")
    text = _read_text(path)
    if not text:
        return {"status": "offline", "note": "casebook_records.jsonl missing"}
    cases = []
    for line in text.strip().split("\n")[-8:]:
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        cases.append({"case_id": r.get("case_id"),
                      "kind": r.get("kind", r.get("contract")),
                      "archived_at": r.get("created_at")})
    cases.reverse()
    return {"status": "live", "recent_cases": cases,
            "n_cases": len(text.strip().split("\n"))}


def _current_seq() -> int:
    with _seq_lock:
        return _event_seq


def read_state() -> dict:
    """Build the canonical snapshot. Sections fail to offline, never fake."""
    now = datetime.datetime.now(
        datetime.timezone(datetime.timedelta(hours=-5))).isoformat()
    return {
        "ok": True,
        "generated_at": now,
        "state_seq": _current_seq(),
        "backend": {"version": VERSION, "mode": "live"},
        "departments": {
            "futures": read_futures(),
            "crypto": read_crypto(),
            "tradeify247": {"status": "spec_only",
                            "note": "engine not built; no live data"},
        },
        "p11": read_p11(),
        "notifications": {"status": "offline",
                         "note": "no notification log on disk yet"},
        "vp": {"status": "offline",
               "note": "no VP brief on disk yet"},
    }


# ------------------------------------------------------- change detection

_subscribers: list[queue.Queue] = []
_sub_lock = threading.Lock()
_last_state: dict | None = None
_event_seq = 0
_seq_lock = threading.Lock()


def _next_seq() -> int:
    global _event_seq
    with _seq_lock:
        _event_seq += 1
        return _event_seq


def _emit(event_type: str, *, agent_id: str | None = None,
          account_id: str | None = None, desk: str = "evaluation",
          payload: dict | None = None):
    """Canonical event envelope (spec §6). Dedup key: event_id."""
    import uuid
    now = datetime.datetime.now(
        datetime.timezone(datetime.timedelta(hours=-5))).isoformat()
    envelope = {
        "event_id": f"{int(time.time()*1000)}-{uuid.uuid4().hex[:8]}",
        "event_type": event_type,
        "event_ts": now,
        "observed_at": now,
        "agent_id": agent_id,
        "account_id": account_id if account_id is not None else agent_id,
        "desk": desk,
        "seq": _next_seq(),
        "payload": payload or {},
    }
    wire = f"event: {event_type}\ndata: {json.dumps(envelope)}\n\n"
    with _sub_lock:
        for q in _subscribers:
            try:
                q.put_nowait(wire)
            except queue.Full:
                pass


def _agent_map(state: dict) -> dict:
    fut = state["departments"]["futures"]
    if fut.get("status") != "live":
        return {}
    return {a["id"]: a for a in fut["agents"]}


def _diff(old: dict | None, new: dict):
    if old is None:
        return
    oa, na = _agent_map(old), _agent_map(new)
    for aid, a in na.items():
        o = oa.get(aid)
        if o is None:
            continue
        if o["open_positions"] == 0 and a["open_positions"] > 0:
            _emit("TRADE_OPENED", agent_id=aid,
                  payload={"agent_name": a["name"], "symbol": None,
                           "direction": None, "qty": a["open_positions"],
                           "entry": None})
        elif o["open_positions"] > 0 and a["open_positions"] == 0:
            _emit("TRADE_CLOSED", agent_id=aid,
                  payload={"agent_name": a["name"], "symbol": None,
                           "direction": None, "exit": None,
                           "realized_pnl": None})
        elif a["open_positions"] > 0:
            _emit("TRADE_UPDATED", agent_id=aid,
                  payload={"symbol": None, "unrealized_pnl": None})
        if o["eval_state"] != a["eval_state"]:
            _emit("EVAL_STATE_CHANGED", agent_id=aid,
                  payload={"old_state": o["eval_state"],
                           "new_state": a["eval_state"]})
            _emit("FUNDED_STATE_CHANGED", agent_id=aid,
                  payload={"old_state": o["eval_state"],
                           "new_state": a["eval_state"]})
            if a["eval_state"] == "TARGET_MET":
                _emit("TARGET_REACHED", agent_id=aid,
                      payload={"symbol": None})
        if not o["guardian_halt"] and a["guardian_halt"]:
            _emit("GUARDIAN_BLOCK", agent_id=aid,
                  payload={"reason": "daily halt triggered"})
        elif o["guardian_halt"] and not a["guardian_halt"]:
            _emit("GUARDIAN_PASS", agent_id=aid,
                  payload={"detail": "halt cleared"})
    # Crypto has no live connected feed (spec §1): no crypto events emitted.
    op_, np_ = old.get("p11", {}), new.get("p11", {})
    if (op_.get("status") == "live" and np_.get("status") == "live"
            and np_.get("n_cases", 0) > op_.get("n_cases", 0)):
        for c in np_["recent_cases"][:np_["n_cases"] - op_["n_cases"]]:
            _emit("P11_CASE_ARCHIVED",
                  payload={"case_id": c.get("case_id"),
                           "kind": c.get("kind")})


def _poller():
    global _last_state
    while True:
        try:
            new = read_state()
            _diff(_last_state, new)
            _last_state = new
        except Exception:
            pass
        time.sleep(POLL_SECONDS)


# ---------------------------------------------------------------- server

_MIME = {".html": "text/html", ".js": "text/javascript",
         ".css": "text/css", ".json": "application/json",
         ".png": "image/png", ".webmanifest": "application/manifest+json"}


class Handler(BaseHTTPRequestHandler):
    server_version = "OfficeAPI/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/office/state":
            body = json.dumps(read_state()).encode()
            self._send(200, body, "application/json")
            return
        if path == "/api/office/events":
            self._sse()
            return
        if path == "/api/office/health":
            self._send(200, b'{"ok":true}', "application/json")
            return
        # static frontend (local dev)
        rel = path.lstrip("/") or "index.html"
        if ".." in rel or rel.startswith("/"):
            self._send(404, b"not found", "text/plain")
            return
        fpath = os.path.join(FRONTEND_DIR, rel)
        if os.path.isdir(fpath):
            fpath = os.path.join(fpath, "index.html")
        if not os.path.exists(fpath):
            fpath = os.path.join(FRONTEND_DIR, "index.html")
        try:
            with open(fpath, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send(404, b"not found", "text/plain")
            return
        ext = os.path.splitext(fpath)[1]
        self._send(200, body, _MIME.get(ext, "application/octet-stream"))

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        q: queue.Queue = queue.Queue(maxsize=100)
        with _sub_lock:
            _subscribers.append(q)
        try:
            snap = json.dumps(read_state())
            self.wfile.write(f"event: snapshot\ndata: {snap}\n\n".encode())
            self.wfile.flush()
            last_beat = time.time()
            while True:
                try:
                    payload = q.get(timeout=5)
                    self.wfile.write(payload.encode())
                    self.wfile.flush()
                except queue.Empty:
                    pass
                if time.time() - last_beat > 15:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
                    last_beat = time.time()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _sub_lock:
                if q in _subscribers:
                    _subscribers.remove(q)


def main() -> int:
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    threading.Thread(target=_poller, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"office-api-v1 on 127.0.0.1:{port}", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
