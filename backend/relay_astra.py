#!/usr/bin/env python3
"""ASTRA public webhook relay — isolated module (Ric Dev Summary 2026-10-11).

Authorized: Ric 2026-10-11 (public relay + outbound local consumer architecture).
Replaces inbound HTTPS to the NAT'd local VM, which is structurally impossible.

Public surface (path-routed by launcher.py): POST /webhook/astra only.
Pipeline per event:
    HMAC-SHA256 (ASTRA_TV_HMAC_SECRET) -> schema -> version pin ->
    stale/dedup -> durable JSONL append -> ACK
Consumer surface (same process):
    GET  /webhook/astra/pending   (auth: ASTRA_RELAY_CONSUMER_SECRET)
    POST /webhook/astra/ack       (auth: ASTRA_RELAY_CONSUMER_SECRET)

NO trading logic. NO order authority. NO Phase 1 access. NO broker access.
Stdlib only. Binds 127.0.0.1 only — the launcher exposes it publicly.
Fails closed: refuses to accept events when ASTRA_TV_HMAC_SECRET is unset.

Durable store: ~/astra_relay/ (Render disk) or $ASTRA_RELAY_DATA_DIR
  events.jsonl     append-only: every accepted event {event_id, received_at, body}
  delivered.jsonl  append-only: acked event_ids {event_id, acked_at}
Pending = received minus delivered. Crash-safe: sets rebuilt from disk on start.

HMAC scheme: byte-identical to strategy2_astra/webhook_receiver.py —
HMAC-SHA256 hex over the canonical JSON (28 ASCII-sorted contract fields,
Pine-compatible 2dp formatting), carried in the payload_hash field AND the
X-Astra-Signature header.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import math
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ------------------------------------------------------------ config
HOST = "127.0.0.1"
PORT = int(os.environ.get("ASTRA_RELAY_PORT", "18788"))
DATA_DIR = os.path.expanduser(os.environ.get(
    "ASTRA_RELAY_DATA_DIR", "~/astra_relay"))
TV_SECRET_VAR = "ASTRA_TV_HMAC_SECRET"
CONSUMER_SECRET_VAR = "ASTRA_RELAY_CONSUMER_SECRET"
MAX_BODY = 1_000_000
PENDING_CAP = 50
# Coarse wall-clock staleness backstop (local side enforces the real 8-bar rule).
STALE_AFTER_SEC = 1800
FUTURE_SKEW_SEC = 300
PINNED_STRATEGY_VERSION = "1.0.2"

EVENTS_LOG = os.path.join(DATA_DIR, "events.jsonl")
DELIVERED_LOG = os.path.join(DATA_DIR, "delivered.jsonl")

# --------------------------------- canonical HMAC (ported verbatim logic)
CANONICAL_KEYS = (
    "absorption_state", "armed", "chart_timeframe", "contract", "direction",
    "directional_gap", "event_id", "event_type", "flow_state",
    "footprint_available", "liquidity_price", "liquidity_type", "long_score",
    "market_ts", "observed_at", "reclaim_state", "release_state", "room_r",
    "schema_version", "setup_id", "short_score", "source_bar_close",
    "strategy_id", "strategy_run_id", "strategy_version", "sweep_confirmed",
    "symbol", "target_reference",
)
assert list(CANONICAL_KEYS) == sorted(CANONICAL_KEYS)
REQUIRED_FIELDS = CANONICAL_KEYS + ("payload_hash",)
EVENT_TYPES = frozenset({
    "SWEEP_DETECTED", "ABSORPTION_CONFIRMED", "RECLAIM_CONFIRMED",
    "FLOW_SHIFT", "ARMED", "RELEASE", "DATA_UNAVAILABLE", "TEST_PING",
})
DIRECTIONS = frozenset({"LONG", "SHORT", "NONE"})
_BOOL_FIELDS = frozenset({"armed", "sweep_confirmed", "footprint_available"})
_INT_FIELDS = frozenset({
    "directional_gap", "long_score", "short_score",
    "market_ts", "observed_at", "source_bar_close",
})
_STR_FIELDS = frozenset({
    "event_id", "symbol", "contract", "chart_timeframe",
    "setup_id", "strategy_run_id", "strategy_version",
})


def _canon_number_2dp(value) -> str:
    # Bit-for-bit replica of the Pine emitter's f_jnum2() (see webhook_receiver.py).
    if value is None:
        return "null"
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("numeric field got non-numeric value: %r" % (value,))
    x = float(value)
    if x == 0:
        return "0.00"
    r = int(math.floor(abs(x) * 100.0 + 0.5))
    cents = r % 100
    return ("-" if x < 0 else "") + str(r // 100) + "." + (
        "0" + str(cents) if cents < 10 else str(cents))


def _canon_value(key: str, value) -> str:
    if key in _BOOL_FIELDS:
        if type(value) is not bool:
            raise ValueError("%s must be boolean" % key)
        return "true" if value else "false"
    if key in _INT_FIELDS:
        if type(value) is not int:
            raise ValueError("%s must be int" % key)
        return str(value)
    if key in ("liquidity_price", "room_r"):
        return _canon_number_2dp(value)
    if not isinstance(value, str):
        raise ValueError("%s must be string" % key)
    return json.dumps(value, ensure_ascii=True)


def canonical_event_json(payload: dict) -> str:
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    missing = [k for k in CANONICAL_KEYS if k not in payload]
    if missing:
        raise ValueError("missing canonical fields: %s" % missing)
    parts = [json.dumps(k, ensure_ascii=True) + ":" + _canon_value(k, payload[k])
             for k in CANONICAL_KEYS]
    return "{" + ",".join(parts) + "}"


def compute_payload_hmac(payload: dict, secret: str) -> str:
    if not secret:
        raise ValueError("cannot sign/verify with an empty secret")
    body = canonical_event_json(payload).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_payload(raw_body: bytes, signature_header: str, secret: str) -> bool:
    try:
        if not raw_body or not secret:
            return False
        payload = json.loads(raw_body.decode("utf-8"))
        if not isinstance(payload, dict):
            return False
        declared = payload.get("payload_hash")
        if not isinstance(declared, str) or not declared:
            return False
        expected = compute_payload_hmac(payload, secret)
        if not hmac.compare_digest(expected, declared):
            return False
        if signature_header and not hmac.compare_digest(expected, signature_header):
            return False
        return True
    except Exception:
        return False


# ------------------------------------------------------------ store
_lock = threading.Lock()
_seen_ids: set = set()       # every event_id ever durably stored
_delivered_ids: set = set()  # event_ids acked by the local consumer


def _read_jsonl(path):
    out = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    except OSError:
        pass
    return out


def _init_store():
    os.makedirs(DATA_DIR, exist_ok=True)
    for rec in _read_jsonl(EVENTS_LOG):
        eid = rec.get("event_id")
        if eid:
            _seen_ids.add(eid)
    for rec in _read_jsonl(DELIVERED_LOG):
        eid = rec.get("event_id")
        if eid:
            _delivered_ids.add(eid)


def _append_jsonl(path, rec):
    with open(path, "a") as fh:
        fh.write(json.dumps(rec) + "\n")


def _pending_events():
    with _lock:
        pending_ids = [eid for eid in _seen_ids if eid not in _delivered_ids]
    # pull bodies from the events log (small scale; rebuild index if needed)
    bodies = {}
    for rec in _read_jsonl(EVENTS_LOG):
        eid = rec.get("event_id")
        if eid in pending_ids and eid not in bodies:
            bodies[eid] = rec
    return [bodies[eid] for eid in pending_ids if eid in bodies][:PENDING_CAP]


# ------------------------------------------------------------ validation
def _validate_schema(payload: dict):
    """Return None if valid, else a reason string. Structural only."""
    if not isinstance(payload, dict):
        return "SCHEMA_INVALID: not an object"
    for f in REQUIRED_FIELDS:
        if f not in payload:
            return "SCHEMA_INVALID: missing %s" % f
    if payload.get("schema_version") != "astra-edge-event-v1":
        return "SCHEMA_INVALID: schema_version"
    if payload.get("strategy_version") != PINNED_STRATEGY_VERSION:
        return "VERSION_MISMATCH: want %s" % PINNED_STRATEGY_VERSION
    if payload.get("event_type") not in EVENT_TYPES:
        return "SCHEMA_INVALID: event_type"
    if not isinstance(payload.get("event_id"), str) or not payload["event_id"]:
        return "SCHEMA_INVALID: event_id"
    if payload.get("direction") not in DIRECTIONS:
        return "SCHEMA_INVALID: direction"
    for f in _BOOL_FIELDS:
        if type(payload.get(f)) is not bool:
            return "SCHEMA_INVALID: %s not bool" % f
    for f in _INT_FIELDS:
        if type(payload.get(f)) is not int:
            return "SCHEMA_INVALID: %s not int" % f
    for f in _STR_FIELDS:
        if not isinstance(payload.get(f), str):
            return "SCHEMA_INVALID: %s not str" % f
    return None


def _check_stale(payload: dict):
    now_ms = int(time.time() * 1000)
    obs = payload.get("observed_at")
    if not isinstance(obs, int):
        return "STALE_CHECK_FAIL"
    if obs < now_ms - STALE_AFTER_SEC * 1000:
        return "STALE_EVENT"
    if obs > now_ms + FUTURE_SKEW_SEC * 1000:
        return "FUTURE_EVENT"
    return None


# ------------------------------------------------------------ handler
class RelayHandler(BaseHTTPRequestHandler):
    server_version = "AstraRelay/1.0"

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _consumer_authed(self):
        secret = os.environ.get(CONSUMER_SECRET_VAR, "")
        if not secret:
            return False
        presented = self.headers.get("X-Relay-Auth", "")
        return bool(presented) and hmac.compare_digest(presented, secret)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/webhook/astra":
            self._handle_webhook()
        elif path == "/webhook/astra/ack":
            self._handle_ack()
        else:
            self._send(404, {"accepted": False, "reason": "NOT_FOUND"})

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/webhook/astra/pending":
            self._handle_pending()
        else:
            self._send(404, {"accepted": False, "reason": "NOT_FOUND"})

    def _handle_webhook(self):
        tv_secret = os.environ.get(TV_SECRET_VAR, "")
        if not tv_secret:
            self._send(503, {"accepted": False,
                             "reason": "RELAY_NOT_CONFIGURED"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._send(400, {"accepted": False, "reason": "BAD_LENGTH"})
            return
        raw = self.rfile.read(length)
        sig = self.headers.get("X-Astra-Signature", "")
        if not verify_payload(raw, sig, tv_secret):
            self._send(200, {"accepted": False, "reason": "HMAC_FAIL"})
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send(200, {"accepted": False, "reason": "BAD_JSON"})
            return
        reason = _validate_schema(payload)
        if reason:
            self._send(200, {"accepted": False, "reason": reason})
            return
        reason = _check_stale(payload)
        if reason:
            self._send(200, {"accepted": False, "reason": reason})
            return
        event_id = payload["event_id"]
        with _lock:
            if event_id in _seen_ids:
                self._send(200, {"accepted": True, "event_id": event_id,
                                 "duplicate": True, "stored": False})
                return
            rec = {
                "event_id": event_id,
                "received_at": datetime.datetime.now(
                    datetime.timezone.utc).isoformat(),
                "body": raw.decode("utf-8"),
            }
            _append_jsonl(EVENTS_LOG, rec)
            _seen_ids.add(event_id)
        self._send(200, {"accepted": True, "event_id": event_id,
                         "duplicate": False, "stored": True})

    def _handle_pending(self):
        if not self._consumer_authed():
            self._send(401, {"ok": False, "reason": "UNAUTHORIZED"})
            return
        events = _pending_events()
        self._send(200, {"ok": True, "count": len(events),
                         "events": [{"event_id": e["event_id"],
                                     "received_at": e["received_at"],
                                     "body": e["body"]} for e in events]})

    def _handle_ack(self):
        if not self._consumer_authed():
            self._send(401, {"ok": False, "reason": "UNAUTHORIZED"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 65536:
            self._send(400, {"ok": False, "reason": "BAD_LENGTH"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            ids = payload.get("event_ids", [])
        except Exception:
            self._send(400, {"ok": False, "reason": "BAD_JSON"})
            return
        if not isinstance(ids, list):
            self._send(400, {"ok": False, "reason": "BAD_JSON"})
            return
        acked = 0
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with _lock:
            for eid in ids:
                if isinstance(eid, str) and eid and eid not in _delivered_ids:
                    _append_jsonl(DELIVERED_LOG,
                                  {"event_id": eid, "acked_at": now})
                    _delivered_ids.add(eid)
                    acked += 1
        self._send(200, {"ok": True, "acked": acked})

    def log_message(self, fmt, *args):
        pass


def main():
    _init_store()
    print("AstraRelay/1.0 on http://%s:%d/webhook/astra (data=%s)" % (
        HOST, PORT, DATA_DIR), flush=True)
    print("tv_secret_configured=%s consumer_secret_configured=%s stored_events=%d" % (
        bool(os.environ.get(TV_SECRET_VAR)), bool(os.environ.get(CONSUMER_SECRET_VAR)),
        len(_seen_ids)), flush=True)
    ThreadingHTTPServer((HOST, PORT), RelayHandler).serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())
