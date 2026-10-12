#!/usr/bin/env python3
"""Synthetic end-to-end acceptance: Pine-like JSON -> edge -> relay ->
consumer fetch -> local listener (handle_webhook, fresh state) -> ACK.

Uses a relay on a test port with throwaway secrets and temp dirs. Does NOT
touch the live listener, live relay, or live state.

Run:  python3 test_tv_e2e_synthetic.py
"""
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

RELAY_DIR = os.path.dirname(os.path.abspath(__file__))
TA_DIR = os.path.expanduser("~/workspace/trading-agent")

TV_SECRET = "e2e-tv-secret-abc123"
CONSUMER_SECRET = "e2e-consumer-secret-def456"
INGEST_TOKEN = "e2e-ingest-token-ghi789"
PORT = 18799

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS  " if cond else "FAIL  ") + name +
          ("" if cond else "  %r" % (detail,)))


def http_post(path, body, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    conn.request("POST", path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, json.loads(data.decode("utf-8"))


def http_get(path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, json.loads(data.decode("utf-8"))


def wait_for_port():
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def make_pine(event_id, event_type, **over):
    now_ms = int(time.time() * 1000)
    pine = {
        "schema_version": "astra-edge-event-v1.1",
        "strategy_id": "STRATEGY2_ASTRA_EDGE_V1",
        "strategy_version": "1.0.2",
        "event_id": event_id,
        "event_type": event_type,
        "symbol": "NQ",
        "contract": "NQ",
        "chart_timeframe": "1",
        "direction": "LONG",
        "market_ts": now_ms - 5000,
        "observed_at": now_ms - 1000,
        "source_bar_close": now_ms - 5000,
        "setup_id": "E2E-SETUP-1",
        "liquidity_type": "PDH",
        "liquidity_price": 25000.50,
        "sweep_confirmed": True,
        "absorption_state": "SELLERS ABSORBED",
        "flow_state": "NEUTRAL",
        "long_score": 80,
        "short_score": 60,
        "directional_gap": 20,
        "reclaim_state": "PENDING",
        "room_r": 2.5,
        "target_reference": "PDH",
        "armed": False,
        "release_state": "PENDING",
        "footprint_available": True,
        "freshness_bars": 2,
        "stacked_imbalance_rows": 2,
    }
    pine.update(over)
    return pine


def main():
    data_dir = tempfile.mkdtemp(prefix="astra-relay-e2e-")
    state_root = tempfile.mkdtemp(prefix="astra-listener-e2e-")
    env = dict(os.environ)
    env.update({
        "ASTRA_RELAY_PORT": str(PORT),
        "ASTRA_RELAY_DATA_DIR": data_dir,
        "ASTRA_TV_HMAC_SECRET": TV_SECRET,
        "ASTRA_RELAY_CONSUMER_SECRET": CONSUMER_SECRET,
        "ASTRA_TV_INGEST_TOKEN": INGEST_TOKEN,
        "ASTRA_TV_SYMBOLS": "NQ",
        "ASTRA_TV_TIMEFRAMES": "1",
    })
    proc = subprocess.Popen(
        [sys.executable, os.path.join(RELAY_DIR, "relay_astra.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        check("relay starts", wait_for_port())
        if not wait_for_port():
            return 1

        # 1. Pine-like JSON -> edge (with token).
        pine = make_pine("E2E-SWEEP-1", "SWEEP_DETECTED")
        body = json.dumps(pine).encode("utf-8")
        st, r = http_post("/ingest/tv?token=" + INGEST_TOKEN, body,
                          {"Content-Type": "application/json"})
        check("edge accepts valid Pine JSON", st == 200 and r.get("accepted"),
              (st, r))
        check("edge attests (not sender-proof)", r.get("accepted") is True)

        # 2. No token -> 401.
        st, r = http_post("/ingest/tv", body,
                          {"Content-Type": "application/json"})
        check("edge rejects missing token", st == 401, (st, r))

        # 3. Malformed -> 422, never queued.
        bad = make_pine("E2E-BAD-1", "SWEEP_DETECTED", freshness_bars=99)
        st, r = http_post("/ingest/tv?token=" + INGEST_TOKEN,
                          json.dumps(bad).encode("utf-8"),
                          {"Content-Type": "application/json"})
        check("edge refuses stale evidence", st == 422 and
              r.get("attested") is False, (st, r))

        # 4. Consumer fetches pending.
        hdrs = {"X-Relay-Auth": CONSUMER_SECRET}
        st, r = http_get("/webhook/astra/pending", hdrs)
        check("pending lists attested event", st == 200 and
              len(r.get("events", [])) == 1, (st, r))
        ev_body = r["events"][0]["body"].encode("utf-8")
        ev = json.loads(ev_body)
        check("queued event carries attestation hash",
              len(ev.get("payload_hash", "")) == 64)
        check("queued event run_id empty (local assigns)",
              ev.get("strategy_run_id") == "")

        # 5. Local listener ingests (fresh state root, new code).
        # Faithful consumer hop: re-sign the canonical body with the listener
        # secret (as the real consumer does), then call handle_webhook.
        LISTENER_SECRET = "e2e-listener-secret-jkl012"
        os.environ["ASTRA_EDGE_WEBHOOK_SECRET"] = LISTENER_SECRET
        sys.path.insert(0, TA_DIR)
        from strategy2_astra.service import handle_webhook
        from strategy2_astra.webhook_receiver import compute_payload_hmac
        ev_for_sign = json.loads(ev_body)
        listener_sig = compute_payload_hmac(ev_for_sign, LISTENER_SECRET)
        ev_for_sign["payload_hash"] = listener_sig
        listener_body = json.dumps(ev_for_sign).encode("utf-8")
        resp = handle_webhook(listener_body, listener_sig, root=state_root,
                              run_id="E2E-RUN-001")
        check("listener accepts attested event", resp.get("accepted") is True,
              resp)
        check("disposition=processed", resp.get("result") == "processed",
              resp)
        check("local run_id assigned",
              resp.get("assigned_strategy_run_id") == "E2E-RUN-001" and
              resp.get("run_id_source") == "LOCAL_CONFIG", resp)

        # 6. Replay the same event -> already_processed.
        resp2 = handle_webhook(listener_body, listener_sig, root=state_root,
                               run_id="E2E-RUN-001")
        check("replay -> already_processed",
              resp2.get("result") == "already_processed", resp2)

        # 7. ACK drains the queue.
        st, r = http_post("/webhook/astra/ack",
                          json.dumps({"event_ids": ["E2E-SWEEP-1"]}).encode(),
                          {"Content-Type": "application/json", **hdrs})
        check("ack accepted", st == 200 and r.get("ok") is True, (st, r))
        st, r = http_get("/webhook/astra/pending", hdrs)
        check("queue drained", st == 200 and r.get("events") == [], (st, r))

        print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
        if FAIL:
            print("FAILURES:", FAIL)
            return 1
        return 0
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        shutil.rmtree(data_dir, ignore_errors=True)
        shutil.rmtree(state_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
