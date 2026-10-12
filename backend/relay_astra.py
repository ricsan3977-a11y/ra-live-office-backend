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

HMAC scheme: inherited canonicalization from strategy2_astra/webhook_receiver.py —
HMAC-SHA256 hex over the canonical JSON (28 ASCII-sorted contract fields,
Pine-compatible 2dp formatting), carried in the payload_hash field. The
X-Astra-Signature header is optional; if present it must match too.

Every rejected webhook returns a non-2xx HTTP status AND accepted=false.
Clients still MUST require an explicit JSON accepted=true before success.
An HTTP 200 alone is never an application-level acceptance receipt.
This module does not turn unsigned TradingView payloads into trusted events.
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
# Shared transport bound with the candidate consumer; larger pending sets are
# delivered in successive ordered batches. One accepted MAX_BODY event fits.
MAX_PENDING_RESPONSE_BYTES = 16 * 1024 * 1024
# Coarse wall-clock staleness backstop (local side enforces the real 8-bar rule).
STALE_AFTER_SEC = 1800
FUTURE_SKEW_SEC = 300
PINNED_STRATEGY_VERSION = "1.0.2"
PINNED_STRATEGY_ID = "STRATEGY2_ASTRA_EDGE_V1"
PINNED_SCHEMA_VERSION = "astra-edge-event-v1.1"

EVENTS_LOG = os.path.join(DATA_DIR, "events.jsonl")
DELIVERED_LOG = os.path.join(DATA_DIR, "delivered.jsonl")

# --------------------------------- canonical HMAC (ported verbatim logic)
CANONICAL_KEYS = (
    "absorption_state", "armed", "chart_timeframe", "contract", "direction",
    "directional_gap", "event_id", "event_type", "flow_state",
    "footprint_available", "freshness_bars", "liquidity_price",
    "liquidity_type", "long_score",
    "market_ts", "observed_at", "reclaim_state", "release_state", "room_r",
    "schema_version", "setup_id", "short_score", "source_bar_close",
    "stacked_imbalance_rows",
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
    "freshness_bars", "stacked_imbalance_rows",
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
    # Confirm durability before a success receipt or in-memory ACK/dedup update.
    # This assumes one relay process owns this store, as launcher.py specifies.
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _pending_events():
    with _lock:
        # Preserve durable arrival order. A set iteration can reorder lifecycle
        # events and let a later stage overtake its prerequisite.
        pending_ids = _seen_ids - _delivered_ids
        result, emitted = [], set()
        for rec in _read_jsonl(EVENTS_LOG):
            eid = rec.get("event_id")
            if eid in pending_ids and eid not in emitted:
                result.append(rec)
                emitted.add(eid)
                if len(result) >= PENDING_CAP:
                    break
        return result


# ------------------------------------------------------------ validation
def _validate_schema(payload: dict):
    """Return None if valid, else a reason string. Structural only.

    v1.1: strict — unknown fields are rejected (never silently stripped);
    strategy_run_id must be "" (the edge canonicalizes null/omitted to ""
    and rejects any externally supplied value; the local trusted service
    assigns the clean run id after durable ingestion).
    """
    if not isinstance(payload, dict):
        return "SCHEMA_INVALID: not an object"
    for f in REQUIRED_FIELDS:
        if f not in payload:
            return "SCHEMA_INVALID: missing %s" % f
    for f in payload:
        if f not in REQUIRED_FIELDS:
            return "SCHEMA_INVALID: unknown field %s" % f
    if payload.get("schema_version") != PINNED_SCHEMA_VERSION:
        return "SCHEMA_INVALID: schema_version want %s" % PINNED_SCHEMA_VERSION
    if payload.get("strategy_version") != PINNED_STRATEGY_VERSION:
        return "VERSION_MISMATCH: want %s" % PINNED_STRATEGY_VERSION
    if payload.get("strategy_id") != PINNED_STRATEGY_ID:
        return "STRATEGY_MISMATCH: want %s" % PINNED_STRATEGY_ID
    if payload.get("strategy_run_id") != "":
        return "SCHEMA_INVALID: strategy_run_id must be empty (local assignment only)"
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


# ------------------------------------------------------------ TV ingest edge
# Off-chart validation + attestation layer for TradingView Pine JSON.
#
# Pine Script has no cryptographic functions, so Pine cannot sign. This module
# validates Pine-emitted evidence JSON against the frozen v1.1 contract,
# constructs a FRESH canonical event from the validated input, HMAC-signs it
# with ASTRA_TV_HMAC_SECRET, and feeds it into the relay's standard intake
# (which re-verifies the HMAC itself).
#
# The resulting signature is RELAY VALIDATION ATTESTATION: it proves the event
# passed this module's strict validation. It is NOT proof that TradingView
# was the sender — TradingView webhooks are unauthenticated HTTPS POSTs and
# offer no cryptographic sender proof. Never describe an attested event as
# "TradingView-authenticated." Sender-side mitigation is layered (see design
# doc): unguessable endpoint token, exact schema/template, symbol/timeframe
# allowlist, freshness bound, dedup, rate limiting, shadow-only blast radius.
#
# Anti-oracle rules: this module NEVER signs input it did not fully validate,
# never forwards unsigned bodies, never invents field values, and never
# bypasses a relay check. Refusals are logged structurally (reason + event_id
# when present); no secrets and no payload contents in logs.

TV_INGEST_PATH = os.environ.get("ASTRA_TV_INGEST_PATH", "/ingest/tv")
TV_INGEST_TOKEN_VAR = "ASTRA_TV_INGEST_TOKEN"
TV_SYMBOLS = frozenset(
    s.strip() for s in os.environ.get("ASTRA_TV_SYMBOLS", "NQ").split(",")
    if s.strip())
TV_TIMEFRAMES = frozenset(
    s.strip() for s in os.environ.get("ASTRA_TV_TIMEFRAMES", "1").split(",")
    if s.strip())
# Ingest skew bound mirrors the local service (fail fast on stale evidence).
TV_INGEST_SKEW_MS = 60_000
# Frozen contract bounds enforced pre-sign (edge refuses beyond these).
TV_MAX_FRESHNESS_BARS = 8
# Frozen readiness gates (must match strategy2_astra/lifecycle.py; the relay
# cannot import it, so they are duplicated here and frozen by design review).
# Enforced on ARMED/RELEASE claims only (ruling 2026-10-11): a readiness claim
# must satisfy the frozen thresholds or fail closed. Earlier lifecycle stages
# carry evidence values without claiming readiness and are domain-checked.
TV_GATE_SCORE_MIN = 72
TV_GATE_GAP_MIN = 15
TV_GATE_ROOM_R_MIN = 1.8
TV_GATE_IMBALANCE_ROWS_MIN = 2
# Imbalance rows: domain-checked here (>= 0); the frozen 2-row gate is
# evaluated by the lifecycle at ARMED from the wire value (verified, not
# attested). Refusing sub-2-row values here would break non-ARMED stages
# (a fresh sweep legitimately carries 0 rows); the gate verdict belongs in
# the lifecycle funnel with an explicit disposition.
TV_INGEST_RATE_PER_MIN = 60

# Pine never sends payload_hash (it cannot compute it). strategy_run_id is
# nullable per ruling 5 (null or omitted only; any supplied value refused).
_EDGE_ENUMS = {
    "event_type": EVENT_TYPES,
    "direction": DIRECTIONS,
    "absorption_state": frozenset({
        "SELLERS ABSORBED", "BUYERS ABSORBED", "NONE", "DATA_UNAVAILABLE"}),
    "flow_state": frozenset({
        "BULLISH_SHIFT", "BEARISH_SHIFT", "NEUTRAL", "DATA_UNAVAILABLE"}),
    "reclaim_state": frozenset({
        "NONE", "PENDING", "CONFIRMED", "FAILED", "DATA_UNAVAILABLE"}),
    "release_state": frozenset({
        "PENDING", "RELEASED", "WITHHELD_NO_FOOTPRINT", "WITHHELD_GATE_FAIL"}),
    "liquidity_type": frozenset({
        "PDH", "PDL", "SESSION_HIGH", "SESSION_LOW", "NONE"}),
    "target_reference": frozenset({
        "PDH", "PDL", "SESSION_HIGH", "SESSION_LOW", "NONE"}),
}

_tv_ingest_hits = []


def _tv_ingest_rate_ok():
    now = time.time()
    with _lock:
        while _tv_ingest_hits and _tv_ingest_hits[0] < now - 60:
            _tv_ingest_hits.pop(0)
        if len(_tv_ingest_hits) >= TV_INGEST_RATE_PER_MIN:
            return False
        _tv_ingest_hits.append(now)
        return True


def _tv_ingest_log_refusal(reason, pine):
    """Structured refusal log: reason + event_id when present. No secrets,
    no payload contents."""
    eid = None
    if isinstance(pine, dict):
        v = pine.get("event_id")
        eid = v if isinstance(v, str) and v else None
    print("tv-ingest REFUSE reason=%s event_id=%s" % (reason, eid),
          flush=True)


def _edge_validate(pine: dict):
    """Validate Pine-emitted evidence JSON. Return None if valid, else reason.

    Strict allowlist: unknown fields refuse. Never mutates input. All refusals
    are fail-closed; nothing is signed on any failure.
    """
    if not isinstance(pine, dict):
        return "TV_INGEST_INVALID: not an object"
    for f in pine:
        if f not in CANONICAL_KEYS:
            return "TV_INGEST_INVALID: unknown field %s" % f
    for k in CANONICAL_KEYS:
        if k == "strategy_run_id":
            continue
        if k not in pine:
            return "TV_INGEST_INVALID: missing %s" % k
    # Ruling 5: run ID is locally assigned; Pine sends null or omits it.
    if "strategy_run_id" in pine and pine["strategy_run_id"] is not None:
        return "TV_INGEST_INVALID: strategy_run_id externally unassignable"
    # Pinned literals.
    if pine.get("schema_version") != PINNED_SCHEMA_VERSION:
        return "TV_INGEST_INVALID: schema_version"
    if pine.get("strategy_id") != PINNED_STRATEGY_ID:
        return "TV_INGEST_INVALID: strategy_id"
    if pine.get("strategy_version") != PINNED_STRATEGY_VERSION:
        return "TV_INGEST_INVALID: strategy_version"
    # Symbol / timeframe allowlist.
    if pine.get("symbol") not in TV_SYMBOLS:
        return "TV_INGEST_INVALID: symbol not allowlisted"
    if pine.get("chart_timeframe") not in TV_TIMEFRAMES:
        return "TV_INGEST_INVALID: timeframe not allowlisted"
    # Types.
    for f in _BOOL_FIELDS:
        if type(pine.get(f)) is not bool:
            return "TV_INGEST_INVALID: %s not bool" % f
    for f in _INT_FIELDS:
        if type(pine.get(f)) is not int or isinstance(pine.get(f), bool):
            return "TV_INGEST_INVALID: %s not int" % f
    for f in _STR_FIELDS:
        if f == "strategy_run_id":
            continue
        if not isinstance(pine.get(f), str) or not pine[f]:
            return "TV_INGEST_INVALID: %s not non-empty str" % f
    # Enums.
    for f, allowed in _EDGE_ENUMS.items():
        if pine.get(f) not in allowed:
            return "TV_INGEST_INVALID: %s not in enum" % f
    # Scores and gap coherence.
    for f in ("long_score", "short_score"):
        if not (0 <= pine[f] <= 100):
            return "TV_INGEST_INVALID: %s out of range" % f
    if pine["directional_gap"] != abs(pine["long_score"] - pine["short_score"]):
        return "TV_INGEST_INVALID: directional_gap incoherent"
    # Direction / event coherence.
    et, direction = pine["event_type"], pine["direction"]
    if et in ("DATA_UNAVAILABLE", "TEST_PING"):
        if direction != "NONE":
            return "TV_INGEST_INVALID: direction must be NONE for %s" % et
    elif direction not in ("LONG", "SHORT"):
        return "TV_INGEST_INVALID: direction must be LONG/SHORT for %s" % et
    # Armed / release coherence.
    if pine["armed"] and et not in ("ARMED", "RELEASE"):
        return "TV_INGEST_INVALID: armed=true requires ARMED/RELEASE"
    if et == "RELEASE" and not (pine["armed"]
                                and pine["release_state"] == "RELEASED"):
        return "TV_INGEST_INVALID: RELEASE requires armed+RELEASED"
    if et == "ARMED" and not (pine["armed"]
                              and pine["release_state"] == "PENDING"):
        return "TV_INGEST_INVALID: ARMED requires armed+PENDING"
    # Footprint integrity: missing footprint is DATA_UNAVAILABLE, never zeroed.
    if not pine["footprint_available"] and et != "TEST_PING":
        if pine["armed"]:
            return "TV_INGEST_INVALID: no footprint with armed=true"
        if pine["absorption_state"] != "DATA_UNAVAILABLE":
            return "TV_INGEST_INVALID: no footprint needs DATA_UNAVAILABLE absorption"
        if pine["long_score"] != 0 or pine["short_score"] != 0:
            return "TV_INGEST_INVALID: no footprint needs zero scores"
        if et != "DATA_UNAVAILABLE":
            return "TV_INGEST_INVALID: no footprint needs DATA_UNAVAILABLE type"
    # Timestamps: fail fast on stale/future evidence.
    now_ms = int(time.time() * 1000)
    obs, mts = pine["observed_at"], pine["market_ts"]
    if abs(now_ms - obs) > TV_INGEST_SKEW_MS:
        return "TV_INGEST_INVALID: observed_at outside 60s skew"
    if mts > now_ms + TV_INGEST_SKEW_MS or mts <= 0:
        return "TV_INGEST_INVALID: market_ts invalid"
    # Frozen evidence values (ruling 1): verified pre-sign, not merely accepted.
    fb = pine["freshness_bars"]
    if not (0 <= fb <= TV_MAX_FRESHNESS_BARS):
        return "TV_INGEST_INVALID: freshness_bars=%s exceeds 8-bar contract" % fb
    if pine["stacked_imbalance_rows"] < 0:
        return "TV_INGEST_INVALID: stacked_imbalance_rows negative"
    # Frozen readiness gates on readiness claims (ruling 2026-10-11): an event
    # claiming ARMED or RELEASE must satisfy the frozen thresholds or fail
    # closed. Earlier stages (0/1 imbalance rows etc.) are legitimate evidence
    # and are evaluated by the lifecycle, not refused here.
    if et in ("ARMED", "RELEASE"):
        if pine["stacked_imbalance_rows"] < TV_GATE_IMBALANCE_ROWS_MIN:
            return ("TV_INGEST_INVALID: ARMED/RELEASE requires >=%d "
                    "imbalance rows" % TV_GATE_IMBALANCE_ROWS_MIN)
        claim_score = (pine["long_score"] if direction == "LONG"
                       else pine["short_score"])
        if claim_score < TV_GATE_SCORE_MIN:
            return ("TV_INGEST_INVALID: ARMED/RELEASE requires score>=%d" %
                    TV_GATE_SCORE_MIN)
        if pine["directional_gap"] < TV_GATE_GAP_MIN:
            return ("TV_INGEST_INVALID: ARMED/RELEASE requires gap>=%d" %
                    TV_GATE_GAP_MIN)
        room = pine["room_r"]
        if not isinstance(room, (int, float)) or isinstance(room, bool) \
                or room < TV_GATE_ROOM_R_MIN:
            return ("TV_INGEST_INVALID: ARMED/RELEASE requires room>=%.1fR" %
                    TV_GATE_ROOM_R_MIN)
    return None


def _edge_canonicalize(pine: dict, tv_secret: str):
    """Build a FRESH canonical event from validated Pine input and sign it.

    Caller must have run _edge_validate first (returns None). Constructs a new
    dict with exactly the canonical keys (strategy_run_id="" per ruling 5),
    computes the HMAC, and returns the signed body bytes. Never reuses input
    object identity; any client-supplied payload_hash is dropped.
    """
    event = {}
    for k in CANONICAL_KEYS:
        if k == "strategy_run_id":
            event[k] = ""
        elif k == "payload_hash":
            continue  # not in CANONICAL_KEYS; set after signing
        else:
            event[k] = pine[k]
    # Numbers: enforce canonical 2dp form via the shared canonicalizer path.
    # (canonical_event_json handles formatting; we just ensure float type.)
    for k in ("liquidity_price", "room_r"):
        v = event.get(k)
        if v is not None:
            event[k] = float(v)
    event["payload_hash"] = compute_payload_hmac(event, tv_secret)
    return json.dumps(event, separators=(",", ":")).encode("utf-8")


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
        elif path == TV_INGEST_PATH:
            self._handle_tv_ingest()
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
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            self._send(400, {"accepted": False, "reason": "BAD_LENGTH"})
            return
        if length <= 0 or length > MAX_BODY:
            self._send(400, {"accepted": False, "reason": "BAD_LENGTH"})
            return
        raw = self.rfile.read(length)
        sig = self.headers.get("X-Astra-Signature", "")
        self._ingest_signed_body(raw, sig)

    def _ingest_signed_body(self, raw: bytes, sig: str):
        """Standard intake for HMAC-signed bodies.

        Shared by /webhook/astra and the TV edge. The edge signs its validated
        output with the same TV secret and feeds it here; this method verifies
        that signature itself — the edge is never trusted blindly.
        """
        tv_secret = os.environ.get(TV_SECRET_VAR, "")
        if not tv_secret:
            self._send(503, {"accepted": False,
                             "reason": "RELAY_NOT_CONFIGURED"})
            return
        if not verify_payload(raw, sig, tv_secret):
            self._send(401, {"accepted": False, "reason": "HMAC_FAIL"})
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send(400, {"accepted": False, "reason": "BAD_JSON"})
            return
        reason = _validate_schema(payload)
        if reason:
            self._send(422, {"accepted": False, "reason": reason})
            return
        reason = _check_stale(payload)
        if reason:
            self._send(422, {"accepted": False, "reason": reason})
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
            try:
                _append_jsonl(EVENTS_LOG, rec)
            except OSError:
                self._send(503, {"accepted": False, "reason": "STORE_UNAVAILABLE"})
                return
            _seen_ids.add(event_id)
        self._send(200, {"accepted": True, "event_id": event_id,
                         "duplicate": False, "stored": True})

    def _handle_tv_ingest(self):
        """TradingView Pine JSON ingress: validate strictly, attest by signing,
        feed the standard intake.

        The resulting signature is RELAY VALIDATION ATTESTATION — proof the
        event passed this module's validation. It is NOT proof TradingView was
        the sender (TradingView webhooks are unauthenticated). Never describe
        an attested event as "TradingView-authenticated."
        """
        tv_secret = os.environ.get(TV_SECRET_VAR, "")
        if not tv_secret:
            self._send(503, {"accepted": False,
                             "reason": "RELAY_NOT_CONFIGURED"})
            return
        token = os.environ.get(TV_INGEST_TOKEN_VAR, "")
        if not token:
            self._send(503, {"accepted": False,
                             "reason": "TV_INGEST_NOT_CONFIGURED"})
            return
        presented = ""
        for part in urlparse(self.path).query.split("&"):
            if part.startswith("token="):
                presented = part[len("token="):]
                break
        if not presented or not hmac.compare_digest(presented, token):
            self._send(401, {"accepted": False,
                             "reason": "TV_INGEST_UNAUTHORIZED"})
            return
        if not _tv_ingest_rate_ok():
            self._send(429, {"accepted": False,
                             "reason": "TV_INGEST_RATE_LIMITED"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            self._send(400, {"accepted": False, "reason": "BAD_LENGTH"})
            return
        if length <= 0 or length > MAX_BODY:
            self._send(400, {"accepted": False, "reason": "BAD_LENGTH"})
            return
        raw = self.rfile.read(length)
        try:
            pine = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send(400, {"accepted": False,
                             "reason": "TV_INGEST_BAD_JSON"})
            return
        reason = _edge_validate(pine)
        if reason:
            _tv_ingest_log_refusal(
                reason, pine if isinstance(pine, dict) else None)
            self._send(422, {"accepted": False, "reason": reason,
                             "attested": False})
            return
        signed = _edge_canonicalize(pine, tv_secret)
        # Standard intake verifies this signature itself.
        self._ingest_signed_body(signed, "")

    def _handle_pending(self):
        if not self._consumer_authed():
            self._send(401, {"ok": False, "reason": "UNAUTHORIZED"})
            return
        selected = []
        for event in _pending_events():
            item = {"event_id": event["event_id"],
                    "received_at": event["received_at"], "body": event["body"]}
            batch = selected + [item]
            reply = {"ok": True, "count": len(batch), "events": batch}
            if len(json.dumps(reply).encode("utf-8")) > MAX_PENDING_RESPONSE_BYTES:
                if not selected:
                    self._send(503, {"ok": False, "reason": "EVENT_EXCEEDS_RESPONSE_LIMIT"})
                    return
                break
            selected = batch
        self._send(200, {"ok": True, "count": len(selected), "events": selected})

    def _handle_ack(self):
        if not self._consumer_authed():
            self._send(401, {"ok": False, "reason": "UNAUTHORIZED"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            self._send(400, {"ok": False, "reason": "BAD_LENGTH"})
            return
        # Every returned pending event_id must be ACK-able, including long IDs.
        # An ACK ID list is smaller than its bounded pending response envelope.
        if length <= 0 or length > MAX_PENDING_RESPONSE_BYTES:
            self._send(400, {"ok": False, "reason": "BAD_LENGTH"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            ids = payload.get("event_ids", [])
        except Exception:
            self._send(400, {"ok": False, "reason": "BAD_JSON"})
            return
        if (not isinstance(ids, list)
                or any(not isinstance(eid, str) or not eid for eid in ids)):
            self._send(400, {"ok": False, "reason": "BAD_JSON"})
            return
        acked = 0
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with _lock:
            # Reject the whole batch before mutation. An ACK for an unknown ID
            # otherwise hides a future event with that ID before delivery.
            if any(eid not in _seen_ids for eid in ids):
                self._send(409, {"ok": False, "reason": "UNKNOWN_EVENT_ID"})
                return
            for eid in ids:
                if eid not in _delivered_ids:
                    try:
                        _append_jsonl(DELIVERED_LOG,
                                      {"event_id": eid, "acked_at": now})
                    except OSError:
                        self._send(503, {"ok": False, "reason": "STORE_UNAVAILABLE"})
                        return
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
