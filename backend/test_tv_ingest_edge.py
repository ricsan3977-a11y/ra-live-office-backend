#!/usr/bin/env python3
"""Tests for the v1.1 contract and the TV ingest edge (BUILD APPROVED 2026-10-11).

Covers: schema v1.1 validation, malformed-payload refusals, edge
validate-before-sign rules, and signing/attestation vectors.

Run:  python3 test_tv_ingest_edge.py
"""
import copy
import hmac as hmac_lib
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Edge env must be set before import reads module-level config.
os.environ.setdefault("ASTRA_TV_SYMBOLS", "NQ")
os.environ.setdefault("ASTRA_TV_TIMEFRAMES", "1")

import relay_astra as relay

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS  " if cond else "FAIL  ") + name +
          ("" if cond else "  %r" % (detail,)))


def make_pine(**over):
    now_ms = int(time.time() * 1000)
    pine = {
        "schema_version": "astra-edge-event-v1.1",
        "strategy_id": "STRATEGY2_ASTRA_EDGE_V1",
        "strategy_version": "1.0.2",
        "event_id": "TV-TEST-001",
        "event_type": "SWEEP_DETECTED",
        "symbol": "NQ",
        "contract": "NQ",
        "chart_timeframe": "1",
        "direction": "LONG",
        "market_ts": now_ms - 5000,
        "observed_at": now_ms - 1000,
        "source_bar_close": now_ms - 5000,
        "setup_id": "SETUP-1",
        "liquidity_type": "PDH",
        "liquidity_price": 25000.50,
        "sweep_confirmed": True,
        "absorption_state": "NONE",
        "flow_state": "NEUTRAL",
        "long_score": 80,
        "short_score": 60,
        "directional_gap": 20,
        "reclaim_state": "NONE",
        "room_r": 2.5,
        "target_reference": "PDH",
        "armed": False,
        "release_state": "PENDING",
        "footprint_available": True,
        "freshness_bars": 3,
        "stacked_imbalance_rows": 2,
    }
    pine.update(over)
    return pine


def main():
    # ---- schema v1.1: canonical key count ----
    check("30 canonical keys", len(relay.CANONICAL_KEYS) == 30,
          len(relay.CANONICAL_KEYS))
    check("canonical sorted", list(relay.CANONICAL_KEYS) ==
          sorted(relay.CANONICAL_KEYS))
    check("v1.1 pinned", relay.PINNED_SCHEMA_VERSION ==
          "astra-edge-event-v1.1")

    # ---- edge validate: happy path ----
    check("valid Pine JSON accepted",
          relay._edge_validate(make_pine()) is None,
          relay._edge_validate(make_pine()))

    # ---- edge validate: strict allowlist ----
    bad = make_pine()
    bad["extra_field"] = 1
    check("unknown field refused",
          relay._edge_validate(bad) is not None and
          "unknown field" in relay._edge_validate(bad),
          relay._edge_validate(bad))

    # ---- edge validate: strategy_run_id ----
    bad = make_pine()
    bad["strategy_run_id"] = "CLEAN-RUN-123"
    check("non-null run_id refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    ok = make_pine()
    ok["strategy_run_id"] = None
    check("null run_id accepted",
          relay._edge_validate(ok) is None,
          relay._edge_validate(ok))
    ok2 = make_pine()  # strategy_run_id already omitted from base
    check("omitted run_id accepted",
          relay._edge_validate(ok2) is None,
          relay._edge_validate(ok2))

    # ---- edge validate: allowlists ----
    bad = make_pine(symbol="ES")
    check("non-allowlisted symbol refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    bad = make_pine(chart_timeframe="5")
    check("non-allowlisted timeframe refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))

    # ---- edge validate: frozen evidence values ----
    bad = make_pine(freshness_bars=9)
    check("freshness_bars=9 refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    check("freshness_bars=8 accepted",
          relay._edge_validate(make_pine(freshness_bars=8)) is None)
    bad = make_pine(stacked_imbalance_rows=-1)
    check("negative imbalance refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    # Sub-2-row values pass the edge (domain); the lifecycle evaluates the
    # 2-row gate at ARMED with an explicit disposition.
    check("imbalance_rows=0 passes edge (lifecycle gates it)",
          relay._edge_validate(make_pine(stacked_imbalance_rows=0)) is None,
          relay._edge_validate(make_pine(stacked_imbalance_rows=0)))

    # ---- edge validate: timestamps ----
    now_ms = int(time.time() * 1000)
    bad = make_pine(observed_at=now_ms - 120_000)
    check("stale observed_at refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    bad = make_pine(market_ts=now_ms + 120_000)
    check("future market_ts refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))

    # ---- edge validate: coherence ----
    bad = make_pine(directional_gap=99)
    check("incoherent gap refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    bad = make_pine(armed=True, event_type="SWEEP_DETECTED")
    check("armed with wrong type refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    bad = make_pine(footprint_available=False, armed=False,
                    absorption_state="NONE", long_score=0, short_score=0,
                    directional_gap=0, event_type="SWEEP_DETECTED")
    check("no-footprint non-DATA_UNAVAILABLE refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))

    # ---- edge: frozen gates on ARMED/RELEASE claims ----
    def make_armed(**over):
        base = dict(event_type="ARMED", armed=True, release_state="PENDING",
                    absorption_state="SELLERS ABSORBED",
                    reclaim_state="CONFIRMED", flow_state="BULLISH_SHIFT")
        base.update(over)
        return make_pine(**base)

    check("ARMED with all gates met accepted",
          relay._edge_validate(make_armed()) is None,
          relay._edge_validate(make_armed()))
    bad = make_armed(stacked_imbalance_rows=1)
    check("ARMED with 1 imbalance row refused",
          relay._edge_validate(bad) is not None and "imbalance" in
          relay._edge_validate(bad), relay._edge_validate(bad))
    bad = make_armed(long_score=70, short_score=50, directional_gap=20)
    check("ARMED with score<72 refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    bad = make_armed(long_score=80, short_score=70, directional_gap=10)
    check("ARMED with gap<15 refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    bad = make_armed(room_r=1.5)
    check("ARMED with room<1.8 refused",
          relay._edge_validate(bad) is not None,
          relay._edge_validate(bad))
    # Non-ARMED stages with sub-threshold values pass the edge (lifecycle
    # evaluates them with explicit dispositions).
    check("SWEEP with 0 rows passes edge",
          relay._edge_validate(make_pine(stacked_imbalance_rows=0)) is None)
    check("SWEEP with low score passes edge",
          relay._edge_validate(make_pine(long_score=60, short_score=50,
                                         directional_gap=10)) is None)

    # ---- attestation vectors ----
    secret = "test-edge-secret"
    pine = make_pine()
    pine["payload_hash"] = "forged-client-hash"
    signed = relay._edge_canonicalize(pine, secret)
    out = json.loads(signed.decode("utf-8"))
    check("client payload_hash dropped, edge-computed",
          out["payload_hash"] != "forged-client-hash" and
          len(out["payload_hash"]) == 64, out["payload_hash"])
    check("run_id canonicalized to empty",
          out["strategy_run_id"] == "", out.get("strategy_run_id"))
    # The attested output verifies under the relay's own HMAC check.
    check("attested output passes verify_payload",
          relay.verify_payload(signed, "", secret))
    # ...and passes the relay's strict schema validation.
    check("attested output passes relay schema",
          relay._validate_schema(out) is None,
          relay._validate_schema(out))
    # Tampering after attestation breaks verification.
    tampered = json.loads(signed.decode("utf-8"))
    tampered["long_score"] = 99
    tampered_raw = json.dumps(tampered).encode("utf-8")
    check("tampered attested event fails HMAC",
          not relay.verify_payload(tampered_raw, "", secret))

    # ---- relay schema strictness ----
    bad_schema = json.loads(signed.decode("utf-8"))
    bad_schema["mystery"] = 1
    check("relay rejects unknown field",
          relay._validate_schema(bad_schema) is not None)
    bad_schema2 = json.loads(signed.decode("utf-8"))
    bad_schema2["strategy_run_id"] = "SMUGGLED"
    check("relay rejects non-empty run_id",
          relay._validate_schema(bad_schema2) is not None and
          "strategy_run_id" in relay._validate_schema(bad_schema2))
    bad_schema3 = json.loads(signed.decode("utf-8"))
    bad_schema3["schema_version"] = "astra-edge-event-v1"
    check("relay rejects v1.0 schema",
          relay._validate_schema(bad_schema3) is not None)

    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:", FAIL)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
