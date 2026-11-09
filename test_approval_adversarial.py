"""Adversarial approval integrity tests for Project LEO.

Tests every attack vector against ApprovalManager.authorize_once()
using isolated temporary databases. The live leo_memory.db is NEVER touched.

Adversarial cases (34 total assertions):

  Section 1 — Status attacks
    A1 : Use a PENDING ticket directly        -> blocked
    A2 : Use a REJECTED ticket               -> blocked
    A3 : Consume a ticket twice (replay)     -> second use blocked
    A4 : Use a REVOKED ticket                -> blocked

  Section 2 — Payload / action mismatch attacks
    A5 : Wrong action_type                   -> blocked
    A6 : Payload task_id differs             -> blocked
    A7 : Extra key injected into payload     -> blocked
    A8 : Stripped key from payload           -> blocked
    A9 : approve then authorize with empty payload -> blocked

  Section 3 — Expiry attack
    A10: Expired ticket (_expires_at in past) -> blocked

  Section 4 — Non-existent ticket
    A11: Random approval_id                  -> blocked

  Section 5 — Happy path control
    A12: Valid approval consumed exactly once -> succeeds; second call blocked

Run: python test_approval_adversarial.py
"""

import json
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from memory_store import MemoryStore
from approval_manager import ApprovalManager, ApprovalError

SEP = "=" * 58
FAIL_SEP = "!" * 58

_passed: list = []
_failed: list = []

ACTION = "execute_task_release_manager"
TASK_ID = "task-rel-001"
PAYLOAD = {"task_id": TASK_ID}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stack() -> tuple[MemoryStore, ApprovalManager]:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = MemoryStore(db_path=Path(tmp.name))
    mgr = ApprovalManager(store=store)
    return store, mgr


def _request(mgr: ApprovalManager, ttl: int = 3600) -> str:
    """Create a standard pending approval request and return its id."""
    a = mgr.request_approval(
        action_type=ACTION,
        description="Release gate test",
        requested_by="release_manager",
        task_id=TASK_ID,
        payload=PAYLOAD,
        ttl_seconds=ttl,
    )
    return a["id"]


def _assert(condition: bool, label: str, detail: str = ""):
    if condition:
        _passed.append(label)
        print(f"  [PASS] {label}")
    else:
        _failed.append(label)
        print(f"  [FAIL] {label}" + (f"\n         {detail}" if detail else ""))


def _must_raise(fn, label: str, keyword: str = "blocked"):
    """Assert that fn() raises ApprovalError containing keyword."""
    try:
        fn()
        _assert(False, label, "Expected ApprovalError but none was raised")
    except ApprovalError as exc:
        matched = keyword.lower() in str(exc).lower()
        _assert(matched, label, f"Got ApprovalError but message missing '{keyword}': {exc}")
    except Exception as exc:
        _assert(False, label, f"Wrong exception type {type(exc).__name__}: {exc}")


# ===========================================================================
# Section 1 — Status attacks
# ===========================================================================
print(SEP)
print("Section 1 — Status attacks")
print(SEP)

# A1: pending ticket cannot authorize
_, mgr1 = _stack()
aid1 = _request(mgr1)
_must_raise(
    lambda: mgr1.authorize_once(aid1, ACTION, PAYLOAD),
    "A1: Pending ticket rejected by authorize_once",
    "pending",
)

# A2: rejected ticket cannot authorize
_, mgr2 = _stack()
aid2 = _request(mgr2)
mgr2.decide(aid2, approved=False)
_must_raise(
    lambda: mgr2.authorize_once(aid2, ACTION, PAYLOAD),
    "A2: Rejected ticket blocked",
    "rejected",
)

# A3: replay attack — approve once, authorize once, then try again
_, mgr3 = _stack()
aid3 = _request(mgr3)
mgr3.decide(aid3, approved=True)
first_ok = mgr3.authorize_once(aid3, ACTION, PAYLOAD)
_assert(first_ok is True, "A3a: First authorization succeeds")
_must_raise(
    lambda: mgr3.authorize_once(aid3, ACTION, PAYLOAD),
    "A3b: Replay (second consume) blocked",
    "consumed",
)

# A4: revoked ticket cannot authorize
_, mgr4 = _stack()
aid4 = _request(mgr4)
mgr4.revoke(aid4)
_must_raise(
    lambda: mgr4.authorize_once(aid4, ACTION, PAYLOAD),
    "A4: Revoked ticket blocked",
    "blocked",
)

print()

# ===========================================================================
# Section 2 — Payload / action mismatch attacks
# ===========================================================================
print(SEP)
print("Section 2 — Payload and action mismatch attacks")
print(SEP)

# A5: wrong action_type
_, mgr5 = _stack()
aid5 = _request(mgr5)
mgr5.decide(aid5, approved=True)
_must_raise(
    lambda: mgr5.authorize_once(aid5, "execute_task_DIFFERENT", PAYLOAD),
    "A5: Wrong action_type blocked",
    "blocked",
)

# A6: payload task_id changed (pivot to a different task)
_, mgr6 = _stack()
aid6 = _request(mgr6)
mgr6.decide(aid6, approved=True)
_must_raise(
    lambda: mgr6.authorize_once(aid6, ACTION, {"task_id": "task-DIFFERENT-999"}),
    "A6: Payload task_id pivot blocked",
    "blocked",
)

# A7: extra key injected into the presented payload
_, mgr7 = _stack()
aid7 = _request(mgr7)
mgr7.decide(aid7, approved=True)
injected = {**PAYLOAD, "extra_key": "injected_value"}
_must_raise(
    lambda: mgr7.authorize_once(aid7, ACTION, injected),
    "A7: Extra key injection blocked",
    "blocked",
)

# A8: key stripped from the presented payload (subset of approved payload)
_, mgr8 = _stack()
# Request with a richer payload
rich_payload = {"task_id": TASK_ID, "environment": "production"}
a8 = mgr8.request_approval(
    action_type=ACTION, description="Rich payload test",
    requested_by="release_manager", task_id=TASK_ID,
    payload=rich_payload, ttl_seconds=3600,
)
mgr8.decide(a8["id"], approved=True)
_must_raise(
    lambda: mgr8.authorize_once(a8["id"], ACTION, {"task_id": TASK_ID}),   # stripped
    "A8: Stripped payload (subset) blocked",
    "blocked",
)

# A9: approve ticket, then authorize with completely empty payload
_, mgr9 = _stack()
aid9 = _request(mgr9)   # payload = {"task_id": TASK_ID}
mgr9.decide(aid9, approved=True)
_must_raise(
    lambda: mgr9.authorize_once(aid9, ACTION, {}),
    "A9: Empty payload vs non-empty stored payload blocked",
    "blocked",
)

print()

# ===========================================================================
# Section 3 — Expiry attack
# ===========================================================================
print(SEP)
print("Section 3 — Expired ticket attack")
print(SEP)

# A10: inject an already-expired _expires_at into the payload
store10, mgr10 = _stack()

# Request with a 1-second TTL so we can expire it reliably in the payload
past_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()

# Directly create a ticket whose payload has a past expiry
approval10 = store10.create_approval(
    action_type=ACTION,
    description="Expired ticket test",
    requested_by="release_manager",
    task_id=TASK_ID,
    payload={**PAYLOAD, "_expires_at": past_time},
)
# Mark it approved so we get past the status checks
store10.resolve_approval(approval10["id"], approved=True, approved_by="user")

_must_raise(
    lambda: mgr10.authorize_once(approval10["id"], ACTION, PAYLOAD),
    "A10: Expired ticket blocked",
    "expired",
)

print()

# ===========================================================================
# Section 4 — Non-existent ticket
# ===========================================================================
print(SEP)
print("Section 4 — Non-existent approval ID")
print(SEP)

_, mgr11 = _stack()
_must_raise(
    lambda: mgr11.authorize_once("appr-does-not-exist-000", ACTION, PAYLOAD),
    "A11: Fabricated approval ID blocked",
    "blocked",
)

print()

# ===========================================================================
# Section 5 — Happy path control (proves the gate is not permanently sealed)
# ===========================================================================
print(SEP)
print("Section 5 — Happy path: valid approval consumed exactly once")
print(SEP)

_, mgr12 = _stack()
aid12 = _request(mgr12)

# Confirm it starts pending
appr_before = mgr12.get_approval(aid12)
_assert(appr_before["status"] == "pending",  "A12a: Ticket starts as pending")

# Approve it
mgr12.decide(aid12, approved=True)
appr_approved = mgr12.get_approval(aid12)
_assert(appr_approved["status"] == "approved", "A12b: Status transitions to approved after decide()")

# Authorize once — must succeed
result12 = mgr12.authorize_once(aid12, ACTION, PAYLOAD)
_assert(result12 is True, "A12c: authorize_once returns True for valid approved ticket")

# Ticket must now be consumed, not pending or approved
appr_after = mgr12.get_approval(aid12)
_assert(appr_after["status"] == "consumed", "A12d: Ticket status = consumed after use")

# It must no longer appear in pending list
pending_after = mgr12.list_pending()
ids_pending = [a["id"] for a in pending_after]
_assert(aid12 not in ids_pending, "A12e: Consumed ticket absent from pending list")

# Replay must still be blocked even after the happy path
_must_raise(
    lambda: mgr12.authorize_once(aid12, ACTION, PAYLOAD),
    "A12f: Replay after successful consume blocked",
    "consumed",
)

print()

# ===========================================================================
# Bonus: decide() idempotency — cannot re-decide an already-decided ticket
# ===========================================================================
print(SEP)
print("Bonus — decide() idempotency")
print(SEP)

_, mgrB = _stack()
aidB = _request(mgrB)
mgrB.decide(aidB, approved=True)

_must_raise(
    lambda: mgrB.decide(aidB, approved=True),
    "B1: Re-approving already-approved ticket blocked",
    "already",
)

_, mgrB2 = _stack()
aidB2 = _request(mgrB2)
mgrB2.decide(aidB2, approved=False)

_must_raise(
    lambda: mgrB2.decide(aidB2, approved=True),
    "B2: Approving already-rejected ticket blocked",
    "already",
)

print()

# ===========================================================================
# Final summary
# ===========================================================================
total = len(_passed) + len(_failed)
print(SEP)
print(f"Results: {len(_passed)}/{total} assertions passed")
if _failed:
    print("\nFailed assertions:")
    for f in _failed:
        print(f"  - {f}")
    raise SystemExit(1)
else:
    print("All adversarial approval integrity assertions passed.")
print(SEP)
