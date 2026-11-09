"""End-to-end release gate verification for Project LEO.

Tests the ACTUAL orchestrator.py + quality_gate.py + approval_manager.py
pipeline using a fresh temporary SQLite database so the live leo_memory.db
is NEVER touched.

Four cases verified (15 total assertions):
  Case 1 : Reviewer rejects       -> gate blocks, no approval ticket.
  Case 2 : QA execution fails     -> gate blocks, no approval ticket.
  Case 2b: QA result is text-only -> gate blocks (no evidence), no ticket.
  Case 3 : Missing Reviewer + QA  -> gate blocks both, no approval ticket.
  Case 4 : All evidence passes    -> pipeline reaches human approval stage;
                                     approval ticket created, release NOT run.

Run: python test_release_gate_e2e.py
"""

import json
import tempfile
from pathlib import Path

from quality_gate import QualityGate, EXECUTION_VERIFIED_KEY
from memory_store import MemoryStore
from approval_manager import ApprovalManager
from orchestrator import Orchestrator, OrchestratorError


# ---------------------------------------------------------------------------
# Shared test payloads
# ---------------------------------------------------------------------------

REVIEWER_APPROVE = "**Verdict:** Approve\nCode quality is acceptable."
REVIEWER_REJECT  = "**Verdict:** Reject\nCritical security flaw detected."

VERIFIED_QA_PASS = json.dumps({
    EXECUTION_VERIFIED_KEY: True,
    "executed": True, "passed": True, "returncode": 0,
    "stdout": "", "stderr": "",
    "summary": "Sandboxed unit tests passed",
})

VERIFIED_QA_FAIL = json.dumps({
    EXECUTION_VERIFIED_KEY: True,
    "executed": True, "passed": False, "returncode": 1,
    "stdout": "", "stderr": "FAIL: test_add_wrong\nAssertionError: 5 != 999",
    "summary": "Sandboxed unit tests FAILED",
})

TEXT_ONLY_QA = "All tests passed. 10/10 cases OK."   # no execution evidence

SEP = "=" * 56

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_stack() -> tuple:
    """Return a fresh (Orchestrator, store, approvals) backed by a temp DB."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db_path = Path(tmp.name)
    store = MemoryStore(db_path=db_path)
    approvals = ApprovalManager(store=store)
    gate = QualityGate()
    orch = Orchestrator(
        store=store,
        approval_manager=approvals,
        quality_gate=gate,
        agent_runner=None,   # no live Ollama calls
    )
    return orch, store, approvals


def _done(store: MemoryStore, specialist: str, result: str) -> str:
    """Insert a task already marked done so the orchestrator sees it completed."""
    t = store.create_task(
        description=f"Prereq: {specialist}",
        specialist=specialist,
        depends_on=[],
        needs_approval=False,
    )
    store.update_task(t["id"], status="done", result=result)
    return t["id"]


# ---------------------------------------------------------------------------
# Assertion tracking
# ---------------------------------------------------------------------------

_passed: list = []
_failed: list = []


def _assert(condition: bool, label: str, detail: str = ""):
    if condition:
        _passed.append(label)
        print(f"  [PASS] {label}")
    else:
        _failed.append(label)
        print(f"  [FAIL] {label}" + (f"\n         {detail}" if detail else ""))


# ===========================================================================
# Case 1: Reviewer rejects -> gate blocks, no approval ticket
# ===========================================================================
print(SEP)
print("Case 1 — Reviewer rejects")
print(SEP)

orch1, store1, approvals1 = _make_stack()
_done(store1, "architect", "Blueprint done.")
_done(store1, "builder",   "Code done.")
_done(store1, "reviewer",  REVIEWER_REJECT)
_done(store1, "qa",        VERIFIED_QA_PASS)

rt1 = store1.create_task(
    description="Release v1.0", specialist="release_manager",
    depends_on=[], needs_approval=True,
)

blocked1 = False
try:
    orch1.run_task(rt1["id"])
except OrchestratorError as exc:
    blocked1 = "quality gate" in str(exc).lower()

s1       = store1.get_task(rt1["id"])["status"]
pending1 = approvals1.list_pending()

_assert(blocked1,  "1A: OrchestratorError raised for rejected reviewer")
_assert(s1 == "quality_gate_failed", "1B: task status = quality_gate_failed", f"got '{s1}'")
_assert(len(pending1) == 0,          "1C: no approval ticket created",         f"{len(pending1)} found")
print()


# ===========================================================================
# Case 2: QA execution fails -> gate blocks, no approval ticket
# ===========================================================================
print(SEP)
print("Case 2 — QA sandboxed execution reports failure")
print(SEP)

orch2, store2, approvals2 = _make_stack()
_done(store2, "architect", "Blueprint done.")
_done(store2, "builder",   "Code done.")
_done(store2, "reviewer",  REVIEWER_APPROVE)
_done(store2, "qa",        VERIFIED_QA_FAIL)

rt2 = store2.create_task(
    description="Release v1.0", specialist="release_manager",
    depends_on=[], needs_approval=True,
)

blocked2 = False
try:
    orch2.run_task(rt2["id"])
except OrchestratorError as exc:
    blocked2 = "quality gate" in str(exc).lower()

s2       = store2.get_task(rt2["id"])["status"]
pending2 = approvals2.list_pending()

_assert(blocked2,  "2A: OrchestratorError raised for failed QA execution")
_assert(s2 == "quality_gate_failed", "2B: task status = quality_gate_failed", f"got '{s2}'")
_assert(len(pending2) == 0,          "2C: no approval ticket created",         f"{len(pending2)} found")
print()


# ===========================================================================
# Case 2b: QA result is text-only (no execution evidence) -> blocked
# ===========================================================================
print(SEP)
print("Case 2b — QA result is model text only (no execution evidence)")
print(SEP)

orch2b, store2b, approvals2b = _make_stack()
_done(store2b, "architect", "Blueprint done.")
_done(store2b, "builder",   "Code done.")
_done(store2b, "reviewer",  REVIEWER_APPROVE)
_done(store2b, "qa",        TEXT_ONLY_QA)

rt2b = store2b.create_task(
    description="Release v1.0", specialist="release_manager",
    depends_on=[], needs_approval=True,
)

blocked2b = False
try:
    orch2b.run_task(rt2b["id"])
except OrchestratorError as exc:
    blocked2b = "quality gate" in str(exc).lower()

s2b        = store2b.get_task(rt2b["id"])["status"]
pending2b  = approvals2b.list_pending()
r2b        = orch2b.quality_gate.check_pipeline_readiness(store2b.list_tasks())
evidence_blocker = any("execution evidence" in b for b in r2b["blockers"])

_assert(blocked2b, "2bA: OrchestratorError raised for text-only QA")
_assert(s2b == "quality_gate_failed", "2bB: task status = quality_gate_failed", f"got '{s2b}'")
_assert(len(pending2b) == 0,          "2bC: no approval ticket created",         f"{len(pending2b)} found")
_assert(evidence_blocker,             "2bD: blocker mentions execution evidence", f"blockers={r2b['blockers']}")
print()


# ===========================================================================
# Case 3: Missing Reviewer AND QA -> both blockers raised, no ticket
# ===========================================================================
print(SEP)
print("Case 3 — Missing Reviewer and missing QA")
print(SEP)

orch3, store3, approvals3 = _make_stack()
_done(store3, "architect", "Blueprint done.")
_done(store3, "builder",   "Code done.")
# No reviewer or qa tasks inserted

rt3 = store3.create_task(
    description="Release v1.0", specialist="release_manager",
    depends_on=[], needs_approval=True,
)

blocked3 = False
try:
    orch3.run_task(rt3["id"])
except OrchestratorError as exc:
    blocked3 = "quality gate" in str(exc).lower()

s3         = store3.get_task(rt3["id"])["status"]
pending3   = approvals3.list_pending()
r3         = orch3.quality_gate.check_pipeline_readiness(store3.list_tasks())
rev_blocked = any("Reviewer" in b for b in r3["blockers"])
qa_blocked  = any("QA" in b for b in r3["blockers"])

_assert(blocked3,   "3A: OrchestratorError raised when both are missing")
_assert(s3 == "quality_gate_failed", "3B: task status = quality_gate_failed", f"got '{s3}'")
_assert(len(pending3) == 0,          "3C: no approval ticket created",         f"{len(pending3)} found")
_assert(rev_blocked, "3D: Reviewer blocker present",  f"blockers={r3['blockers']}")
_assert(qa_blocked,  "3E: QA blocker present",         f"blockers={r3['blockers']}")
print()


# ===========================================================================
# Case 4: All evidence passes -> reaches human approval (NOT executed)
# ===========================================================================
print(SEP)
print("Case 4 — All checks pass: human approval gate reached, release not run")
print(SEP)

orch4, store4, approvals4 = _make_stack()
_done(store4, "architect", "Blueprint done.")
_done(store4, "builder",   "Code done.")
_done(store4, "reviewer",  REVIEWER_APPROVE)
_done(store4, "qa",        VERIFIED_QA_PASS)

rt4 = store4.create_task(
    description="Release v1.0", specialist="release_manager",
    depends_on=[], needs_approval=True,
)

reached_approval = False
executed_release = False
try:
    orch4.run_task(rt4["id"])
    executed_release = True    # should NOT reach here
except OrchestratorError as exc:
    err_lower = str(exc).lower()
    reached_approval = (
        "approval" in err_lower
        and "quality gate" not in err_lower
    )

s4         = store4.get_task(rt4["id"])["status"]
pending4   = approvals4.list_pending()
r4         = orch4.quality_gate.check_pipeline_readiness(store4.list_tasks())

_assert(not executed_release,        "4A: release task NOT silently executed")
_assert(reached_approval,            "4B: OrchestratorError mentions approval (not gate)")
_assert(s4 == "blocked",             "4C: task status = blocked (awaiting human)",  f"got '{s4}'")
_assert(len(pending4) == 1,          "4D: exactly one approval ticket created",      f"{len(pending4)} found")
_assert(r4["is_ready_for_release"],  "4E: quality gate reports is_ready_for_release=True",
        f"blockers={r4['blockers']}")

if pending4:
    ticket = pending4[0]
    _assert(ticket.get("status") == "pending",
            "4F: approval ticket status = pending")
    _assert(ticket.get("payload", {}).get("task_id") == rt4["id"],
            "4G: ticket payload.task_id matches release task",
            f"payload={ticket.get('payload')}")
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
    print("All end-to-end release gate assertions passed.")
print(SEP)
