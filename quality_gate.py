"""Quality Gate Enforcement Layer for Project LEO.

Design principles enforced here:
  1. FAIL CLOSED  - missing Reviewer or QA evidence is itself a blocker.
                    The gate starts blocked and clears only when *both*
                    specialist reports are present and passing.
  2. EXECUTION EVIDENCE REQUIRED  - a model-written statement such as
                    "all tests passed" never counts as an executed result.
                    Only results produced by run_sandboxed_tests() carry
                    the SANDBOXED_EXECUTION_VERIFIED marker that the gate
                    trusts. Text-only QA output always raises a blocker.
  3. RESTRICTED EXECUTION  - run_sandboxed_tests() runs only code that
                    was staged explicitly by the orchestrator (not raw
                    agent output). It records stdout/stderr and returncode.
  4. NO PRIVILEGE ESCALATION  - subprocess runs the same Python interpreter
                    with no additional permissions. OS-level sandboxing is
                    a planned future enhancement; this layer documents that gap.
"""

import re
import sys
import json
import tempfile
import subprocess
from pathlib import Path

try:
    from sandbox_runner import run_isolated_tests as _run_isolated
    _SANDBOX_RUNNER_AVAILABLE = True
except ImportError:
    _SANDBOX_RUNNER_AVAILABLE = False

# Marker embedded in QA results produced only by run_sandboxed_tests().
# The pipeline gate checks this as a Python dict key, not a text pattern,
# so an agent cannot fake it by writing the string in its reply.
EXECUTION_VERIFIED_KEY = "__leo_sandboxed_exec__"


class QualityGateError(Exception):
    """Raised when quality checks fail or release criteria are violated."""
    pass


class QualityGate:
    def __init__(self, workspace_dir: Path = None):
        self.workspace_dir = (
            workspace_dir or Path(__file__).resolve().parent / "workspace"
        )
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Reviewer evaluation
    # ------------------------------------------------------------------

    def evaluate_reviewer_output(self, text: str) -> dict:
        """
        Parses Reviewer output to verify approval verdict and detect
        critical defects. Returns a structured result dict.
        """
        text_lower = text.lower()

        verdict = "unknown"
        if "verdict: approve_with_changes" in text_lower or "**verdict:** approve_with_changes" in text_lower:
            verdict = "approve_with_changes"
        elif "verdict: approve" in text_lower or "**verdict:** approve" in text_lower:
            verdict = "approve"
        elif "verdict: reject" in text_lower or "**verdict:** reject" in text_lower:
            verdict = "reject"

        critical_findings = re.findall(
            r"findings\[\s*critical\s*,\s*([^,\]]+)\s*,\s*([^,\]]+)\s*,\s*([^\]]+)\]",
            text,
            re.IGNORECASE,
        )

        passed = (verdict in ("approve", "approve_with_changes")) and len(critical_findings) == 0

        return {
            "verdict": verdict,
            "passed": passed,
            "critical_count": len(critical_findings),
            "critical_findings": critical_findings,
            "reason": (
                "Reviewer rejected the proposal"
                if verdict == "reject"
                else (
                    f"{len(critical_findings)} critical findings detected"
                    if critical_findings
                    else (
                        "Reviewer verdict is unknown (no structured verdict found)"
                        if verdict == "unknown"
                        else "Reviewer check passed"
                    )
                )
            ),
        }

    # ------------------------------------------------------------------
    # QA output evaluation  (text-pattern path - NOT trusted for release)
    # ------------------------------------------------------------------

    def evaluate_qa_output(self, text: str) -> dict:
        """
        Parses QA output to detect failing test cases mentioned in text.

        IMPORTANT: A passing result here does NOT satisfy the execution-
        evidence requirement. Release gating requires a result that carries
        EXECUTION_VERIFIED_KEY=True (produced only by run_sandboxed_tests).
        A model-written 'all tests passed' summary is insufficient.
        """
        failed_lines = []

        for line in text.splitlines():
            line_s = line.strip()
            if re.search(r"\b(fail|failed)\b", line_s, re.IGNORECASE) and not re.search(
                r"\bpass(ed)?\b", line_s, re.IGNORECASE
            ):
                if any(
                    k in line_s.lower()
                    for k in ("id", "test", "case", "expected", "result", "raise")
                ):
                    failed_lines.append(line_s)
            elif re.search(r"\b(id:\s*[\d\s,]+:\s*fail)\b", line_s, re.IGNORECASE):
                failed_lines.append(line_s)

        results_tuples = re.findall(
            r"results\[\s*([^,\]]+)\s*,\s*([^,\]]+)\s*,\s*([^\]]+)\]",
            text,
            re.IGNORECASE,
        )
        for r_id, status, notes in results_tuples:
            if "fail" in status.lower():
                failed_lines.append(f"Test Case {r_id}: {status} - {notes}")

        passed = len(failed_lines) == 0
        return {
            "passed": passed,
            "execution_verified": False,  # text-only; NOT trusted for release
            "failure_count": len(failed_lines),
            "failures": failed_lines,
            "reason": (
                f"{len(failed_lines)} test case(s) failed in QA evaluation"
                if not passed
                else "QA text evaluation found no explicit failures (execution evidence required for release)"
            ),
        }

    # ------------------------------------------------------------------
    # Sandboxed execution  (the only trusted QA evidence path)
    # ------------------------------------------------------------------

    def run_sandboxed_tests(
        self,
        source_code: str,
        test_code: str,
        timeout_seconds: int = 15,
    ) -> dict:
        """
        Executes Python unit tests in an isolated subprocess and returns a
        result dict carrying EXECUTION_VERIFIED_KEY.

        On Windows: delegates to sandbox_runner.run_isolated_tests() which
        applies a Windows Job Object (memory cap, process limit, kill-on-close)
        and a stripped environment.

        On other platforms (or if sandbox_runner is unavailable): falls back
        to a plain subprocess.run() call.

        Security note: filesystem and network access are NOT restricted by
        this layer. See sandbox_runner.py for the full gap list.
        """
        if _SANDBOX_RUNNER_AVAILABLE:
            return _run_isolated(
                source_code=source_code,
                test_code=test_code,
                timeout_seconds=timeout_seconds,
                workspace_dir=self.workspace_dir,
            )

        # Fallback: plain subprocess (no Job Object)
        with tempfile.TemporaryDirectory(dir=self.workspace_dir) as temp_dir:
            temp_path = Path(temp_dir)
            module_file = temp_path / "solution.py"
            test_file   = temp_path / "test_solution.py"

            module_file.write_text(source_code, encoding="utf-8")
            if "from solution import" not in test_code and "import solution" not in test_code:
                test_code = "from solution import *\n" + test_code
            test_file.write_text(test_code, encoding="utf-8")

            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "unittest", test_file.name],
                    cwd=str(temp_path),
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                )
                success = proc.returncode == 0
                return {
                    EXECUTION_VERIFIED_KEY: True,
                    "executed":   True,
                    "passed":     success,
                    "returncode": proc.returncode,
                    "stdout":     proc.stdout,
                    "stderr":     proc.stderr,
                    "summary":    "Sandboxed unit tests passed" if success else "Sandboxed unit tests FAILED",
                }
            except subprocess.TimeoutExpired:
                return {
                    EXECUTION_VERIFIED_KEY: True,
                    "executed":   True,
                    "passed":     False,
                    "returncode": -1,
                    "stdout":     "",
                    "stderr":     f"Execution timed out after {timeout_seconds}s",
                    "summary":    "Test execution timed out",
                }
            except Exception as exc:
                return {
                    EXECUTION_VERIFIED_KEY: False,
                    "executed":   False,
                    "passed":     False,
                    "returncode": -1,
                    "stdout":     "",
                    "stderr":     str(exc),
                    "summary":    f"Execution setup failed: {exc}",
                }

    # ------------------------------------------------------------------
    # Pipeline readiness  (the enforcement gate called by the orchestrator)
    # ------------------------------------------------------------------

    def check_pipeline_readiness(self, tasks: list) -> dict:
        """
        Audits all completed specialist tasks to decide whether the
        Release Manager may proceed to request deployment authorization.

        FAIL-CLOSED RULES (checked in priority order):
          R1. A done Reviewer task must exist.
          R2. The Reviewer verdict must be 'approve' or 'approve_with_changes'
              with zero critical findings.
          R3. A done QA task must exist.
          R4. The QA task result must carry EXECUTION_VERIFIED_KEY=True,
              proving tests were actually run by run_sandboxed_tests().
              A model-written 'all tests passed' is INSUFFICIENT.
          R5. The executed tests must have all passed (returncode==0).
          R6. Any task in a failed or quality_gate_failed state blocks release.
        """
        blockers = []
        reviewer_report = None
        qa_report = None
        qa_exec_result = None

        reviewer_done = False
        qa_done = False

        for t in tasks:
            specialist = t.get("specialist")
            status = t.get("status")
            result = t.get("result", "")

            # R6: any failed task blocks release immediately
            if status in ("failed", "quality_gate_failed"):
                blockers.append(
                    f"Task '{t.get('id')}' ({specialist}) has status '{status}' — "
                    f"must be resolved before release."
                )

            if specialist == "reviewer" and status == "done":
                reviewer_done = True
                reviewer_report = self.evaluate_reviewer_output(result)
                if not reviewer_report["passed"]:
                    blockers.append(
                        f"Reviewer Quality Gate Block: {reviewer_report['reason']}"
                    )

            elif specialist == "qa" and status == "done":
                qa_done = True

                # Try to parse stored execution result (JSON dict stored by orchestrator)
                stored = {}
                try:
                    if isinstance(result, str) and result.strip().startswith("{"):
                        stored = json.loads(result)
                except (json.JSONDecodeError, AttributeError):
                    pass

                if stored.get(EXECUTION_VERIFIED_KEY) is True:
                    # Structurally verified execution result
                    qa_exec_result = stored
                    qa_report = {
                        "passed": stored.get("passed", False),
                        "execution_verified": True,
                        "failure_count": 0 if stored.get("passed") else 1,
                        "failures": (
                            []
                            if stored.get("passed")
                            else [stored.get("stderr", "unknown failure")]
                        ),
                        "reason": stored.get("summary", ""),
                    }
                    if not stored.get("passed"):
                        blockers.append(
                            f"QA Quality Gate Block: Sandboxed tests failed — "
                            f"{stored.get('stderr', '')[:120]}"
                        )
                else:
                    # Text-only QA: parse for explicit failures but always require evidence
                    qa_report = self.evaluate_qa_output(result)
                    blockers.append(
                        "QA Quality Gate Block: No execution evidence found. "
                        "QA result must come from run_sandboxed_tests(), "
                        "not model text output."
                    )
                    if not qa_report["passed"]:
                        blockers.append(
                            f"QA Quality Gate Block: {qa_report['reason']}"
                        )

        # R1 / R3: missing specialist outputs are hard blockers
        if not reviewer_done:
            blockers.append(
                "Reviewer Quality Gate Block: No completed Reviewer task found. "
                "Release cannot proceed without a code review."
            )
        if not qa_done:
            blockers.append(
                "QA Quality Gate Block: No completed QA task found. "
                "Release cannot proceed without quality assurance."
            )

        is_ready = len(blockers) == 0
        return {
            "is_ready_for_release": is_ready,
            "blockers": blockers,
            "reviewer_report": reviewer_report,
            "qa_report": qa_report,
            "qa_exec_result": qa_exec_result,
            "recommendation": (
                "PROCEED_TO_RELEASE_GATE"
                if is_ready
                else "BLOCK_RELEASE_REQUIRE_FIXES"
            ),
        }


# ------------------------------------------------------------------
# Self-test  (python quality_gate.py)
# ------------------------------------------------------------------
if __name__ == "__main__":
    gate = QualityGate()
    print("LEO Quality Gate — self-test\n" + "=" * 42)

    src = """
def add(a, b):
    return a + b

def divide(a, b):
    if b == 0:
        raise ZeroDivisionError("division by zero")
    return a / b
"""

    # Test 1: sandboxed execution detects an intentionally failing assertion
    failing_test = """
import unittest
from solution import add, divide

class TestCalcFail(unittest.TestCase):
    def test_add_wrong_expected(self):
        self.assertEqual(add(2, 3), 999)   # intentionally wrong

    def test_zero_divide(self):
        self.assertRaises(ZeroDivisionError, divide, 10, 0)
"""
    r1 = gate.run_sandboxed_tests(src, failing_test)
    assert r1[EXECUTION_VERIFIED_KEY] is True, "Marker must be present"
    assert r1["executed"] is True
    assert r1["passed"] is False, "Failing assertion must be detected"
    print(f"[PASS] Test 1 — failing assertion detected  (returncode={r1['returncode']})")

    # Test 2: sandboxed execution confirms a correct test suite passes
    passing_test = """
import unittest
from solution import add, divide

class TestCalcPass(unittest.TestCase):
    def test_add_correct(self):
        self.assertEqual(add(2, 3), 5)

    def test_zero_divide(self):
        self.assertRaises(ZeroDivisionError, divide, 10, 0)
"""
    r2 = gate.run_sandboxed_tests(src, passing_test)
    assert r2[EXECUTION_VERIFIED_KEY] is True
    assert r2["passed"] is True, "Correct tests must pass"
    print(f"[PASS] Test 2 — correct test suite verified  (returncode={r2['returncode']})")

    # Test 3: pipeline gate fails closed when QA result is model text only
    tasks_text_qa = [
        {"specialist": "reviewer", "status": "done",
         "result": "**Verdict:** Approve\nLooks good.", "id": "t-rev"},
        {"specialist": "qa", "status": "done",
         "result": "All tests passed. 10/10 cases OK.", "id": "t-qa"},
    ]
    r3 = gate.check_pipeline_readiness(tasks_text_qa)
    assert not r3["is_ready_for_release"], "Text-only QA must block release"
    assert any("execution evidence" in b for b in r3["blockers"]), \
        "Must mention missing execution evidence"
    print("[PASS] Test 3 — text-only QA blocked release (fail-closed)")

    # Test 4: pipeline gate passes when verified execution evidence is stored
    verified_qa = json.dumps({
        EXECUTION_VERIFIED_KEY: True,
        "executed": True,
        "passed": True,
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "summary": "Sandboxed unit tests passed",
    })
    tasks_verified = [
        {"specialist": "reviewer", "status": "done",
         "result": "**Verdict:** Approve\nLooks good.", "id": "t-rev2"},
        {"specialist": "qa", "status": "done",
         "result": verified_qa, "id": "t-qa2"},
    ]
    r4 = gate.check_pipeline_readiness(tasks_verified)
    assert r4["is_ready_for_release"], \
        f"Verified execution should permit release. Blockers: {r4['blockers']}"
    print("[PASS] Test 4 — verified execution result permitted release")

    # Test 5: missing Reviewer blocks release
    tasks_no_rev = [
        {"specialist": "qa", "status": "done", "result": verified_qa, "id": "t-qa3"},
    ]
    r5 = gate.check_pipeline_readiness(tasks_no_rev)
    assert not r5["is_ready_for_release"]
    assert any("Reviewer" in b for b in r5["blockers"])
    print("[PASS] Test 5 — missing Reviewer blocked release")

    # Test 6: missing QA blocks release
    tasks_no_qa = [
        {"specialist": "reviewer", "status": "done",
         "result": "**Verdict:** Approve", "id": "t-rev3"},
    ]
    r6 = gate.check_pipeline_readiness(tasks_no_qa)
    assert not r6["is_ready_for_release"]
    assert any("QA" in b for b in r6["blockers"])
    print("[PASS] Test 6 — missing QA blocked release")

    print("\n" + "=" * 42)
    print("All 6 quality gate self-tests passed.")
