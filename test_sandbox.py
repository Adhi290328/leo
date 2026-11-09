"""Standalone integration test for quality_gate.QualityGate.

Verifies:
  - Failing assertions are reliably detected by run_sandboxed_tests().
  - Passing test suites are confirmed correctly.
  - print() never replaces assert — every test case fails loudly on regression.

Run: python test_sandbox.py
"""
from quality_gate import QualityGate, EXECUTION_VERIFIED_KEY

gate = QualityGate()

SRC = """
def add(a, b):
    return a + b

def divide(a, b):
    if b == 0:
        raise ZeroDivisionError("division by zero")
    return a / b
"""

# -----------------------------------------------------------------------
# Case A — intentionally wrong expected value; gate must detect failure
# -----------------------------------------------------------------------
failing_test = """
import unittest
from solution import add, divide

class TestCalcFailure(unittest.TestCase):
    def test_add_wrong(self):
        self.assertEqual(add(2, 3), 999)   # wrong: add(2,3)==5, not 999

    def test_zero_divide(self):
        self.assertRaises(ZeroDivisionError, divide, 10, 0)
"""

result_fail = gate.run_sandboxed_tests(SRC, failing_test)

assert result_fail[EXECUTION_VERIFIED_KEY] is True, \
    "FAIL: Execution-verified marker must always be present"
assert result_fail["executed"] is True, \
    "FAIL: executed flag must be True"
assert result_fail["passed"] is False, \
    f"FAIL: The intentionally wrong assertion must be detected as a failure. Got: {result_fail}"

print(f"[PASS] Case A — failing assertion correctly detected")
print(f"       returncode={result_fail['returncode']}")
print(f"       stderr snippet: {result_fail['stderr'][:120].strip()}\n")

# -----------------------------------------------------------------------
# Case B — correct expected values; gate must confirm success
# -----------------------------------------------------------------------
passing_test = """
import unittest
from solution import add, divide

class TestCalcPass(unittest.TestCase):
    def test_add_correct(self):
        self.assertEqual(add(2, 3), 5)

    def test_divide_correct(self):
        self.assertAlmostEqual(divide(10, 4), 2.5)

    def test_zero_divide(self):
        self.assertRaises(ZeroDivisionError, divide, 10, 0)
"""

result_pass = gate.run_sandboxed_tests(SRC, passing_test)

assert result_pass[EXECUTION_VERIFIED_KEY] is True, \
    "FAIL: Execution-verified marker must always be present"
assert result_pass["passed"] is True, \
    f"FAIL: All correct assertions must pass. Got: {result_pass}"

print(f"[PASS] Case B — all correct assertions confirmed passing")
print(f"       returncode={result_pass['returncode']}\n")

print("test_sandbox.py: All cases passed.")
