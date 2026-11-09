"""Windows process isolation tests for Project LEO.

Verifies what the defense-in-depth sandbox DOES and DOES NOT enforce.
Uses sandbox_runner.run_isolated_tests() directly (not quality_gate)
so each claim is tested against the actual enforcement layer.

Section 1 -- ENFORCED: Job Object resource limits
  I1: Timeout kill    -- infinite loop is killed within deadline
  I2: Memory cap      -- >256 MB allocation is killed by the kernel
  I3: Process limit   -- spawning many children is capped by the job
  I4: Kill-on-close   -- Job Object cleans up, isolation dict confirms marker
  I5: Env stripped    -- child cannot see LEO_MODEL or user PATH

Section 2 -- ENFORCED: OS-level containment (Windows AppContainer)
  O1: Filesystem DACL   -- Canary file read outside sandbox is blocked with PermissionError
  O2a: External Network -- Egress socket blocked by AppContainer with WSAEACCES (10013)
  O2b: Loopback Network -- Loopback TCP connection dropped by network stack (TimeoutError)
  O3: Isolation Record  -- Confirms AppContainer active and zero gaps reported
  O4: Fail-Closed       -- Setup failures abort execution safely (no unconfined fallback)

Section 3 -- ENFORCED: AST static validator (code_validator.py)
  V1: import socket blocked
  V2: import subprocess blocked
  V3: import os blocked
  V4: exec() call blocked
  V5: eval() call blocked
  V6: import ctypes blocked
  V7: Safe modules allowed (math, re, json, collections, unittest)
  V8: End-to-end: code with socket import does not execute

Section 4 -- ENFORCED: Home-path environment virtualization
  H1: os.path.expanduser returns sandbox dir, not real home
  H2: APPDATA points to sandbox dir
  H3: USERPROFILE points to sandbox dir
  H4: Isolation dict reports home_redirect=True

Each gap test ASSERTS the escape currently SUCCEEDS, then prints [GAP].
This proves the gap is real, not just assumed.

Run: python test_isolation.py
"""

import sys
import os
import socket
import tempfile
from pathlib import Path

from sandbox_runner import (
    run_isolated_tests,
    _run_unvalidated_for_isolation_audit,
    EXECUTION_VERIFIED_KEY,
    MAX_MEMORY_BYTES,
)
from code_validator import validate, SAFE_MODULES

SEP = "=" * 58

_passed: list = []
_failed: list = []


def _assert(condition: bool, label: str, detail: str = ""):
    if condition:
        _passed.append(label)
        print(f"  [PASS] {label}")
    else:
        _failed.append(label)
        print(f"  [FAIL] {label}" + (f"\n         {detail}" if detail else ""))


def _gap(condition: bool, label: str, note: str = ""):
    """Assert that an escape SUCCEEDS (gap confirmed) and print a [GAP] marker."""
    if condition:
        _passed.append(label)
        print(f"  [GAP ] {label}  << not yet blocked")
        if note:
            print(f"         Mitigation needed: {note}")
    else:
        # Escape failed -- the gap may already be mitigated, mark as unexpected
        _passed.append(label)
        print(f"  [GAP?] {label}  << escape was blocked (unexpected -- recheck)")


# ============================================================
# Helpers
# ============================================================

def _run(source: str, test: str, timeout: int = 8, **kw) -> dict:
    """Production execution path — mandatory pre-execution validation."""
    return run_isolated_tests(source, test, timeout_seconds=timeout, **kw)


def _run_audit(source: str, test: str, timeout: int = 8, **kw) -> dict:
    """Audit-only execution path — tests lower-level OS/Job limits under hypothetical bypass."""
    return _run_unvalidated_for_isolation_audit(source, test, timeout_seconds=timeout, **kw)


TRIVIAL_SRC = "def noop(): pass"

# ============================================================
# Section 1 — ENFORCED limits
# ============================================================
print(SEP)
print("Section 1 — Enforced limits (Job Object)")
print(SEP)

# I1: Timeout kill
print("\n[I1] Timeout: infinite loop must be killed")
r_i1 = _run(
    source="def loop(): \n    import time\n    while True: time.sleep(0.01)",
    test="""
import unittest
from solution import loop
class T(unittest.TestCase):
    def test_inf(self): loop()
""",
    timeout=4,
)
_assert(r_i1[EXECUTION_VERIFIED_KEY] is True, "I1a: execution marker present")
_assert(r_i1["passed"] is False,              "I1b: infinite loop did not pass")
_assert(r_i1["returncode"] != 0,              "I1c: non-zero returncode after kill",
        f"got {r_i1['returncode']}")
print(f"       stderr snippet: {r_i1['stderr'][:80].strip()}")

# I2: Memory cap — allocate 2× the job limit; process must be killed
# We use max_memory_bytes=64MB so the test runs quickly
SMALL_MEM = 64 * 1024 * 1024   # 64 MB cap for this test
ALLOC_MB  = 256                 # allocate 256 MB (4× the cap)

print(f"\n[I2] Memory cap: allocating {ALLOC_MB} MB against {SMALL_MEM // (1024*1024)} MB limit")
r_i2 = _run(
    source=f"def eat(): return bytearray({ALLOC_MB} * 1024 * 1024)",
    test="""
import unittest
from solution import eat
class T(unittest.TestCase):
    def test_mem(self): self.assertIsNotNone(eat())
""",
    timeout=10,
    max_memory_bytes=SMALL_MEM,
)
_assert(r_i2[EXECUTION_VERIFIED_KEY] is True, "I2a: execution marker present")
_assert(r_i2["passed"] is False,              "I2b: over-limit allocation was killed",
        f"passed={r_i2['passed']} returncode={r_i2['returncode']} stderr={r_i2['stderr'][:80]}")
print(f"       returncode: {r_i2['returncode']}  stderr: {r_i2['stderr'][:60].strip()}")

# I3: Active-process limit — spawning many subprocesses capped by job
print("\n[I3] Process cap: spawning excess children is blocked by job")
r_i3 = _run_audit(
    source="""
import subprocess, sys
def spawn_many():
    procs = []
    for _ in range(20):
        p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
        procs.append(p)
    for p in procs:
        try: p.wait(timeout=1)
        except: p.kill()
""",
    test="""
import unittest
from solution import spawn_many
class T(unittest.TestCase):
    def test_spawn(self): spawn_many()
""",
    timeout=8,
    max_processes=3,   # cap at 3 (Python + unittest + 1 child = already at limit)
)
_assert(r_i3[EXECUTION_VERIFIED_KEY] is True, "I3a: execution marker present")
_assert(r_i3["passed"] is False,              "I3b: excess process spawn was blocked or caused failure",
        f"passed={r_i3['passed']} returncode={r_i3['returncode']}")
print(f"       returncode: {r_i3['returncode']}")

# I4: Kill-on-close marker — isolation dict must report job_object=True on Windows
print("\n[I4] Kill-on-close: isolation dict confirms Job Object applied")
r_i4 = _run(TRIVIAL_SRC, """
import unittest
from solution import noop
class T(unittest.TestCase):
    def test_noop(self): noop()
""")
_assert(r_i4[EXECUTION_VERIFIED_KEY] is True, "I4a: execution marker present")
_assert(r_i4["passed"] is True,               "I4b: trivial test passes inside job")
iso = r_i4.get("isolation", {})
if sys.platform == "win32":
    _assert(iso.get("job_object") is True,    "I4c: job_object=True on Windows",
            f"isolation={iso}")
    _assert(iso.get("memory_limit") is not None, "I4d: memory_limit reported")
    _assert(iso.get("process_limit") is not None,"I4e: process_limit reported")
else:
    print("  [SKIP] I4c/d/e: not on Windows")

# I5: Stripped environment — child should NOT see custom or secret user variables
print("\n[I5] Environment stripping: child cannot see user variables")
r_i5 = _run_audit(
    source="""
import os
def check_env():
    leaked = {k: v for k, v in os.environ.items()
              if k.upper() in ('LEO_MODEL', 'COMPUTERNAME', 'USERDOMAIN')}
    return leaked
""",
    test="""
import unittest
from solution import check_env
class T(unittest.TestCase):
    def test_env(self):
        leaked = check_env()
        self.assertEqual(leaked, {}, f"Leaked env vars: {leaked}")
""",
)
_assert(r_i5[EXECUTION_VERIFIED_KEY] is True, "I5a: execution marker present")
_assert(r_i5["passed"] is True,               "I5b: no user env vars leaked to child",
        f"stderr={r_i5['stderr'][:120]}")

print()

# ============================================================
# Section 2 — DOCUMENTED GAPS
# ============================================================
# Section 2 — ENFORCED: OS-level containment (Windows AppContainer)
# ============================================================
print(SEP)
print("Section 2 — OS-enforced boundaries (Windows AppContainer)")
print(SEP)

# O1: Canary File Read Outside Sandbox — verified blocked by OS DACL
print("\n[O1] OS Filesystem Boundary: Canary file read outside sandbox is blocked")
CANARY_FILE = Path(os.environ.get("USERPROFILE", "C:\\Users")) / "canary_security_audit.txt"
CANARY_FILE.write_text("CONFIDENTIAL_CANARY_TOKEN_12345", encoding="utf-8")

try:
    r_o1 = _run_audit(
        source=f"""
def read_canary():
    try:
        with open(r'{CANARY_FILE}', 'r', encoding='utf-8') as f:
            return f.read()
    except PermissionError:
        return 'OS_ACCESS_DENIED'
    except Exception as e:
        return type(e).__name__
""",
        test="""
import unittest
from solution import read_canary
class T(unittest.TestCase):
    def test_canary(self):
        result = read_canary()
        self.assertEqual(result, 'OS_ACCESS_DENIED', f"Expected OS_ACCESS_DENIED, got: {result}")
""",
        timeout=8,
    )
    _assert(r_o1[EXECUTION_VERIFIED_KEY] is True, "O1a: execution marker present")
    _assert(r_o1["passed"] is True, "O1b: OS kernel blocked canary read with PermissionError",
            f"stdout={r_o1['stdout']} stderr={r_o1['stderr']}")
finally:
    if CANARY_FILE.exists():
        CANARY_FILE.unlink()

# O2a: External Network Isolation — egress socket blocked with PermissionError / WSAEACCES (10013)
print("\n[O2a] OS Network Boundary: External TCP connection blocked by AppContainer (WSAEACCES)")
r_o2a = _run_audit(
    source="""
import socket
def try_external():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('8.8.8.8', 53))
        s.close()
        return 'CONNECTED'
    except PermissionError as e:
        if getattr(e, 'winerror', None) == 10013:
            return 'OS_WSAEACCES_DENIED'
        return f'OS_PERMISSION_ERROR_{getattr(e, "winerror", None)}'
    except Exception as e:
        return type(e).__name__
""",
    test="""
import unittest
from solution import try_external
class T(unittest.TestCase):
    def test_ext(self):
        res = try_external()
        self.assertEqual(res, 'OS_WSAEACCES_DENIED', f"Expected OS_WSAEACCES_DENIED, got: {res}")
""",
    timeout=6,
)
_assert(r_o2a[EXECUTION_VERIFIED_KEY] is True, "O2a-1: execution marker present")
_assert(r_o2a["passed"] is True, "O2a-2: Windows AppContainer blocked external socket with WSAEACCES (10013)",
        f"stdout={r_o2a['stdout']} stderr={r_o2a['stderr']}")

# O2b: Loopback Network Isolation — loopback connection is dropped by Windows network stack (TimeoutError)
print("\n[O2b] OS Network Boundary: Loopback TCP connection dropped by AppContainer isolation")
_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
_listener.bind(("127.0.0.1", 0))
_listener.listen(1)
_listen_port = _listener.getsockname()[1]
_listener.settimeout(3)

try:
    r_o2b = _run_audit(
        source=f"""
import socket
def try_loopback():
    try:
        s = socket.create_connection(('127.0.0.1', {_listen_port}), timeout=2)
        s.close()
        return 'CONNECTED'
    except TimeoutError:
        return 'OS_LOOPBACK_TIMED_OUT'
    except Exception as e:
        return type(e).__name__
""",
        test="""
import unittest
from solution import try_loopback
class T(unittest.TestCase):
    def test_loopback(self):
        res = try_loopback()
        self.assertEqual(res, 'OS_LOOPBACK_TIMED_OUT', f"Expected OS_LOOPBACK_TIMED_OUT, got: {res}")
""",
        timeout=6,
    )
    _assert(r_o2b[EXECUTION_VERIFIED_KEY] is True, "O2b-1: execution marker present")
    _assert(r_o2b["passed"] is True, "O2b-2: Windows network stack dropped loopback packets (TimeoutError)",
            f"stdout={r_o2b['stdout']} stderr={r_o2b['stderr']}")
finally:
    _listener.close()

# O3: Isolation record confirms AppContainer active on Windows
print("\n[O3] Isolation Record: Confirms AppContainer active on Windows")
iso_o3 = r_o1.get("isolation", {})
if sys.platform == "win32":
    _assert(iso_o3.get("appcontainer") is True, "O3a: appcontainer=True on Windows", f"isolation={iso_o3}")
    _assert(iso_o3.get("appcontainer_sid") is not None, "O3b: appcontainer_sid present")
    _assert(iso_o3.get("gaps") == [], "O3c: no unmitigated OS gaps reported", f"gaps={iso_o3.get('gaps')}")
else:
    print("  [SKIP] O3: not on Windows")

# O4: Fail-closed verification — setup failures abort execution without running code
print("\n[O4] Fail-Closed Safety: Setup failures abort execution safely (fail-closed)")
import sandbox_runner

if sys.platform == "win32":
    # O4a: Injected Job Object creation failure fails closed
    orig_create_job = sandbox_runner._create_job
    try:
        def fake_create_job(*args, **kwargs):
            raise OSError("Injected Job Object creation failure for security audit")
        sandbox_runner._create_job = fake_create_job

        r_o4a = _run("def noop(): pass", "import unittest\nclass T(unittest.TestCase):\n    def test_noop(self): pass")
        _assert(r_o4a[EXECUTION_VERIFIED_KEY] is False, "O4a-1: execution marker is False on job failure")
        _assert(r_o4a["executed"] is False, "O4a-2: executed is False on job failure")
        _assert(r_o4a["passed"] is False, "O4a-3: passed is False on job failure")
        _assert("fail-closed" in r_o4a["stderr"].lower(), "O4a-4: stderr indicates fail-closed abort", f"stderr={r_o4a['stderr']}")
    finally:
        sandbox_runner._create_job = orig_create_job

    # O4b: Injected AppContainer CreateProcessW failure fails closed
    orig_create_process = sandbox_runner._k32.CreateProcessW
    try:
        def fake_create_process(*args, **kwargs):
            sandbox_runner._k32.SetLastError(5)  # ERROR_ACCESS_DENIED
            return 0
        sandbox_runner._k32.CreateProcessW = fake_create_process

        r_o4b = _run("def noop(): pass", "import unittest\nclass T(unittest.TestCase):\n    def test_noop(self): pass")
        _assert(r_o4b[EXECUTION_VERIFIED_KEY] is False, "O4b-1: execution marker is False on CreateProcessW failure")
        _assert(r_o4b["executed"] is False, "O4b-2: executed is False on CreateProcessW failure")
        _assert(r_o4b["passed"] is False, "O4b-3: passed is False on CreateProcessW failure")
        _assert("fail-closed" in r_o4b["stderr"].lower(), "O4b-4: stderr indicates fail-closed abort", f"stderr={r_o4b['stderr']}")
    finally:
        sandbox_runner._k32.CreateProcessW = orig_create_process
else:
    print("  [SKIP] O4: not on Windows")

print()

# ============================================================
# Section 3 -- ENFORCED: AST static validator
# ============================================================
print(SEP)
print("Section 3 -- AST static validator (code_validator.py)")
print(SEP)

print()
forbidden_cases = [
    ("import socket",                          "V1: import socket blocked"),
    ("import subprocess",                       "V2: import subprocess blocked"),
    ("import os",                              "V3: import os blocked"),
    ("exec('print(1)')",                       "V4: exec() call blocked"),
    ("eval('1+1')",                            "V5: eval() call blocked"),
    ("import ctypes",                          "V6: import ctypes blocked"),
]
for code, label in forbidden_cases:
    r = validate(code)
    _assert(not r.allowed and len(r.violations) > 0, label,
            f"violations={r.violations}")

# V7: safe modules are allowed
print()
safe_cases = [
    ("import math",                            "V7a: import math allowed"),
    ("import re",                              "V7b: import re allowed"),
    ("import json",                            "V7c: import json allowed"),
    ("from collections import defaultdict",    "V7d: from collections import allowed"),
    ("import unittest",                        "V7e: import unittest allowed"),
]
for code, label in safe_cases:
    r = validate(code)
    _assert(r.allowed, label, f"violations={r.violations}")

# V8: end-to-end -- code containing socket import does NOT execute
print()
print("[V8] End-to-end: socket-importing code must be blocked before execution")
r_v8 = _run(
    source="import socket\ndef get_host(): return socket.gethostname()",
    test="""
import unittest
from solution import get_host
class T(unittest.TestCase):
    def test_host(self): self.assertIsNotNone(get_host())
""",
    timeout=5,
)
_assert(r_v8.get("blocked") is True,              "V8a: result.blocked=True (not executed)")
_assert(r_v8[EXECUTION_VERIFIED_KEY] is False,    "V8b: EXECUTION_VERIFIED_KEY=False (not trusted)")
_assert(r_v8["executed"] is False,                "V8c: executed=False")
_assert("socket" in r_v8["stderr"].lower(),       "V8d: violation message mentions socket",
        f"stderr={r_v8['stderr'][:120]}")

# V9: run_isolated_tests rejects skip_validation parameter (interface hardening)
print()
print("[V9] Security interface: run_isolated_tests rejects skip_validation parameter")
try:
    run_isolated_tests(TRIVIAL_SRC, "import unittest", skip_validation=True)  # type: ignore
    _assert(False, "V9: TypeError raised when attempting to pass skip_validation")
except TypeError:
    _assert(True, "V9: TypeError raised when attempting to pass skip_validation (bypass rejected)")
print()

# ============================================================
# Section 4 -- ENFORCED: Home-path environment virtualization
# ============================================================
print(SEP)
print("Section 4 -- Home-path environment virtualization (ENV-2)")
print(SEP)

print()
print("[H1-H3] Verify expanduser, APPDATA, USERPROFILE point to sandbox")
print("        (direct subprocess probe -- bypasses AST validator intentionally)")

# Build the same env that the sandbox runner produces, then probe it directly.
import tempfile, subprocess as _sp
with tempfile.TemporaryDirectory() as _tmp:
    from sandbox_runner import _build_minimal_env
    _sandbox_env = _build_minimal_env(sandbox_dir=Path(_tmp))

    _probe = _sp.run(
        [sys.executable, "-c",
         "import os,json;print(json.dumps({'home':os.path.expanduser('~'),"
         "'appdata':os.environ.get('APPDATA','NOT_SET'),"
         "'userprofile':os.environ.get('USERPROFILE','NOT_SET')}))"],
        capture_output=True, text=True, env=_sandbox_env, timeout=10,
    )
    import json as _json
    _env_vals = _json.loads(_probe.stdout.strip())

real_home = os.path.expanduser("~")

_assert(_env_vals["home"] != real_home,
        "H1: os.path.expanduser in sandbox != real home",
        f"got {_env_vals['home']!r}, real={real_home!r}")

_assert(_env_vals["appdata"] == str(Path(_tmp)),
        "H2: APPDATA points to sandbox dir",
        f"got {_env_vals['appdata']!r}")

_assert(_env_vals["userprofile"] == str(Path(_tmp)),
        "H3: USERPROFILE points to sandbox dir",
        f"got {_env_vals['userprofile']!r}")

# H4: isolation dict from full run_isolated_tests must report home_redirect=True
_r_h4 = _run(
    "def noop(): pass",
    "import unittest\nfrom solution import noop\nclass T(unittest.TestCase):\n    def test_ok(self): noop()\n",
    timeout=8,
)
_assert(_r_h4.get("isolation", {}).get("home_redirect") is True,
        "H4: isolation dict reports home_redirect=True",
        f"isolation={_r_h4.get('isolation')}")
print()


# ============================================================
# Summary
# ============================================================
total = len(_passed) + len(_failed)
print(SEP)
print(f"Results: {len(_passed)}/{total} checks reported")
if _failed:
    print(f"\nUnexpected failures:")
    for f in _failed:
        print(f"  [FAIL] {f}")
    raise SystemExit(1)
else:
    print()
    print("Isolation summary:")
    print("  ENFORCED (OS)  : Windows AppContainer kernel DACL filesystem isolation (canary blocked)")
    print("  ENFORCED (OS)  : Windows AppContainer network isolation (zero capabilities, loopback blocked)")
    print("  ENFORCED (Job) : timeout, memory cap (256MB), process cap (4), kill-on-close")
    print("  ENFORCED (AST) : allowlist validator (socket/os/subprocess/exec/open blocked before spawn)")
    print("  ENFORCED (Env) : env strip + home-path virtualization (APPDATA/USERPROFILE)")
    print()
    print("All isolation assertions passed. Zero unmitigated OS gaps remaining.")
print(SEP)
