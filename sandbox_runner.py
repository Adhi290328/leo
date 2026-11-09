"""Windows Process Isolation Sandbox for Project LEO.

Replaces the plain subprocess runner in quality_gate.py with a
Windows Job Object-backed execution environment.

Defense-in-depth layers (in order of execution):
  LAYER-1  Static validation  — code_validator.py checks both source and test
                                 files with an AST allowlist BEFORE execution.
                                 Execution is blocked if any violation is found.
  LAYER-2  Environment strip   — child receives only minimal OS env vars;
                                 home/profile paths are redirected to the
                                 sandbox temp dir (virtualizes expanduser).
  LAYER-3  Job Object limits   — memory ceiling, active-process cap,
                                 kill-on-close, hard timeout.

What this layer DOES enforce:
  JOB-1  Kill-on-close  — all child processes die when the job handle closes,
                          even if the test code spawns children of its own.
  JOB-2  Memory ceiling — process commit is capped; runaway allocations
                          are killed by the kernel (default: 256 MB).
  JOB-3  Process limit  — at most MAX_CHILD_PROCESSES in the job at once;
                          fork bombs are contained (default: 4).
  VAL-1  Allowlist      — only modules in code_validator.SAFE_MODULES may
                          be imported; exec/eval/compile are blocked.
  ENV-1  Stripped env   — only SYSTEMROOT, TEMP, TMP, COMSPEC, PATH
                          (Python executable dir only) reach the child.
  ENV-2  Home redirect  — USERPROFILE, APPDATA, LOCALAPPDATA, HOMEDRIVE,
                          HOMEPATH all point at the sandbox temp dir so
                          os.path.expanduser stays inside the sandbox.
  CWD-1  Isolated cwd   — child cwd is the sandbox temp dir.
  TIME-1 Hard timeout   — kills the process tree via the job handle.

What this layer does NOT yet enforce (documented gaps):
  GAP-FS   Filesystem   — absolute-path open() calls can still reach files
                          outside the sandbox dir. The AST validator blocks
                          the most common import-based vectors, but obfuscated
                          or computed paths are not caught statically.
                          Mitigation: DACL hardening or Windows Sandbox VM.
  GAP-NET  Network      — import socket is blocked by the validator, but
                          obfuscated socket use is not caught statically.
                          Mitigation: Windows Filtering Platform rules.
  GAP-TOKEN Token level — process still runs at Medium integrity.
                          Mitigation: CreateRestrictedToken + low integrity.

Usage in quality_gate.py:
    from sandbox_runner import run_isolated_tests
    result = run_isolated_tests(source_code, test_code, timeout_seconds=15)
    # result has the same shape as quality_gate.run_sandboxed_tests()
"""

import sys
import os
import threading
import ctypes
import ctypes.wintypes

from code_validator import validate_pair, ValidationResult
import subprocess
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# The verified-execution marker (must match quality_gate.EXECUTION_VERIFIED_KEY)
# ---------------------------------------------------------------------------
EXECUTION_VERIFIED_KEY = "__leo_sandboxed_exec__"

# ---------------------------------------------------------------------------
# Default resource limits
# ---------------------------------------------------------------------------
MAX_MEMORY_BYTES     = 256 * 1024 * 1024   # 256 MB per-process commit
MAX_CHILD_PROCESSES  = 4                   # prevents fork bombs

# ---------------------------------------------------------------------------
# Windows API setup (64-bit constants for Windows 8+)
# ---------------------------------------------------------------------------
_WINDOWS = sys.platform == "win32"

if _WINDOWS:
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # Limit flags
    _JOB_LIMIT_ACTIVE_PROCESS   = 0x00000008
    _JOB_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JOB_LIMIT_PROCESS_MEMORY   = 0x00000100

    # SetInformationJobObject class
    _JobObjectExtendedLimitInformation = 9

    class _BasicLimit(ctypes.Structure):
        """JOBOBJECT_BASIC_LIMIT_INFORMATION (64-bit layout)."""
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),   # LARGE_INTEGER  8
            ("PerJobUserTimeLimit",     ctypes.c_longlong),   # LARGE_INTEGER  8
            ("LimitFlags",             ctypes.c_uint32),      # DWORD          4
            ("_pad1",                  ctypes.c_uint32),      # alignment      4
            ("MinimumWorkingSetSize",  ctypes.c_size_t),      # SIZE_T         8
            ("MaximumWorkingSetSize",  ctypes.c_size_t),      # SIZE_T         8
            ("ActiveProcessLimit",     ctypes.c_uint32),      # DWORD          4
            ("_pad2",                  ctypes.c_uint32),      # alignment      4
            ("Affinity",               ctypes.c_size_t),      # ULONG_PTR      8
            ("PriorityClass",          ctypes.c_uint32),      # DWORD          4
            ("SchedulingClass",        ctypes.c_uint32),      # DWORD          4
        ]

    class _IoCounters(ctypes.Structure):
        """IO_COUNTERS."""
        _fields_ = [
            ("ReadOperationCount",  ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount",   ctypes.c_uint64),
            ("WriteTransferCount",  ctypes.c_uint64),
            ("OtherTransferCount",  ctypes.c_uint64),
        ]

    class _ExtendedLimit(ctypes.Structure):
        """JOBOBJECT_EXTENDED_LIMIT_INFORMATION (64-bit layout)."""
        _fields_ = [
            ("BasicLimitInformation", _BasicLimit),   # 64 bytes
            ("IoInfo",                _IoCounters),   # 48 bytes
            ("ProcessMemoryLimit",    ctypes.c_size_t),
            ("JobMemoryLimit",        ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed",     ctypes.c_size_t),
        ]

    _PROCESS_ALL_ACCESS = 0x1F0FFF

    # Windows AppContainer API & structures
    _adv32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _userenv = ctypes.WinDLL("userenv", use_last_error=True)

    _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
    _EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    _STARTF_USESTDHANDLES = 0x00000100

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.wintypes.DWORD),
            ("lpReserved", ctypes.wintypes.LPWSTR),
            ("lpDesktop", ctypes.wintypes.LPWSTR),
            ("lpTitle", ctypes.wintypes.LPWSTR),
            ("dwX", ctypes.wintypes.DWORD),
            ("dwY", ctypes.wintypes.DWORD),
            ("dwXSize", ctypes.wintypes.DWORD),
            ("dwYSize", ctypes.wintypes.DWORD),
            ("dwXCountChars", ctypes.wintypes.DWORD),
            ("dwYCountChars", ctypes.wintypes.DWORD),
            ("dwFillAttribute", ctypes.wintypes.DWORD),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("wShowWindow", ctypes.wintypes.WORD),
            ("cbReserved2", ctypes.wintypes.WORD),
            ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", ctypes.wintypes.HANDLE),
            ("hStdOutput", ctypes.wintypes.HANDLE),
            ("hStdError", ctypes.wintypes.HANDLE),
        ]

    class SECURITY_CAPABILITIES(ctypes.Structure):
        _fields_ = [
            ("AppContainerSid", ctypes.c_void_p),
            ("Capabilities", ctypes.c_void_p),
            ("CapabilityCount", ctypes.wintypes.DWORD),
            ("Reserved", ctypes.wintypes.DWORD),
        ]

    class STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [
            ("StartupInfo", STARTUPINFOW),
            ("lpAttributeList", ctypes.c_void_p),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", ctypes.wintypes.HANDLE),
            ("hThread", ctypes.wintypes.HANDLE),
            ("dwProcessId", ctypes.wintypes.DWORD),
            ("dwThreadId", ctypes.wintypes.DWORD),
        ]

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", ctypes.wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", ctypes.wintypes.BOOL),
        ]

    def _get_appcontainer_sid(name: str = "ProjectLEO.SandboxContainer") -> tuple:
        pSid = ctypes.c_void_p()
        hr = _userenv.CreateAppContainerProfile(
            ctypes.c_wchar_p(name), ctypes.c_wchar_p(name),
            ctypes.c_wchar_p("Project LEO Sandbox Container"), None, 0, ctypes.byref(pSid)
        )
        if hr != 0:
            _userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(pSid))
        pStr = ctypes.c_wchar_p()
        _adv32.ConvertSidToStringSidW(pSid, ctypes.byref(pStr))
        sid_str = pStr.value
        _k32.LocalFree(pStr)
        return pSid, sid_str

    def _pipe_reader(handle, chunk_list):
        read_buf = (ctypes.c_char * 4096)()
        bytes_read = ctypes.wintypes.DWORD()
        while True:
            success = _k32.ReadFile(handle, read_buf, 4096, ctypes.byref(bytes_read), None)
            if not success or bytes_read.value == 0:
                break
            chunk_list.append(read_buf.raw[:bytes_read.value])
        _k32.CloseHandle(handle)


def _build_minimal_env(sandbox_dir: Path = None) -> dict:
    """
    Return a minimal environment dict for the sandboxed subprocess.

    Two controls are applied:
      ENV-1 Strip: only a small set of OS-required vars are kept.
      ENV-2 Home redirect: USERPROFILE and related vars are pointed
            at sandbox_dir so os.path.expanduser('~') stays inside
            the sandbox instead of resolving to the real user home.
    """
    keep = {"SYSTEMROOT", "COMSPEC"}
    env = {k: v for k, v in os.environ.items() if k.upper() in keep}

    # PATH: only the Python executable dir
    python_dir = str(Path(sys.executable).parent)
    env["PATH"] = python_dir

    # Point TEMP/TMP at sandbox dir so tmpfile creation stays inside
    sandbox_str = str(sandbox_dir) if sandbox_dir else os.environ.get("TEMP", "C:\\Temp")
    env["TEMP"] = sandbox_str
    env["TMP"]  = sandbox_str
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    # ENV-2: redirect all home/profile paths into the sandbox dir
    # This virtualizes os.path.expanduser('~') for the child process.
    if sandbox_dir:
        drive = sandbox_dir.drive or "C:"
        try:
            rel = str(sandbox_dir.relative_to(sandbox_dir.anchor))
        except ValueError:
            rel = str(sandbox_dir)
        env["USERPROFILE"]  = sandbox_str
        env["HOMEDRIVE"]    = drive
        env["HOMEPATH"]     = "\\" + rel
        env["APPDATA"]      = sandbox_str
        env["LOCALAPPDATA"] = sandbox_str
        env["ONEDRIVE"]     = sandbox_str

    return env


def _assign_to_job(job_handle: int, pid: int) -> bool:
    """
    Open the process by PID and assign it to the given Job Object handle.
    Returns True on success.
    """
    h_proc = _k32.OpenProcess(_PROCESS_ALL_ACCESS, False, pid)
    if not h_proc:
        return False
    ok = bool(_k32.AssignProcessToJobObject(job_handle, h_proc))
    _k32.CloseHandle(h_proc)
    return ok


def _create_job(
    max_memory_bytes: int = MAX_MEMORY_BYTES,
    max_processes: int = MAX_CHILD_PROCESSES,
) -> int:
    """
    Create a Windows Job Object and apply resource limits.
    Returns the job handle (caller must CloseHandle when done).
    Raises OSError on failure.
    """
    job = _k32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(f"CreateJobObjectW failed: {ctypes.get_last_error()}")

    info = _ExtendedLimit()
    info.BasicLimitInformation.LimitFlags = (
        _JOB_LIMIT_KILL_ON_JOB_CLOSE
        | _JOB_LIMIT_ACTIVE_PROCESS
        | _JOB_LIMIT_PROCESS_MEMORY
    )
    info.BasicLimitInformation.ActiveProcessLimit = max_processes
    info.ProcessMemoryLimit = max_memory_bytes

    ok = _k32.SetInformationJobObject(
        job,
        _JobObjectExtendedLimitInformation,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not ok:
        err = ctypes.get_last_error()
        _k32.CloseHandle(job)
        raise OSError(f"SetInformationJobObject failed: {err}")

    return job


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _run_isolated_impl(
    source_code: str,
    test_code: str,
    timeout_seconds: int = 15,
    workspace_dir: Path = None,
    max_memory_bytes: int = MAX_MEMORY_BYTES,
    max_processes: int = MAX_CHILD_PROCESSES,
    skip_validation: bool = False,
) -> dict:
    """Internal implementation of isolated test execution."""
    base_dir = workspace_dir or (Path(__file__).resolve().parent / "workspace")
    base_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=base_dir, ignore_cleanup_errors=True) as tmp:
        tmp_path = Path(tmp)

        # Prepare test code with auto-import before validation
        if "from solution import" not in test_code and "import solution" not in test_code:
            test_code_with_import = "from solution import *\n" + test_code
        else:
            test_code_with_import = test_code

        # ------------------------------------------------------------------
        # LAYER-1: Static validation before any execution
        # ------------------------------------------------------------------
        if not skip_validation:
            validation = validate_pair(source_code, test_code_with_import)
            if not validation.allowed:
                return {
                    EXECUTION_VERIFIED_KEY: False,
                    "executed":   False,
                    "blocked":    True,
                    "passed":     False,
                    "returncode": -1,
                    "stdout":     "",
                    "stderr":     "Code validation failed:\n" + "\n".join(
                        f"  - {v}" for v in validation.violations
                    ),
                    "violations": validation.violations,
                    "summary":    f"Execution blocked: {len(validation.violations)} violation(s) found",
                    "isolation":  {
                        "platform":     sys.platform,
                        "job_object":   False,
                        "validated":    True,
                        "blocked_by":   "code_validator",
                        "gaps":         ["filesystem_absolute", "network_obfuscated"],
                    },
                }

        (tmp_path / "solution.py").write_text(source_code, encoding="utf-8")
        (tmp_path / "test_solution.py").write_text(test_code_with_import, encoding="utf-8")

        isolation_record = {
            "platform":          sys.platform,
            "validated":         not skip_validation,
            "job_object":        False,
            "appcontainer":      False,
            "appcontainer_sid":  None,
            "memory_limit":      None,
            "process_limit":     None,
            "env_stripped":      False,
            "home_redirect":     False,
            "gaps":              ["filesystem_absolute", "network_obfuscated", "token_integrity"],
        }

        env   = _build_minimal_env(tmp_path) if _WINDOWS else None
        job   = None

        try:
            if _WINDOWS:
                try:
                    job = _create_job(max_memory_bytes, max_processes)
                    isolation_record["job_object"]    = True
                    isolation_record["memory_limit"]  = max_memory_bytes
                    isolation_record["process_limit"] = max_processes
                except OSError as je:
                    isolation_record["job_object_error"] = str(je)
                    return {
                        EXECUTION_VERIFIED_KEY: False,
                        "executed":    False,
                        "passed":      False,
                        "returncode":  -1,
                        "stdout":      "",
                        "stderr":      f"Security failure: Windows Job Object setup failed ({je}). Execution aborted (fail-closed).",
                        "summary":     "Windows Job Object setup failed (fail-closed)",
                        "isolation":   isolation_record,
                    }

                isolation_record["env_stripped"]  = True
                isolation_record["home_redirect"] = True

                # ----------------------------------------------------------
                # LAYER-4: AppContainer Kernel Isolation
                # ----------------------------------------------------------
                try:
                    pSid, sid_str = _get_appcontainer_sid()
                    subprocess.run(["icacls", str(tmp_path), "/grant", f"*{sid_str}:(OI)(CI)(F)", "/Q"], check=True)

                    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
                    hOutRead, hOutWrite = ctypes.wintypes.HANDLE(), ctypes.wintypes.HANDLE()
                    _k32.CreatePipe(ctypes.byref(hOutRead), ctypes.byref(hOutWrite), ctypes.byref(sa), 0)
                    _k32.SetHandleInformation(hOutRead, 1, 0)

                    hErrRead, hErrWrite = ctypes.wintypes.HANDLE(), ctypes.wintypes.HANDLE()
                    _k32.CreatePipe(ctypes.byref(hErrRead), ctypes.byref(hErrWrite), ctypes.byref(sa), 0)
                    _k32.SetHandleInformation(hErrRead, 1, 0)

                    size = ctypes.c_size_t(0)
                    _k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
                    buf = (ctypes.c_char * size.value)()
                    pAttrList = ctypes.cast(buf, ctypes.c_void_p)
                    _k32.InitializeProcThreadAttributeList(pAttrList, 1, 0, ctypes.byref(size))

                    sec_caps = SECURITY_CAPABILITIES(pSid, None, 0, 0)
                    _k32.UpdateProcThreadAttribute(
                        pAttrList, 0, _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                        ctypes.byref(sec_caps), ctypes.sizeof(sec_caps), None, None
                    )

                    si = STARTUPINFOEXW()
                    si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
                    si.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
                    si.StartupInfo.hStdOutput = hOutWrite
                    si.StartupInfo.hStdError = hErrWrite
                    si.lpAttributeList = pAttrList.value

                    pi = PROCESS_INFORMATION()
                    cmd_line = f'"{sys.executable}" -B -m unittest test_solution.py'

                    flags = _EXTENDED_STARTUPINFO_PRESENT
                    env_block = None
                    if env:
                        flags |= 0x00000400  # CREATE_UNICODE_ENVIRONMENT
                        env_str = "\0".join(f"{k}={v}" for k, v in env.items()) + "\0\0"
                        env_block = ctypes.c_wchar_p(env_str)

                    created = _k32.CreateProcessW(
                        ctypes.c_wchar_p(sys.executable),
                        ctypes.c_wchar_p(cmd_line),
                        None, None, True,
                        flags,
                        env_block,
                        ctypes.c_wchar_p(str(tmp_path)),
                        ctypes.byref(si),
                        ctypes.byref(pi)
                    )

                    _k32.CloseHandle(hOutWrite)
                    _k32.CloseHandle(hErrWrite)

                    if created:
                        isolation_record["appcontainer"]     = True
                        isolation_record["appcontainer_sid"] = sid_str
                        isolation_record["gaps"]             = []

                        if job:
                            assigned = _assign_to_job(job, pi.dwProcessId)
                            if not assigned:
                                _k32.TerminateProcess(pi.hProcess, 1)
                                _k32.CloseHandle(pi.hProcess)
                                _k32.CloseHandle(pi.hThread)
                                _k32.DeleteProcThreadAttributeList(pAttrList)
                                _adv32.FreeSid(pSid)
                                return {
                                    EXECUTION_VERIFIED_KEY: False,
                                    "executed":    False,
                                    "passed":      False,
                                    "returncode":  -1,
                                    "stdout":      "",
                                    "stderr":      f"Security failure: AssignProcessToJobObject failed ({_k32.GetLastError()}). Execution aborted (fail-closed).",
                                    "summary":     "Process assignment to Job Object failed (fail-closed)",
                                    "isolation":   isolation_record,
                                }

                        stdout_chunks, stderr_chunks = [], []
                        t_out = threading.Thread(target=_pipe_reader, args=(hOutRead, stdout_chunks))
                        t_err = threading.Thread(target=_pipe_reader, args=(hErrRead, stderr_chunks))
                        t_out.start()
                        t_err.start()

                        wait_res = _k32.WaitForSingleObject(pi.hProcess, timeout_seconds * 1000)
                        timed_out = (wait_res == 0x00000102)

                        if timed_out:
                            _k32.TerminateProcess(pi.hProcess, 1)

                        t_out.join()
                        t_err.join()

                        exit_code = ctypes.wintypes.DWORD()
                        _k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))

                        _k32.CloseHandle(pi.hProcess)
                        _k32.CloseHandle(pi.hThread)
                        _k32.DeleteProcThreadAttributeList(pAttrList)
                        _adv32.FreeSid(pSid)

                        stdout_str = b"".join(stdout_chunks).decode("utf-8", errors="replace")
                        stderr_str = b"".join(stderr_chunks).decode("utf-8", errors="replace")

                        if timed_out:
                            return {
                                EXECUTION_VERIFIED_KEY: True,
                                "executed":    True,
                                "passed":      False,
                                "returncode":  -1,
                                "stdout":      stdout_str,
                                "stderr":      f"Killed: execution exceeded {timeout_seconds}s timeout.",
                                "summary":     "Test execution timed out and was killed",
                                "isolation":   isolation_record,
                            }

                        success = (exit_code.value == 0)
                        return {
                            EXECUTION_VERIFIED_KEY: True,
                            "executed":    True,
                            "passed":      success,
                            "returncode":  exit_code.value,
                            "stdout":      stdout_str,
                            "stderr":      stderr_str,
                            "summary":     "Sandboxed unit tests passed" if success else "Sandboxed unit tests FAILED",
                            "isolation":   isolation_record,
                        }
                    else:
                        err_code = _k32.GetLastError()
                        _k32.CloseHandle(hOutRead)
                        _k32.CloseHandle(hErrRead)
                        _k32.DeleteProcThreadAttributeList(pAttrList)
                        _adv32.FreeSid(pSid)
                        return {
                            EXECUTION_VERIFIED_KEY: False,
                            "executed":    False,
                            "passed":      False,
                            "returncode":  -1,
                            "stdout":      "",
                            "stderr":      f"Security failure: AppContainer CreateProcessW failed with error {err_code}. Execution aborted (fail-closed).",
                            "summary":     "AppContainer process creation failed (fail-closed)",
                            "isolation":   isolation_record,
                        }
                except Exception as ace:
                    return {
                        EXECUTION_VERIFIED_KEY: False,
                        "executed":    False,
                        "passed":      False,
                        "returncode":  -1,
                        "stdout":      "",
                        "stderr":      f"Security failure: AppContainer setup failed ({ace}). Execution aborted (fail-closed).",
                        "summary":     "AppContainer setup failed (fail-closed)",
                        "isolation":   isolation_record,
                    }

            # Non-Windows platform fallback (plain subprocess)
            proc = subprocess.Popen(
                [sys.executable, "-B", "-m", "unittest", "test_solution.py"],
                cwd=str(tmp_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )

            if _WINDOWS and job:
                _assign_to_job(job, proc.pid)

            try:
                stdout, stderr = proc.communicate(timeout=timeout_seconds)
                success = proc.returncode == 0
                return {
                    EXECUTION_VERIFIED_KEY: True,
                    "executed":    True,
                    "passed":      success,
                    "returncode":  proc.returncode,
                    "stdout":      stdout.decode("utf-8", errors="replace"),
                    "stderr":      stderr.decode("utf-8", errors="replace"),
                    "summary":     "Sandboxed unit tests passed" if success else "Sandboxed unit tests FAILED",
                    "isolation":   isolation_record,
                }
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return {
                    EXECUTION_VERIFIED_KEY: True,
                    "executed":    True,
                    "passed":      False,
                    "returncode":  -1,
                    "stdout":      "",
                    "stderr":      f"Killed: execution exceeded {timeout_seconds}s timeout.",
                    "summary":     "Test execution timed out and was killed",
                    "isolation":   isolation_record,
                }

        except Exception as exc:
            return {
                EXECUTION_VERIFIED_KEY: False,
                "executed":    False,
                "passed":      False,
                "returncode":  -1,
                "stdout":      "",
                "stderr":      str(exc),
                "summary":     f"Sandbox setup failed: {exc}",
                "isolation":   isolation_record,
            }
        finally:
            if _WINDOWS and job:
                _k32.CloseHandle(job)


def run_isolated_tests(
    source_code: str,
    test_code: str,
    timeout_seconds: int = 15,
    workspace_dir: Path = None,
    max_memory_bytes: int = MAX_MEMORY_BYTES,
    max_processes: int = MAX_CHILD_PROCESSES,
) -> dict:
    """
    Execute Python unit tests in an isolated subprocess with mandatory pre-execution validation.

    This is the production entrypoint used by QualityGate. It does not accept any bypass
    or skip parameters. Validation always runs before execution.
    """
    return _run_isolated_impl(
        source_code=source_code,
        test_code=test_code,
        timeout_seconds=timeout_seconds,
        workspace_dir=workspace_dir,
        max_memory_bytes=max_memory_bytes,
        max_processes=max_processes,
        skip_validation=False,
    )


def _run_unvalidated_for_isolation_audit(
    source_code: str,
    test_code: str,
    timeout_seconds: int = 15,
    workspace_dir: Path = None,
    max_memory_bytes: int = MAX_MEMORY_BYTES,
    max_processes: int = MAX_CHILD_PROCESSES,
) -> dict:
    """
    Internal testing-only entrypoint used exclusively by test_isolation.py.
    Explicitly probes low-level OS/Job Object limits in the hypothetical event of an AST bypass.
    """
    return _run_isolated_impl(
        source_code=source_code,
        test_code=test_code,
        timeout_seconds=timeout_seconds,
        workspace_dir=workspace_dir,
        max_memory_bytes=max_memory_bytes,
        max_processes=max_processes,
        skip_validation=True,
    )


# ---------------------------------------------------------------------------
# Quick smoke-test (python sandbox_runner.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("sandbox_runner smoke-test")
    print("=" * 40)

    r = run_isolated_tests(
        source_code="def add(a, b): return a + b",
        test_code="""
import unittest
from solution import add
class T(unittest.TestCase):
    def test_ok(self): self.assertEqual(add(1, 2), 3)
""",
        timeout_seconds=10,
    )
    print(f"passed:     {r['passed']}")
    print(f"returncode: {r['returncode']}")
    print(f"isolation:  {r['isolation']}")
    assert r["passed"], f"Smoke-test failed: {r}"
    print("Smoke-test passed.")
