"""AST-based pre-execution code validator for Project LEO.

Validates Python source code BEFORE it enters the subprocess sandbox.
Uses an ALLOWLIST strategy: anything not explicitly permitted is rejected.

Design principles:
  - ALLOWLIST (not denylist) for import statements.
    Any module not in SAFE_MODULES is forbidden, even if it seems harmless.
  - Pattern matching for dangerous builtins that bypass import control:
    exec(), eval(), compile(), __import__(), open() with absolute paths.
  - Validation is FAST (pure AST walk, no execution) and always runs before
    sandbox_runner.run_isolated_tests() hands off to the subprocess.

What this catches:
  - Forbidden network imports: socket, ssl, http, urllib, requests, ...
  - Forbidden process imports: subprocess, multiprocessing, os, ...
  - Forbidden filesystem imports: shutil, pathlib (direct), glob, ...
  - Forbidden dynamic execution: exec, eval, compile, __import__
  - Forbidden C-bridge imports: ctypes, cffi, cython, ...

What this does NOT catch (documented limitations):
  - Obfuscated imports: importlib.import_module('socket')
  - Attribute access after import via an alias
  - C extensions loaded via allowed modules (unlikely in a pure-compute test)

The validator is a first-line pre-filter. It must be combined with Job Object
resource controls, timeouts, and explicit gap documentation.
"""

import ast
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Allowlisted module roots (only these may be imported inside the sandbox)
# ---------------------------------------------------------------------------

SAFE_MODULES: frozenset = frozenset({
    # Test infrastructure
    "unittest", "doctest",
    # The module under test (always added by the runner)
    "solution",

    # Pure arithmetic / numeric
    "math", "cmath", "decimal", "fractions", "random", "statistics",
    "numbers",

    # Date / time  (no filesystem or network side-effects)
    "datetime", "calendar", "time",

    # Data structures
    "collections", "heapq", "bisect", "array",

    # Functional / iteration
    "itertools", "functools", "operator",

    # Text / encoding  (no OS calls)
    "re", "string", "textwrap", "difflib",
    "json", "csv", "struct", "codecs", "unicodedata",

    # Hashing / encoding primitives  (no network, no file I/O)
    "hashlib", "hmac", "base64", "binascii",

    # In-memory I/O only  (StringIO, BytesIO — not file open)
    "io",

    # Type system / OOP utilities
    "abc", "copy", "pprint", "reprlib",
    "dataclasses", "enum", "typing", "types",
    "builtins",

    # Testing support utilities
    "contextlib", "warnings", "traceback", "inspect",
    "weakref", "gc",
})

# ---------------------------------------------------------------------------
# Dangerous built-in call and symbol names (blocked even without import)
# ---------------------------------------------------------------------------

FORBIDDEN_BUILTINS: frozenset = frozenset({
    "exec", "eval", "compile", "__import__",
    "open", "getattr", "setattr", "delattr",
    "vars", "breakpoint", "input", "help",
})

# Dunder attributes permitted on objects (data model methods only)
# Anything starting with '__' not in this set is strictly rejected.
SAFE_DUNDERS: frozenset = frozenset({
    "__init__", "__new__", "__str__", "__repr__", "__name__", "__doc__",
    "__len__", "__getitem__", "__setitem__", "__delitem__", "__iter__",
    "__next__", "__enter__", "__exit__", "__eq__", "__ne__", "__lt__",
    "__le__", "__gt__", "__ge__", "__add__", "__sub__", "__mul__",
    "__truediv__", "__floordiv__", "__mod__", "__pow__", "__hash__",
    "__bool__", "__call__", "__contains__", "__abs__",
})

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    allowed: bool
    violations: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.allowed


# ---------------------------------------------------------------------------
# Validator class
# ---------------------------------------------------------------------------

class CodeValidator:
    """Walks the AST of a Python source string and enforces the allowlist."""

    def __init__(self, safe_modules: frozenset = None):
        self._safe = safe_modules if safe_modules is not None else SAFE_MODULES

    def validate(self, source_code: str, filename: str = "<sandbox>") -> ValidationResult:
        """
        Parse and validate source_code. Returns a ValidationResult.
        If parsing fails, returns a result with a syntax-error violation.
        """
        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError as exc:
            return ValidationResult(
                allowed=False,
                violations=[f"Syntax error in {filename}: {exc}"],
            )

        violations: List[str] = []
        self._walk(tree, violations)
        return ValidationResult(allowed=len(violations) == 0, violations=violations)

    def validate_all(self, *sources: tuple) -> ValidationResult:
        """Validate multiple (source, filename) pairs and merge violations."""
        combined: List[str] = []
        for source, fname in sources:
            r = self.validate(source, fname)
            combined.extend(r.violations)
        return ValidationResult(allowed=len(combined) == 0, violations=combined)

    # ------------------------------------------------------------------
    # Internal AST walker
    # ------------------------------------------------------------------

    def _walk(self, tree: ast.AST, violations: List[str]) -> None:
        for node in ast.walk(tree):
            self._check(node, violations)

    def _check(self, node: ast.AST, violations: List[str]) -> None:

        # --- Import statements ---
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in self._safe:
                    violations.append(
                        f"Forbidden import '{alias.name}' (module not in allowlist)"
                    )

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                if root not in self._safe:
                    violations.append(
                        f"Forbidden 'from {node.module} import ...' (module not in allowlist)"
                    )

        # --- Dangerous built-in calls: exec(), eval(), open(), getattr(), etc. ---
        elif isinstance(node, ast.Call):
            name = None

            if isinstance(node.func, ast.Name):
                name = node.func.id

            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in FORBIDDEN_BUILTINS:
                    name = node.func.attr

            if name and name in FORBIDDEN_BUILTINS:
                violations.append(
                    f"Forbidden call '{name}()' (dynamic execution or unsafe built-in)"
                )

        # --- Attribute access: block dangerous dunders and reflection ---
        elif isinstance(node, ast.Attribute):
            attr = node.attr
            if attr.startswith("__"):
                if attr not in SAFE_DUNDERS:
                    violations.append(
                        f"Forbidden dunder attribute access '.{attr}' (introspection or sandbox bypass)"
                    )
            elif attr in FORBIDDEN_BUILTINS:
                violations.append(
                    f"Forbidden attribute access '.{attr}' (unsafe built-in reference)"
                )

        # --- Name nodes: raw references to forbidden builtins (alias attacks like f = eval) ---
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_BUILTINS and not isinstance(getattr(node, "ctx", None), ast.Store):
                violations.append(
                    f"Forbidden reference to '{node.id}' (alias or uncalled reference)"
                )


# ---------------------------------------------------------------------------
# Module-level convenience function used by sandbox_runner
# ---------------------------------------------------------------------------

_default_validator = CodeValidator()


def validate(source_code: str, filename: str = "<sandbox>") -> ValidationResult:
    """Validate a single source string with the default validator."""
    return _default_validator.validate(source_code, filename)


def validate_pair(
    source_code: str,
    test_code: str,
) -> ValidationResult:
    """Validate both the solution and test code together."""
    return _default_validator.validate_all(
        (source_code, "solution.py"),
        (test_code, "test_solution.py"),
    )


# ---------------------------------------------------------------------------
# Quick self-test  (python code_validator.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("code_validator self-test")
    print("=" * 42)

    # Should block
    bad_cases = [
        ("import socket", "socket import"),
        ("import subprocess", "subprocess import"),
        ("import os", "os import"),
        ("import ctypes", "ctypes import"),
        ("from urllib import request", "urllib from-import"),
        ("exec('print(1)')", "exec call"),
        ("eval('1+1')", "eval call"),
        ("x = __import__('os')", "__import__ call"),
        ("f = eval", "eval alias assignment"),
        ("open('foo.txt')", "open call"),
        ("getattr(x, 'y')", "getattr call"),
        ("x = ().__class__.__subclasses__()", "__subclasses__ traversal"),
        ("x = ().__class__.__bases__", "__bases__ traversal"),
    ]
    for code, label in bad_cases:
        r = validate(code)
        assert not r.allowed, f"Should have blocked: {label}"
        print(f"  [PASS] blocked: {label}")

    # Should allow
    good_cases = [
        ("import math", "math import"),
        ("import re", "re import"),
        ("from collections import defaultdict", "collections from-import"),
        ("import unittest", "unittest import"),
        ("import json", "json import"),
        ("x = 1 + 1", "plain expression"),
    ]
    for code, label in good_cases:
        r = validate(code)
        assert r.allowed, f"Should have allowed: {label} — violations: {r.violations}"
        print(f"  [PASS] allowed: {label}")

    print("=" * 42)
    print("All code_validator self-tests passed.")
