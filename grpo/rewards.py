#!/usr/bin/env python3
"""Reward functions for GRPO training of the Rego expert model.

Five stacked reward signals scored by OPA / Regal evaluation:
  1. reward_format        — structural compliance (<think>, package, deny pattern)
  2. reward_opa_parse     — syntactic validity via `opa check`
  3. reward_opa_test      — functional correctness via `opa test`
  4. reward_schema_paths  — schema grounding (valid input.* references)
  5. reward_regal_lint    — idiomatic Rego style via `regal lint`

Total signal range: +15.0 (perfect) to -17.0 (worst).

Each function receives (completions, **kwargs) and returns a list of float
scores, one per completion.  Extra dataset columns (test_code, package_name,
etc.) are forwarded via **kwargs by the GRPOTrainer.

Prerequisites on PATH:
  - opa   (brew install opa)
  - regal (brew install styrainc/packages/regal)  — optional, gracefully degrades
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_PACKAGE_DIR = Path(__file__).resolve().parent
_SFT_ROOT = _PACKAGE_DIR.parent / "sft"
_FIELD_CATALOG_PATH = _SFT_ROOT / "phase0_catalog" / "output" / "field_catalog.jsonl"


# ===========================================================================
# Schema path validation set (for reward_schema_paths)
# ===========================================================================

def _load_valid_input_prefixes() -> set[str]:
    """Build a set of valid ``input.*`` path prefixes from the field catalog.

    Strips ``[*]`` from catalog paths and converts to Rego ``input.`` style.
    e.g. ``.predicate.materials[*].digest.sha256`` → ``input.predicate.materials``
    Multiple depth levels are kept so partial references also validate.
    """
    prefixes: set[str] = set()
    if not _FIELD_CATALOG_PATH.exists():
        return prefixes

    with open(_FIELD_CATALOG_PATH) as f:
        for line in f:
            rec = json.loads(line.strip())
            path = rec["path"]
            clean = path.lstrip(".").replace("[*]", "")
            parts = clean.split(".")
            for depth in range(1, len(parts) + 1):
                prefixes.add("input." + ".".join(parts[:depth]))

    return prefixes


_VALID_INPUT_PREFIXES: set[str] = set()  # populated lazily at first use


def _get_valid_prefixes() -> set[str]:
    global _VALID_INPUT_PREFIXES
    if not _VALID_INPUT_PREFIXES:
        _VALID_INPUT_PREFIXES = _load_valid_input_prefixes()
    return _VALID_INPUT_PREFIXES


# ===========================================================================
# Rego code extraction helpers
# ===========================================================================

def _extract_rego_code(text: str) -> Optional[str]:
    """Extract Rego code from a model completion (after ``</think>`` or raw).

    Returns ``None`` if nothing looks like Rego code.
    """
    # Try after </think> tag first
    m = re.search(r"</think>\s*\n*(.*)", text, re.DOTALL)
    if m:
        code = m.group(1).strip()
        if code:
            return code

    # Try finding a package declaration
    m = re.search(r"^(package\s+\w+.*)", text, re.DOTALL | re.MULTILINE)
    if m:
        return m.group(1).strip()

    # Return the raw text as a last resort
    return text.strip() if text.strip() else None


# ===========================================================================
# 1. reward_format  (max +5.0 / min -7.0)
# ===========================================================================

def reward_format(completions, **kwargs) -> list[float]:
    """Reward structural compliance with Rego deny-rule conventions.

    Checks for:
      - ``<think>`` / ``</think>`` tags  (+0.5 each, -0.5 if missing)  — checked on full response
      - ``package`` declaration           (+1.0, -2.0 if missing)      — checked on CODE only
      - ``import rego.v1``                (+0.5, -1.0 if missing)      — checked on CODE only
      - ``deny contains msg if``          (+2.0, -3.0 if missing)      — checked on CODE only
      - ``sprintf``                       (+0.5, no penalty if missing) — checked on CODE only

    Max: +5.0, Min: -7.0.

    IMPORTANT: Code-structure checks use the extracted code (after ``</think>``),
    NOT the full response. This prevents the model from gaming the reward by
    mentioning patterns in ``<think>`` traces without using them in the code.
    """
    scores = []
    for completion in completions:
        response = completion[0]["content"]
        code = _extract_rego_code(response) or ""
        score = 0.0

        # Reasoning traces — check full response (these ARE about the response structure)
        score += 0.5 if "<think>" in response or response.startswith("") else -0.5
        score += 0.5 if "</think>" in response else -0.5

        # Critical structural elements — check CODE only (prevents think-tag gaming)
        score += 1.0 if re.search(r"^package\s+\w+", code, re.M) else -2.0
        score += 0.5 if "import rego.v1" in code else -1.0
        score += 2.0 if "deny contains msg if" in code else -3.0

        # Nice-to-have — check CODE only
        score += 0.5 if "sprintf" in code else 0.0

        scores.append(score)
    return scores


# ===========================================================================
# 2. reward_opa_parse  (max +2.0 / min -2.0)
# ===========================================================================

def reward_opa_parse(completions, **kwargs) -> list[float]:
    """Reward syntactically valid Rego via ``opa check``.

    +2.0 if OPA parses the code successfully, -2.0 otherwise.
    """
    scores = []
    for completion in completions:
        response = completion[0]["content"]
        code = _extract_rego_code(response)
        if code is None:
            scores.append(-2.0)
            continue

        try:
            with tempfile.TemporaryDirectory() as td:
                rule_path = os.path.join(td, "rule.rego")
                with open(rule_path, "w") as f:
                    f.write(code)

                result = subprocess.run(
                    ["opa", "check", rule_path],
                    capture_output=True, text=True, timeout=5,
                )
                scores.append(2.0 if result.returncode == 0 else -2.0)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            scores.append(-2.0)

    return scores


# ===========================================================================
# 3. reward_opa_test  (max +5.0 / min -4.0)
# ===========================================================================

def reward_opa_test(completions, test_code, package_name, **kwargs) -> list[float]:
    """Reward functional correctness via ``opa test``.

    Writes the generated rule + ground-truth test to a temp directory,
    runs ``opa test``, and scores:

    ======  ======================
    +5.0    all tests pass
    +2.0    some tests pass (partial)
    -3.0    all tests fail
    -4.0    code doesn't parse at all
    ======  ======================
    """
    scores = []
    for completion, tc, pkg in zip(completions, test_code, package_name):
        response = completion[0]["content"]
        code = _extract_rego_code(response)
        if code is None:
            scores.append(-4.0)
            continue

        # Fix package name if the model used a different one
        code_fixed = re.sub(
            r"^package\s+\w+",
            f"package {pkg}",
            code,
            count=1,
            flags=re.MULTILINE,
        )

        try:
            with tempfile.TemporaryDirectory() as td:
                rule_path = os.path.join(td, f"{pkg}.rego")
                test_path = os.path.join(td, f"{pkg}_test.rego")

                with open(rule_path, "w") as f:
                    f.write(code_fixed)
                with open(test_path, "w") as f:
                    f.write(tc)

                result = subprocess.run(
                    ["opa", "test", td, "-v"],
                    capture_output=True, text=True, timeout=10,
                )

                if result.returncode == 0:
                    scores.append(5.0)
                else:
                    output = result.stdout + result.stderr
                    passes = output.count("PASS")
                    fails = output.count("FAIL")
                    if passes > 0 and fails > 0:
                        scores.append(2.0)
                    elif passes > 0 and fails == 0:
                        scores.append(2.0)
                    else:
                        scores.append(-3.0)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            scores.append(-4.0)

    return scores


# ===========================================================================
# 4. reward_regal_lint  (max +2.0 / min -2.0)
# ===========================================================================

def reward_regal_lint(completions, **kwargs) -> list[float]:
    """Reward idiomatic, lint-clean Rego via ``regal lint``.

    Runs Regal (the Rego linter) on each completion and scores:

    ========  ===================================================
    +2.0      no violations
    partial   ``2.0 - 0.5 * num_violations`` (clamped to -2.0)
    -2.0      code doesn't parse or regal unavailable
    ========  ===================================================

    Two rules are disabled because they always fire in temp directories:

    - **opa-fmt**: trivial whitespace differences
    - **directory-package-mismatch**: temp path ≠ package name
    """
    regal_bin = shutil.which("regal")
    if not regal_bin:
        return [0.0] * len(completions)

    scores = []
    for completion in completions:
        response = completion[0]["content"]
        code = _extract_rego_code(response)
        if code is None:
            scores.append(-2.0)
            continue

        try:
            with tempfile.TemporaryDirectory() as td:
                rule_path = os.path.join(td, "rule.rego")
                with open(rule_path, "w") as f:
                    f.write(code)

                result = subprocess.run(
                    [
                        regal_bin, "lint", "--format", "json",
                        "-d", "opa-fmt",
                        "-d", "directory-package-mismatch",
                        rule_path,
                    ],
                    capture_output=True, text=True, timeout=10,
                )

                if result.returncode == 0:
                    scores.append(2.0)
                elif result.returncode == 3:
                    try:
                        data = json.loads(result.stdout)
                        num_violations = data.get("summary", {}).get("num_violations", 1)
                        score = max(2.0 - 0.5 * num_violations, -2.0)
                        scores.append(score)
                    except (json.JSONDecodeError, KeyError):
                        scores.append(-1.0)
                else:
                    scores.append(-2.0)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            scores.append(-2.0)

    return scores


# ===========================================================================
# 5. reward_schema_paths  (max +1.0 / min -1.0 base, can go lower)
# ===========================================================================

def reward_schema_paths(completions, **kwargs) -> list[float]:
    """Reward correct schema path references in generated Rego code.

    Extracts all ``input.*`` references and validates against the field catalog.

    ======  ===================================
    +1.0    all references are valid
    -0.5    per invalid reference
    -1.0    no ``input`` references found at all
    ======  ===================================
    """
    valid_prefixes = _get_valid_prefixes()
    if not valid_prefixes:
        return [0.0] * len(completions)

    scores = []
    for completion in completions:
        response = completion[0]["content"]
        code = _extract_rego_code(response)
        if code is None:
            scores.append(-1.0)
            continue

        refs = re.findall(r"input(?:\.\w+)+", code)
        if not refs:
            scores.append(-1.0)
            continue

        invalid_count = 0
        for ref in refs:
            if ref not in valid_prefixes:
                parts = ref.split(".")
                found = False
                for depth in range(len(parts), 1, -1):
                    candidate = ".".join(parts[:depth])
                    if candidate in valid_prefixes:
                        found = True
                        break
                if not found:
                    invalid_count += 1

        if invalid_count == 0:
            scores.append(1.0)
        else:
            scores.append(-0.5 * invalid_count)

    return scores


# ===========================================================================
# Convenience list of all reward functions (for the trainer)
# ===========================================================================

ALL_REWARD_FUNCS = [
    reward_format,
    reward_opa_parse,
    reward_opa_test,
    reward_schema_paths,
    reward_regal_lint,
]
