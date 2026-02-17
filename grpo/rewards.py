#!/usr/bin/env python3
"""Reward functions for GRPO training of the Rego expert model.

Five stacked reward signals scored by OPA / Regal evaluation:
  1. reward_format        — structural compliance (<think>, package, deny pattern)
  2. reward_opa_parse     — syntactic validity via `opa check`
  3. reward_opa_test      — functional correctness via `opa test`
  4. reward_schema_paths  — schema grounding (valid input.* references)
  5. reward_regal_lint    — idiomatic Rego style via `regal lint`

Total signal range: +15.0 (perfect) to -17.0 (worst).

─── How these scores affect model weights ─────────────────────────────

  GRPOTrainer calls ALL 5 functions on each completion and **sums** the
  scores to get one scalar reward per completion.

  Example for 4 completions of the same prompt:

    Completion A:  format=+5  parse=+2  test=+5  schema=+1  lint=+2  → total = +15
    Completion B:  format=+5  parse=+2  test=-3  schema=+1  lint=+2  → total = +7
    Completion C:  format=+5  parse=-2  test=-4  schema=-1  lint=-2  → total = -4
    Completion D:  format=-3  parse=-2  test=-4  schema=-1  lint=-2  → total = -12

    mean = 1.5,  std = 10.2

    Advantage A = (15 - 1.5) / 10.2 = +1.32   → ↑ make these tokens MORE likely
    Advantage B = (7 - 1.5) / 10.2  = +0.54   → ↑ slightly more likely
    Advantage C = (-4 - 1.5) / 10.2 = -0.54   → ↓ slightly less likely
    Advantage D = (-12 - 1.5) / 10.2= -1.32   → ↓ make these tokens LESS likely

  The advantage multiplies the log-probability of each token in the
  completion during the policy-gradient update.  So:
    - Tokens from completion A get a strong positive push
    - Tokens from completion D get a strong negative push
    - The optimizer (AdamW) adjusts LoRA weights accordingly

  Over many steps, the model learns to produce outputs that score high on
  ALL functions simultaneously — correct structure, valid syntax, passing
  tests, valid schema references, and clean lint.

────────────────────────────────────────────────────────────────────────

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


def _extract_package_name(code: str) -> Optional[str]:
    """Extract package name from Rego code."""
    m = re.search(r"^package\s+([A-Za-z_]\w*)\s*$", code, re.MULTILINE)
    return m.group(1) if m else None


# ===========================================================================
# 1. reward_format  (max +5.0 / min -7.0)
# ===========================================================================
# PURPOSE: Ensures the model's output has the right SHAPE before we even
# check if it's valid Rego.  This is the cheapest reward to compute (pure
# regex, no subprocess) and gives the model fast signal about basic
# structural requirements.  Without this, the model might produce valid
# Rego that doesn't follow the deny-rule pattern we need.
# ===========================================================================

def reward_format(completions, task_type=None, **kwargs) -> list[float]:
    """Reward structural compliance with Rego deny-rule conventions.

    Checks for:
      - ``<think>`` / ``</think>`` tags  (+0.5 each, -0.5 if missing)  — checked on full response
      - ``package`` declaration           (+1.0, -2.0 if missing)      — checked on CODE only
      - ``import rego.v1``                (+0.5, -1.0 if missing)      — checked on CODE only
      - ``deny contains msg if``          (+2.0, -3.0 if missing)      — checked on CODE only
      - ``sprintf``                       (+0.5, no penalty if missing) — checked on CODE only
      - think-length efficiency           (+0.5 concise, -1.0/-1.5 excessive) — ratio of think to code

    Max: +5.5, Min: -8.5.

    IMPORTANT: Code-structure checks use the extracted code (after ``</think>``),
    NOT the full response. This prevents the model from gaming the reward by
    mentioning patterns in ``<think>`` traces without using them in the code.
    """
    scores = []
    for i, completion in enumerate(completions):
        response = completion[0]["content"]
        code = _extract_rego_code(response) or ""
        tt = task_type[i] if isinstance(task_type, list) and i < len(task_type) else "deny_rule"
        score = 0.0

        # Reasoning traces — check full response (these ARE about the response structure)
        score += 0.5 if "<think>" in response or response.startswith("") else -0.5
        score += 0.5 if "</think>" in response else -0.5

        is_deny_like = "deny contains msg if" in code

        # Critical structural elements — check CODE only (prevents think-tag gaming)
        score += 1.0 if re.search(r"^package\s+\w+", code, re.M) else -2.0
        score += 0.5 if "import rego.v1" in code else -1.0
        if tt == "helper_method":
            # Helper tasks shouldn't be forced into deny-pattern outputs.
            helper_like = (
                not is_deny_like
                and (
                    bool(re.search(r"\b[a-zA-Z_]\w*\s*\(", code))
                    or bool(re.search(r"\b[a-zA-Z_]\w*\s*:=", code))
                    or bool(re.search(r"\b[a-zA-Z_]\w*\s+if\s+\{", code))
                )
            )
            score += 2.0 if helper_like else -3.0
            # Hard penalty for off-task deny outputs on helper prompts.
            if is_deny_like:
                score -= 6.0
        else:
            score += 2.0 if is_deny_like else -3.0

        # Nice-to-have — check CODE only
        if tt == "helper_method":
            score += 0.5 if " := " in code else 0.0
        else:
            score += 0.5 if "sprintf" in code else 0.0

        # Think-length efficiency: reward concise reasoning that still
        # produces substantial code.  Penalise completions where <think>
        # dominates and code is tiny (often a sign of truncation or
        # rambling reasoning that never gets to the answer).
        think_text = ""
        tm = re.search(r"<think>(.*?)</think>", response, re.DOTALL)
        if tm:
            think_text = tm.group(1)
        think_len = len(think_text)
        code_len = len(code) if code else 0

        if code_len > 50 and think_len > 0:
            ratio = think_len / code_len
            if ratio <= 2.0:
                # Concise reasoning relative to code output — small bonus
                score += 0.5
            elif ratio > 5.0:
                # Excessive thinking with little code — penalty
                score -= 1.0
        elif think_len > 200 and code_len <= 50:
            # Long think but essentially no code (likely truncated)
            score -= 1.5

        scores.append(score)
    return scores


# ===========================================================================
# 2. reward_opa_parse  (max +2.0 / min -2.0)
# ===========================================================================
# PURPOSE: Binary syntax check — can OPA even parse this code?  This is a
# gate: if opa_parse fails, opa_test will also fail, but having a separate
# signal lets the model learn "fix your syntax first" independently from
# "make the tests pass".  The separate score means a completion with valid
# syntax but failing tests (+2 parse, -3 test = -1) is ranked higher than
# one that doesn't parse at all (-2 parse, -4 test = -6), teaching the
# model that parseable-but-wrong is closer to the goal than gibberish.
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
# PURPOSE: The STRONGEST signal — does the generated rule actually work?
# This is worth the most points (+5) because it's the ultimate goal: a
# rule that passes all tests is functionally correct.  The test_code and
# package_name come from the dataset (forwarded by GRPOTrainer as kwargs).
#
# This function pairs the model's generated rule with the ground-truth
# test file, writes both to a temp directory, and runs `opa test`.
# The ground-truth test was validated in Phase 3 against the reference
# rule, so if the model's rule passes the same tests, it's equivalent.
# ===========================================================================

def reward_opa_test(completions, test_code, package_name, task_type=None, **kwargs) -> list[float]:
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
    for i, (completion, tc, pkg) in enumerate(zip(completions, test_code, package_name)):
        response = completion[0]["content"]
        code = _extract_rego_code(response)
        if code is None:
            scores.append(-4.0)
            continue
        tt = task_type[i] if isinstance(task_type, list) and i < len(task_type) else "deny_rule"

        # Enforce task-type intent: helper tasks should not output deny rules.
        if tt == "helper_method" and "deny contains msg if" in code:
            scores.append(-4.0)
            continue

        # Enforce package alignment to prevent reward gaming with unrelated code.
        declared_pkg = _extract_package_name(code)
        if declared_pkg is not None and declared_pkg != pkg:
            scores.append(-4.0)
            continue

        try:
            with tempfile.TemporaryDirectory() as td:
                rule_path = os.path.join(td, f"{pkg}.rego")
                test_path = os.path.join(td, f"{pkg}_test.rego")

                with open(rule_path, "w") as f:
                    f.write(code)
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
# PURPOSE: Encourages idiomatic Rego style.  A rule can pass all tests but
# still use non-idiomatic patterns (e.g. redundant iterations, non-standard
# variable names).  This reward nudges the model toward clean code that a
# human Rego developer would write.  Worth fewer points than opa_test
# because correctness matters more than style.
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
                        "-d", "external-reference",
                        "-d", "leaked-internal-reference",
                        "-d", "rule-length",
                        "-d", "file-length",
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
# PURPOSE: Prevents hallucinated field references.  The model might write
# `input.predicate.buildConfig.taskz` (misspelled) — syntactically valid
# Rego, but it would never match real attestation data.  This reward checks
# every `input.*` path against the field catalog from Phase 0.  Worth fewer
# points because it's a subtle error, but the penalty stacks per invalid
# reference so a completely hallucinated rule gets heavily penalised.
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
# GRPOTrainer iterates this list, calls each function on every completion,
# and sums the returned scores to get one total reward per completion.
# The ORDER doesn't matter — they're summed, not chained.
# ===========================================================================

ALL_REWARD_FUNCS = [
    reward_format,       # max +5.5 / min -8.5  — structural shape + think efficiency
    reward_opa_parse,    # max +2.0 / min -2.0  — syntactic validity
    reward_opa_test,     # max +5.0 / min -4.0  — functional correctness (strongest signal)
    reward_schema_paths, # max +1.0 / min -∞    — schema grounding
    reward_regal_lint,   # max +2.0 / min -2.0  — idiomatic style
    # ─────────────────────────────────────────
    # Perfect score: +15.5    Worst: -18.5 (approx)
]
