#!/usr/bin/env python3
"""Build the GRPO prompt dataset from Phase 1 instructions + Phase 3 rules/tests.

Reads the SFT-pipeline artefacts (instructions, rules, tests, ambiguous prompts)
and assembles a JSONL dataset where each record has:

  - prompt:        list of messages [system, user]  (what the model sees)
  - test_code:     ground-truth test for reward_opa_test
  - package_name:  Rego package name for reward_opa_test
  - rule_code:     ground-truth rule (reference only, not shown to the model)
  - task_id:       identifier linking back to the SFT pipeline

Prompt variants:
  - canonical / terse / vague / poor_grammar — instruction rewording
  - ambiguous — schema-ambiguous prompts (from SFT Phase 4)
  - error_fix_* — corrupted ground-truth rules with real OPA/Regal error output;
    teaches the model to diagnose and fix broken Rego code

Output: grpo/output/grpo_prompts.jsonl

Prerequisites:
  - OPA binary on PATH (required for error-fix variant generation)
  - Regal binary on PATH (optional, enriches error output)

Usage:
    cd /path/to/aiagent
    python -m grpo.build_dataset

    # Or directly:
    python grpo/build_dataset.py

    # Inspect:
    wc -l grpo/output/grpo_prompts.jsonl
    head -1 grpo/output/grpo_prompts.jsonl | python -m json.tool
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
SFT_ROOT = PROJECT_ROOT / "sft"
INSTRUCTIONS_PATH = SFT_ROOT / "phase1_instructions" / "output" / "instructions.jsonl"
PHASE3_TASKS = SFT_ROOT / "phase3_rules" / "output" / "tasks"
OUTPUT_DIR = SCRIPT_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "grpo_prompts.jsonl"

# ---------------------------------------------------------------------------
# Ensure the SFT package is importable (for AMBIGUOUS_PROMPTS)
# ---------------------------------------------------------------------------
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ===========================================================================
# System prompt — identical to what the model sees during SFT and GRPO
# ===========================================================================

SYSTEM_PROMPT = """\
You are an expert in the Rego policy language (Open Policy Agent). \
You specialize in writing deny rules for verifying SLSA provenance attestations.

Conventions you always follow:
- Use `import rego.v1` (Rego v1 syntax).
- Use `deny contains msg if { ... }` (partial set rules). Rules fire when something is WRONG.
- Use `some x in collection` to iterate (Rego v1 iteration, not indexing).
- Use `sprintf` to produce human-readable deny messages.
- The attestation document is accessed via `input`.
- Tests use `count(<pkg>.deny) == 0` for positive cases and `count(<pkg>.deny) > 0` for negative cases.

SLSA attestation schema (field → JSON path):
- _type: ._type
- predicateType: .predicateType
- subject[*].name: .subject[*].name
- subject[*].digest.sha256: .subject[*].digest.sha256
- buildType: .predicate.buildType
- builder.id: .predicate.builder.id
- materials: .predicate.materials (array)
- materials[*].uri: .predicate.materials[*].uri
- materials[*].digest.sha256: .predicate.materials[*].digest.sha256
- materials[*].digest.sha1: .predicate.materials[*].digest.sha1
- invocation.parameters.git-url: .predicate.invocation.parameters.git-url
- invocation.parameters.revision: .predicate.invocation.parameters.revision
- invocation.parameters.output-image: .predicate.invocation.parameters.output-image
- invocation.parameters.hermetic: .predicate.invocation.parameters.hermetic
- invocation.parameters.rebuild: .predicate.invocation.parameters.rebuild
- invocation.parameters.skip-checks: .predicate.invocation.parameters.skip-checks
- metadata.buildStartedOn: .predicate.metadata.buildStartedOn
- metadata.buildFinishedOn: .predicate.metadata.buildFinishedOn
- metadata.reproducible: .predicate.metadata.reproducible
- tasks[*].name: .predicate.buildConfig.tasks[*].name
- tasks[*].status: .predicate.buildConfig.tasks[*].status
- tasks[*].startedOn: .predicate.buildConfig.tasks[*].startedOn
- tasks[*].finishedOn: .predicate.buildConfig.tasks[*].finishedOn
- tasks[*].serviceAccountName: .predicate.buildConfig.tasks[*].serviceAccountName
- tasks[*].ref.resolver: .predicate.buildConfig.tasks[*].ref.resolver
- tasks[*].ref.params[*].name: .predicate.buildConfig.tasks[*].ref.params[*].name
- tasks[*].ref.params[*].value: .predicate.buildConfig.tasks[*].ref.params[*].value
- tasks[*].steps: .predicate.buildConfig.tasks[*].steps (array)
- tasks[*].steps[*].entryPoint: .predicate.buildConfig.tasks[*].steps[*].entryPoint
- tasks[*].steps[*].environment.container: .predicate.buildConfig.tasks[*].steps[*].environment.container
- tasks[*].steps[*].environment.image: .predicate.buildConfig.tasks[*].steps[*].environment.image
- tasks[*].results[*].name: .predicate.buildConfig.tasks[*].results[*].name
- tasks[*].results[*].type: .predicate.buildConfig.tasks[*].results[*].type
- tasks[*].results[*].value: .predicate.buildConfig.tasks[*].results[*].value
- tasks[*].invocation.parameters.HERMETIC: .predicate.buildConfig.tasks[*].invocation.parameters.HERMETIC
- tasks[*].invocation.parameters.TLSVERIFY: .predicate.buildConfig.tasks[*].invocation.parameters.TLSVERIFY
- tasks[*].invocation.parameters.COMMIT_SHA: .predicate.buildConfig.tasks[*].invocation.parameters.COMMIT_SHA
- tasks[*].invocation.parameters.DOCKERFILE: .predicate.buildConfig.tasks[*].invocation.parameters.DOCKERFILE
- tasks[*].invocation.parameters.IMAGE: .predicate.buildConfig.tasks[*].invocation.parameters.IMAGE\
"""


# ===========================================================================
# Loaders
# ===========================================================================

def _load_instructions() -> list[dict]:
    records = []
    with open(INSTRUCTIONS_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _load_phase3_result(task_id: str) -> dict | None:
    result_path = PHASE3_TASKS / task_id / "result.json"
    if not result_path.exists():
        return None
    with open(result_path) as f:
        result = json.load(f)
    if result.get("status") != "pass":
        return None
    return result


# ===========================================================================
# Variant generators
# ===========================================================================

def _make_variant_instructions(canonical: str) -> list[str]:
    """Generate diverse prompt wordings for a single task."""
    variants = [canonical]

    # Terse
    m = re.search(
        r"(?:Write a Rego deny rule that rejects the attestation if |"
        r"Write a Rego deny rule that rejects the attestation if the build was not )",
        canonical,
    )
    if m:
        tail = canonical[m.end():]
        tail = re.sub(r"\s*\([^)]+\)\s*$", "", tail).strip().rstrip(".")
        variants.append(f"deny if {tail}")

    # Vague
    m2 = re.search(r"\(([^)]+)\)\s*$", canonical)
    note = m2.group(1) if m2 else None
    m3 = re.search(
        r"rejects the attestation if (.+?)(?:\.\s*\(|\.?\s*$)",
        canonical,
    )
    if note:
        variants.append(f"Write a Rego rule to verify the {note.lower()}.")
    elif m3:
        simplified = m3.group(1).strip().rstrip(".")
        simplified = simplified.replace("`.predicate.", "the ").replace("`", "")
        variants.append(f"Make a deny rule checking {simplified}.")

    # Poor grammar
    text = canonical
    for old, new in [
        ("Write a Rego deny rule that rejects the attestation if",
         "write rego deny rule that reject attestation if"),
        ("is not", "isnt"),
        ("does not", "dont"),
        ("is missing", "is miss"),
    ]:
        text = text.replace(old, new, 1)
    if text != canonical:
        variants.append(text)

    return variants


# ===========================================================================
# Code corruption functions (for error-fix prompts)
# ===========================================================================
# Each returns (corrupted_code, description) or (original, None) if N/A.

def _corrupt_old_deny_no_import(code: str) -> tuple[str, str | None]:
    """Remove ``import rego.v1`` and revert to old-style ``deny[msg] {``.

    Produces both OPA parse errors (``contains``/``if`` required) and Regal
    violations (``use-contains``, ``use-if``, ``use-rego-v1``).
    """
    new = re.sub(r"import rego\.v1\n?", "", code)
    new = new.replace("deny contains msg if {", "deny[msg] {")
    if new == code:
        return code, None
    return new, "removed `import rego.v1` and used old-style `deny[msg]`"


def _corrupt_wrong_schema_path(code: str) -> tuple[str, str | None]:
    """Replace ``input.predicate.X`` with ``input.X`` (wrong path depth).

    OPA and Regal won't catch this — it's a logic error that causes test
    failures. Teaches the model to reason about schema paths.
    """
    new = code.replace("input.predicate.", "input.")
    if new == code:
        return code, None
    return new, "used wrong schema paths (`input.X` instead of `input.predicate.X`)"


def _corrupt_missing_some(code: str) -> tuple[str, str | None]:
    """Remove the ``some`` keyword from iteration.

    Produces ``rego_unsafe_var_error`` from OPA.
    """
    new = re.sub(r"\bsome\s+(\w+)\s+in\s+", r"\1 in ", code)
    if new == code:
        return code, None
    return new, "removed `some` keyword from iteration"


def _corrupt_missing_brace(code: str) -> tuple[str, str | None]:
    """Remove the final closing ``}`` from the rule.

    Produces ``rego_parse_error: unexpected eof token`` from OPA.
    """
    # Find the last closing brace
    idx = code.rfind("}")
    if idx == -1:
        return code, None
    new = code[:idx].rstrip() + "\n"
    return new, "removed closing `}` from the rule"


def _corrupt_old_deny_keep_import(code: str) -> tuple[str, str | None]:
    """Keep ``import rego.v1`` but use old-style ``deny[msg] {``.

    Produces OPA parse errors because rego.v1 strictly requires ``contains``
    and ``if`` keywords.
    """
    new = code.replace("deny contains msg if {", "deny[msg] {")
    if new == code:
        return code, None
    return new, "used old-style `deny[msg]` with `import rego.v1`"


# Corruption combos to apply per task.  Each is a list of (func, label_suffix).
# Not all will apply to every rule — we skip when the corruption is a no-op.
_CORRUPTION_SETS = [
    # Style + parse errors (most common beginner mistake)
    [(_corrupt_old_deny_no_import, "error_fix_style")],
    # Logic error (wrong schema paths — requires reasoning through test failures)
    [(_corrupt_wrong_schema_path, "error_fix_logic")],
    # Syntax errors (missing some, missing brace)
    [(_corrupt_missing_some, "error_fix_unsafe_var")],
    [(_corrupt_missing_brace, "error_fix_syntax")],
    # Parse error with import present
    [(_corrupt_old_deny_keep_import, "error_fix_parse")],
]


# ===========================================================================
# Error message capture (opa check, regal lint, opa test)
# ===========================================================================

def _get_error_output(
    broken_code: str,
    test_code: str | None = None,
    pkg: str | None = None,
) -> str:
    """Run ``opa check``, ``regal lint``, and optionally ``opa test`` on
    broken code.  Return a human-readable error report string.
    """
    sections: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        rule_file = os.path.join(td, "rule.rego")
        with open(rule_file, "w") as f:
            f.write(broken_code)

        # ── opa check ────────────────────────────────────────────────
        opa = subprocess.run(
            ["opa", "check", rule_file],
            capture_output=True, text=True, timeout=5,
        )
        opa_ok = opa.returncode == 0
        if not opa_ok:
            err = (opa.stderr or opa.stdout).strip()
            # Strip temp-dir paths for cleanliness
            err = err.replace(rule_file, "rule.rego")
            sections.append(f"`opa check` errors:\n{err}")

        # ── regal lint (only meaningful if OPA parsed the code) ──────
        if opa_ok:
            regal_bin = shutil.which("regal")
            if regal_bin:
                regal = subprocess.run(
                    [
                        regal_bin, "lint", "--format", "json",
                        "-d", "opa-fmt",
                        "-d", "directory-package-mismatch",
                        rule_file,
                    ],
                    capture_output=True, text=True, timeout=10,
                )
                if regal.returncode == 3:
                    try:
                        data = json.loads(regal.stdout)
                        violations = data.get("violations", [])
                        if violations:
                            lines = ["`regal lint` violations:"]
                            for v in violations:
                                row = v.get("location", {}).get("row", "?")
                                lines.append(
                                    f"- {v['title']}: {v['description']} (line {row})"
                                )
                            sections.append("\n".join(lines))
                    except (json.JSONDecodeError, KeyError):
                        pass

        # ── opa test (catches logic errors that pass static analysis) ─
        if opa_ok and test_code and pkg:
            # Write test file alongside the rule
            test_file = os.path.join(td, f"{pkg}_test.rego")
            # Rename the rule file to match the package name so OPA resolves it
            pkg_rule_file = os.path.join(td, f"{pkg}.rego")
            os.rename(rule_file, pkg_rule_file)
            with open(test_file, "w") as f:
                f.write(test_code)

            opatest = subprocess.run(
                ["opa", "test", td, "-v"],
                capture_output=True, text=True, timeout=10,
            )
            if opatest.returncode != 0:
                output = (opatest.stdout or "").strip()
                # Extract FAIL lines + summary
                fail_lines = [
                    l for l in output.split("\n")
                    if "FAIL" in l or "PASS:" in l or "FAIL:" in l
                ]
                if fail_lines:
                    sections.append("`opa test` failures:\n" + "\n".join(fail_lines))

    if not sections:
        return "No errors detected by static analysis."
    return "\n\n".join(sections)


def _format_error_fix_prompt(broken_code: str, error_output: str) -> str:
    """Build the user-facing prompt for an error-fix task."""
    return (
        "The following Rego deny rule has errors. "
        "Analyze the errors and produce a corrected version.\n\n"
        f"Rule:\n```\n{broken_code.strip()}\n```\n\n"
        f"{error_output}\n\n"
        "Write the corrected rule."
    )


def _build_error_fix_records(instructions: list[dict]) -> list[dict]:
    """Generate error-fix prompts by corrupting ground-truth rules and
    capturing real ``opa``/``regal`` error output.

    Requires ``opa`` on PATH; ``regal`` is optional (gracefully skipped).
    """
    if not shutil.which("opa"):
        print("  WARNING: `opa` not found — skipping error-fix variants.")
        return []

    records: list[dict] = []
    skipped = 0

    for instr_rec in instructions:
        task_id = instr_rec["id"]
        pkg = instr_rec["package_name"]

        result = _load_phase3_result(task_id)
        if result is None:
            continue

        rule_path = PHASE3_TASKS / task_id / f"{pkg}.rego"
        test_path = PHASE3_TASKS / task_id / f"{pkg}_test.rego"
        if not rule_path.exists() or not test_path.exists():
            continue

        rule_code = rule_path.read_text()
        test_code = test_path.read_text()

        for combo in _CORRUPTION_SETS:
            corrupt_fn, variant_label = combo[0]
            broken, description = corrupt_fn(rule_code)

            if description is None:
                # Corruption didn't apply to this rule
                skipped += 1
                continue

            # Get real error messages from the tools
            error_output = _get_error_output(broken, test_code, pkg)

            prompt_text = _format_error_fix_prompt(broken, error_output)

            records.append({
                "prompt": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt_text},
                ],
                "test_code": test_code,
                "package_name": pkg,
                "rule_code": rule_code,
                "task_id": task_id,
                "variant": variant_label,
            })

    if skipped:
        print(f"  (skipped {skipped} corruptions that didn't apply)")

    return records


# ===========================================================================
# Main builder
# ===========================================================================

def build_dataset() -> list[dict]:
    """Build the full GRPO prompt dataset.

    Returns a list of dicts, each with: prompt, test_code, package_name,
    rule_code, task_id, variant.
    """
    instructions = _load_instructions()
    records: list[dict] = []

    # ── Core variants (canonical, terse, vague, poor-grammar) ────────────
    for instr_rec in instructions:
        task_id = instr_rec["id"]
        pkg = instr_rec["package_name"]
        canonical = instr_rec["instruction"]

        result = _load_phase3_result(task_id)
        if result is None:
            continue

        rule_path = PHASE3_TASKS / task_id / f"{pkg}.rego"
        test_path = PHASE3_TASKS / task_id / f"{pkg}_test.rego"
        if not rule_path.exists() or not test_path.exists():
            continue

        rule_code = rule_path.read_text()
        test_code = test_path.read_text()

        variant_labels = ["canonical", "terse", "vague", "poor_grammar"]
        for i, variant_instr in enumerate(_make_variant_instructions(canonical)):
            label = variant_labels[i] if i < len(variant_labels) else f"variant_{i}"
            records.append({
                "prompt": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": variant_instr},
                ],
                "test_code": test_code,
                "package_name": pkg,
                "rule_code": rule_code,
                "task_id": task_id,
                "variant": label,
            })

    # ── Ambiguous prompts (highest value for GRPO reasoning) ─────────────
    from sft.phase4_dataset.assemble_dataset import AMBIGUOUS_PROMPTS

    for task_id, prompt_list in AMBIGUOUS_PROMPTS.items():
        result = _load_phase3_result(task_id)
        if result is None:
            continue

        instr_rec = next(
            (r for r in instructions if r["id"] == task_id), None
        )
        if instr_rec is None:
            continue

        pkg = instr_rec["package_name"]
        rule_path = PHASE3_TASKS / task_id / f"{pkg}.rego"
        test_path = PHASE3_TASKS / task_id / f"{pkg}_test.rego"
        if not rule_path.exists() or not test_path.exists():
            continue

        rule_code = rule_path.read_text()
        test_code = test_path.read_text()

        for ambig_prompt, _disambig_note in prompt_list:
            records.append({
                "prompt": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": ambig_prompt},
                ],
                "test_code": test_code,
                "package_name": pkg,
                "rule_code": rule_code,
                "task_id": task_id,
                "variant": "ambiguous",
            })

    # ── Error-fix prompts (broken code + real error output) ──────────────
    print("  Generating error-fix variants (running opa/regal on corrupted rules)...")
    error_records = _build_error_fix_records(instructions)
    records.extend(error_records)

    return records


# ===========================================================================
# CLI
# ===========================================================================

def main() -> None:
    records = build_dataset()

    if not records:
        print("ERROR: No GRPO examples could be built.  Check Phase 1/3 outputs.")
        return

    # ── Write JSONL ──────────────────────────────────────────────────────
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # ── Summary stats ────────────────────────────────────────────────────
    unique_tasks = len(set(r["task_id"] for r in records))
    from collections import Counter
    variant_counts = Counter(r["variant"] for r in records)

    print(f"\n  GRPO dataset written to {OUTPUT_FILE}")
    print(f"  Total prompts:   {len(records)}")
    print(f"  Unique tasks:    {unique_tasks}")
    print(f"  By variant:")
    for v, c in sorted(variant_counts.items()):
        print(f"    {v:20s} {c:4d}")
    print()


if __name__ == "__main__":
    main()
