#!/usr/bin/env python3
"""
Phase 2: Generate Rego Test Files from Instructions.

For each instruction from Phase 1, generates a self-contained Rego test file
with at least one positive test (rule does NOT fire on valid input) and one
negative test (rule DOES fire on invalid input).  Test data is injected via
OPA's ``with input as {...}`` keyword so tests stay minimal.

Test files are written to:
    phase2_tests/output/tasks/<task_id>/<package_name>_test.rego

Usage:
    cd sft/
    python phase2_tests/generate_tests.py
    python phase2_tests/generate_tests.py --instructions phase1_instructions/output/instructions.jsonl
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import textwrap
from pathlib import Path
from typing import Any


# ─── JSON → Rego literal formatting ──────────────────────────────────────────

def _to_rego_literal(value: Any, indent: int = 0, tab: str = "\t") -> str:
    """
    Convert a Python value to a Rego literal string.

    Rego objects/arrays use the same syntax as JSON, so this is essentially
    a pretty-printer with tab indentation (Rego convention).
    """
    prefix = tab * indent

    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        # Escape internal quotes
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, list):
        if not value:
            return "[]"
        items = []
        for item in value:
            items.append(f"{prefix}{tab}{_to_rego_literal(item, indent + 1, tab)}")
        return "[\n" + ",\n".join(items) + f",\n{prefix}]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = []
        for k, v in value.items():
            key_str = f'"{k}"'
            val_str = _to_rego_literal(v, indent + 1, tab)
            items.append(f"{prefix}{tab}{key_str}: {val_str}")
        return "{\n" + ",\n".join(items) + f",\n{prefix}}}"

    return repr(value)


def _format_with_input(mock: dict, indent_level: int = 1) -> str:
    """Format a mock dict as a ``with input as { ... }`` clause."""
    tab = "\t"
    prefix = tab * indent_level
    rego_obj = _to_rego_literal(mock, indent_level, tab)
    return f"{prefix}with input as {rego_obj}"


# ─── Mock data mutation helpers ───────────────────────────────────────────────

def _deep_get(d: dict, keys: list[str]) -> Any:
    """Walk into a nested dict by a list of keys, return None if missing."""
    current = d
    for k in keys:
        if isinstance(current, dict) and k in current:
            current = current[k]
        elif isinstance(current, list) and current:
            current = current[0]
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return None
        else:
            return None
    return current


def _deep_set(d: dict, keys: list[str], value: Any) -> dict:
    """Return a deep copy of *d* with nested *keys* set to *value*."""
    d = copy.deepcopy(d)
    current = d
    for i, k in enumerate(keys[:-1]):
        if isinstance(current, dict):
            current = current.setdefault(k, {})
        elif isinstance(current, list) and current:
            current = current[0]
            current = current.setdefault(k, {})
    if isinstance(current, dict):
        current[keys[-1]] = value
    elif isinstance(current, list) and current and isinstance(current[0], dict):
        current[0][keys[-1]] = value
    return d


def _deep_delete(d: dict, keys: list[str]) -> dict:
    """Return a deep copy of *d* with the nested key path removed."""
    d = copy.deepcopy(d)
    current = d
    parents: list[tuple[Any, str]] = []
    for i, k in enumerate(keys[:-1]):
        if isinstance(current, dict) and k in current:
            parents.append((current, k))
            current = current[k]
        elif isinstance(current, list) and current:
            current = current[0]
            if isinstance(current, dict) and k in current:
                parents.append((current, k))
                current = current[k]
            else:
                return d  # path doesn't exist
        else:
            return d  # path doesn't exist

    last_key = keys[-1]
    if isinstance(current, dict) and last_key in current:
        del current[last_key]
    elif isinstance(current, list) and current and isinstance(current[0], dict):
        if last_key in current[0]:
            del current[0][last_key]
    return d


def _extract_leaf_path(input_path: str) -> list[str]:
    """
    Convert a JSON dot-path like '.predicate.builder.id' to ['predicate','builder','id'].
    Strips array wildcards.
    """
    p = input_path.lstrip(".")
    parts = p.split(".")
    return [part.replace("[*]", "") for part in parts]


def _mutate_value(value: Any) -> Any:
    """Return a clearly wrong version of a value for negative tests."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        if value.startswith("https://"):
            return "https://example.com/INVALID"
        if value.startswith("http://"):
            return "http://example.com/INVALID"
        if value.startswith("oci://"):
            return "oci://example.com/INVALID"
        if value.startswith("git+"):
            return "git+https://example.com/INVALID.git"
        if re.match(r"^\d{4}-\d{2}-\d{2}T", value):
            return "not-a-timestamp"
        if re.match(r"^(sha256:)?[0-9a-f]{40,}$", value):
            return "INVALID_DIGEST"
        if value in ("true", "false"):
            return "true" if value == "false" else "false"
        return "INVALID_VALUE"
    if isinstance(value, (int, float)):
        return -9999
    return "INVALID"


# ─── Test generation per tier ─────────────────────────────────────────────────

def _generate_tier1_mocks(inst: dict) -> tuple[dict, dict]:
    """
    For Tier 1 instructions, mock_data IS the valid case.
    Generate the invalid case by mutating the target field.

    Returns (positive_mock, negative_mock).
    """
    mock = inst["mock_data"]
    input_path = inst["input_paths"][0]
    keys = _extract_leaf_path(input_path)
    instruction = inst["instruction"]

    # Get the current value at the leaf
    leaf_val = _deep_get(mock, keys)

    # Determine what kind of negative test to produce
    if "is missing" in instruction or "missing or empty" in instruction:
        # Negative = delete the field
        neg_mock = _deep_delete(mock, keys)
    elif "does not match" in instruction:
        # Negative = bad format
        neg_mock = _deep_set(mock, keys, "INVALID_FORMAT")
    elif "is not" in instruction:
        # Negative = wrong value
        neg_mock = _deep_set(mock, keys, _mutate_value(leaf_val))
    elif "missing or is not" in instruction:
        # Negative = delete the field (simpler)
        neg_mock = _deep_delete(mock, keys)
    else:
        # Fallback: mutate value
        neg_mock = _deep_set(mock, keys, _mutate_value(leaf_val))

    return copy.deepcopy(mock), neg_mock


def _extract_valid_elements(mock: dict) -> dict:
    """
    For Tier 2/3 mocks that contain arrays with mixed valid/invalid elements,
    keep only the first element (which by convention is the valid one).
    """
    mock = copy.deepcopy(mock)
    _keep_first_in_arrays(mock)
    return mock


def _keep_first_in_arrays(obj: Any, truncate: bool = True) -> None:
    """Truncate the first multi-element array found on each path.

    After truncating an array, inner arrays of the kept element are left
    intact — they belong to the "valid" element's internal structure, not
    a mix of valid/invalid alternatives.
    """
    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(val, list) and len(val) > 1 and truncate:
                # Keep only the first element (the "good" one by convention)
                obj[key] = [val[0]]
                # Do NOT truncate inner arrays of the kept element
                _keep_first_in_arrays(val[0], truncate=False)
            elif isinstance(val, list) and len(val) == 1:
                _keep_first_in_arrays(val[0], truncate=truncate)
            elif isinstance(val, dict):
                _keep_first_in_arrays(val, truncate=truncate)
    elif isinstance(obj, list):
        for item in obj:
            _keep_first_in_arrays(item, truncate=truncate)


def _generate_tier2_mocks(inst: dict) -> tuple[dict, dict]:
    """
    For Tier 2 instructions, mock_data contains arrays with both valid and
    invalid elements (by convention, first element is good, others are bad).

    Returns (positive_mock, negative_mock).
    """
    mock = inst["mock_data"]

    # Negative = full mock as-is (contains failing elements)
    neg_mock = copy.deepcopy(mock)

    # Positive = only the valid (first) elements
    pos_mock = _extract_valid_elements(mock)

    return pos_mock, neg_mock


def _generate_tier3_mocks(inst: dict) -> tuple[dict, dict]:
    """
    Tier 3 instructions have hand-crafted mocks that embed the failing scenario.
    We need instruction-specific logic to construct valid versions.

    Returns (positive_mock, negative_mock).
    """
    iid = inst["id"]
    mock = inst["mock_data"]

    # Default: negative is mock as-is, positive is "fixed" version
    neg_mock = copy.deepcopy(mock)
    pos_mock = copy.deepcopy(mock)

    if iid == "image_digest_requires_succeeded":
        # Fix: all tasks producing IMAGE_DIGEST must be Succeeded
        for task in pos_mock["predicate"]["buildConfig"]["tasks"]:
            task["status"] = "Succeeded"

    elif iid == "hermetic_build_required":
        # Fix: all HERMETIC params must be "true"
        pos_mock["predicate"]["invocation"]["parameters"]["hermetic"] = "true"
        for task in pos_mock["predicate"]["buildConfig"]["tasks"]:
            task["invocation"]["parameters"]["HERMETIC"] = "true"

    elif iid == "trusted_builder_id":
        # mock_data is already the valid case for this one
        # Negative: change one of the fields
        neg_mock = copy.deepcopy(mock)
        neg_mock["predicate"]["builder"]["id"] = "https://example.com/untrusted"

    elif iid == "subjects_match_build_results":
        # Fix: remove the orphan subject
        pos_mock["subject"] = [
            {"name": "quay.io/example/image", "digest": {"sha256": "abc123"}}
        ]
        # Ensure the task result matches
        pos_mock["predicate"]["buildConfig"]["tasks"][0]["results"] = [
            {"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc123"},
        ]

    elif iid == "git_revision_matches_material":
        # Fix: make the sha1 match the revision
        revision = pos_mock["predicate"]["invocation"]["parameters"]["revision"]
        for mat in pos_mock["predicate"]["materials"]:
            if mat["uri"].startswith("git+"):
                mat["digest"]["sha1"] = revision

    elif iid == "tls_verify_enabled":
        # Fix: all TLSVERIFY must be "true"
        for task in pos_mock["predicate"]["buildConfig"]["tasks"]:
            task["invocation"]["parameters"]["TLSVERIFY"] = "true"

    elif iid == "build_timestamps_chronological":
        # Fix: swap so start < finish
        pos_mock["predicate"]["metadata"] = {
            "buildStartedOn": "2025-05-12T12:09:47Z",
            "buildFinishedOn": "2025-05-12T12:20:00Z",
        }

    elif iid == "source_repo_uses_https":
        # Fix: use https
        pos_mock["predicate"]["invocation"]["parameters"]["git-url"] = (
            "https://github.com/example/repo"
        )

    elif iid == "checks_not_skipped":
        # Fix: skip-checks is "false"
        pos_mock["predicate"]["invocation"]["parameters"]["skip-checks"] = "false"

    elif iid == "scan_tasks_have_test_output":
        # Fix: all scan/sast tasks have TEST_OUTPUT
        for task in pos_mock["predicate"]["buildConfig"]["tasks"]:
            result_names = {r["name"] for r in task.get("results", [])}
            if "TEST_OUTPUT" not in result_names:
                task["results"].append(
                    {"name": "TEST_OUTPUT", "type": "string", "value": "{}"}
                )

    return pos_mock, neg_mock


# ─── Rego test file rendering ─────────────────────────────────────────────────

def _render_test_file(inst: dict, pos_mock: dict, neg_mock: dict) -> str:
    """Render a complete Rego test file for an instruction."""
    pkg = inst["package_name"]
    iid = inst["id"]
    instruction = inst["instruction"]

    # Build the test names
    pos_name = f"test_{iid}_valid"
    neg_name = f"test_{iid}_invalid"

    # Format the with-input clauses
    pos_input = _format_with_input(pos_mock, indent_level=1)
    neg_input = _format_with_input(neg_mock, indent_level=1)

    # Build the Rego test file
    #
    # NOTE: For partial set rules (``deny contains msg if { ... }``), an empty
    # set is *defined* in Rego v1, so ``not pkg.deny`` fails even when deny
    # has no results.  We use ``count(pkg.deny) == 0`` for positive tests
    # and ``count(pkg.deny) > 0`` for negative tests.
    lines = [
        f"package {pkg}_test",
        "",
        "import rego.v1",
        "",
        f"import data.{pkg}",
        "",
        f"# Instruction: {instruction}",
        "",
        f"# Positive test: valid input should produce no deny violations.",
        f"{pos_name} if {{",
        f"\tcount({pkg}.deny) == 0",
        f"{pos_input}",
        f"}}",
        "",
        f"# Negative test: invalid input should produce at least one deny violation.",
        f"{neg_name} if {{",
        f"\tcount({pkg}.deny) > 0",
        f"{neg_input}",
        f"}}",
        "",
    ]

    return "\n".join(lines)


# ─── Main generation pipeline ────────────────────────────────────────────────

def _load_instructions(path: str) -> list[dict]:
    """Load the JSONL instructions file."""
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def generate_tests(instructions_path: str, output_dir: str) -> None:
    """Generate Rego test files for all instructions."""
    instructions = _load_instructions(instructions_path)
    out_root = Path(output_dir)

    stats = {"total": 0, "tier1": 0, "tier2": 0, "tier3": 0}

    for inst in instructions:
        tier = inst["tier"]
        iid = inst["id"]
        pkg = inst["package_name"]

        # Generate positive/negative mocks based on tier
        if tier == 1:
            pos_mock, neg_mock = _generate_tier1_mocks(inst)
            stats["tier1"] += 1
        elif tier == 2:
            pos_mock, neg_mock = _generate_tier2_mocks(inst)
            stats["tier2"] += 1
        elif tier == 3:
            pos_mock, neg_mock = _generate_tier3_mocks(inst)
            stats["tier3"] += 1
        else:
            print(f"WARNING: Unknown tier {tier} for instruction {iid}, skipping.")
            continue

        # Render the test file
        test_content = _render_test_file(inst, pos_mock, neg_mock)

        # Write to output directory
        task_dir = out_root / "tasks" / iid
        task_dir.mkdir(parents=True, exist_ok=True)
        test_file = task_dir / f"{pkg}_test.rego"
        test_file.write_text(test_content, encoding="utf-8")

        stats["total"] += 1

    # Summary
    print(f"Instructions: {instructions_path}  ({len(instructions)} entries)")
    print(f"Output:       {output_dir}/tasks/")
    print(f"Total tests generated: {stats['total']}")
    print()
    print("Tests by tier:")
    print(f"  Tier 1 (field-level):   {stats['tier1']:4d}")
    print(f"  Tier 2 (pattern-level): {stats['tier2']:4d}")
    print(f"  Tier 3 (composite):     {stats['tier3']:4d}")
    print()

    # Print a sample
    sample = out_root / "tasks" / instructions[0]["id"]
    sample_files = list(sample.glob("*_test.rego")) if sample.exists() else []
    if sample_files:
        print(f"Sample test file: {sample_files[0]}")
        print("─" * 60)
        print(sample_files[0].read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(
        description="Phase 2: Generate Rego test files from instructions."
    )
    parser.add_argument(
        "--instructions", type=str,
        default="phase1_instructions/output/instructions.jsonl",
        help="Path to the instructions JSONL (default: phase1_instructions/output/instructions.jsonl).",
    )
    parser.add_argument(
        "--output", type=str,
        default="phase2_tests/output",
        help="Output directory (default: phase2_tests/output).",
    )
    args = parser.parse_args()

    generate_tests(args.instructions, args.output)


if __name__ == "__main__":
    main()
