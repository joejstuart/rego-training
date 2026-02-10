#!/usr/bin/env python3
"""
Phase 0: Build Field Catalog from SLSA Provenance Attestation.

Parses the source attestation (data/att.json) and produces a structured catalog
of every unique JSON path, observed values, and metadata.  This catalog is the
foundation for deriving natural language instructions, Rego tests, and rules
in subsequent phases.

Usage:
    cd sft/
    python phase0_catalog/build_catalog.py
    python phase0_catalog/build_catalog.py --attestation data/att.json --output phase0_catalog/output/field_catalog.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


# ─── Tier classification ─────────────────────────────────────────────────────
# We classify every path into a tier based on where it sits in the attestation
# structure.  This determines how instructions are framed later.

def classify_tier(path: str) -> str:
    """Assign a tier to a JSON path based on its position in the attestation."""
    if path.startswith(".predicate.buildConfig.tasks[*].results"):
        return "result_level"
    if path.startswith(".predicate.buildConfig.tasks[*].steps"):
        return "step_level"
    if path.startswith(".predicate.buildConfig.tasks[*]"):
        return "task_level"
    if path.startswith(".predicate."):
        return "predicate_level"
    return "top_level"


# ─── Recursive walk ──────────────────────────────────────────────────────────

def walk_json(obj: Any, path: str, collector: dict[str, dict]) -> None:
    """
    Recursively walk a JSON object, collecting unique paths and their values.

    For arrays, we use [*] notation to indicate "any element" — this
    deduplicates across repeated structures (e.g. the 16 tasks).
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}"
            walk_json(value, child_path, collector)

    elif isinstance(obj, list):
        # Record the array itself as a path
        _record_value(collector, path, f"<array of {len(obj)} items>", is_array=True)

        # Walk each element using [*] to deduplicate
        wildcard_path = f"{path}[*]"
        for item in obj:
            walk_json(item, wildcard_path, collector)

    else:
        # Leaf value (string, number, bool, null)
        _record_value(collector, path, obj)


def _record_value(
    collector: dict[str, dict],
    path: str,
    value: Any,
    is_array: bool = False,
) -> None:
    """Record a value observation for a given path."""
    if path not in collector:
        collector[path] = {
            "path": path,
            "observed_values": [],
            "value_types": set(),
            "is_array": is_array,
            "count": 0,
        }

    entry = collector[path]
    entry["count"] += 1

    # Track value type
    if value is None:
        entry["value_types"].add("null")
    elif isinstance(value, bool):
        entry["value_types"].add("boolean")
    elif isinstance(value, int):
        entry["value_types"].add("integer")
    elif isinstance(value, float):
        entry["value_types"].add("number")
    elif isinstance(value, str):
        entry["value_types"].add("string")
    else:
        entry["value_types"].add(type(value).__name__)

    # Store unique values (cap at 20 to avoid bloat for high-cardinality fields)
    str_val = str(value)
    if str_val not in [str(v) for v in entry["observed_values"]]:
        if len(entry["observed_values"]) < 20:
            entry["observed_values"].append(value)


# ─── Task-level enrichment ───────────────────────────────────────────────────

def enrich_task_info(attestation: dict, collector: dict[str, dict]) -> None:
    """
    For task-level paths, figure out which tasks contain each field.
    This helps Phase 1 generate instructions like "verify ALL tasks have X"
    vs. "verify the build-container task has result IMAGE_DIGEST."
    """
    tasks = (
        attestation
        .get("predicate", {})
        .get("buildConfig", {})
        .get("tasks", [])
    )

    task_names = [t.get("name", f"task_{i}") for i, t in enumerate(tasks)]

    for path, entry in collector.items():
        if "[*]" not in path:
            entry["tasks_with_field"] = None
            continue

        # Check which tasks actually contain this field
        if path.startswith(".predicate.buildConfig.tasks[*]"):
            # Extract the sub-path after tasks[*]
            sub_path = path[len(".predicate.buildConfig.tasks[*]"):]
            if not sub_path:
                entry["tasks_with_field"] = task_names
                continue

            matching_tasks = []
            for task_name, task in zip(task_names, tasks):
                if _task_has_path(task, sub_path):
                    matching_tasks.append(task_name)

            entry["tasks_with_field"] = matching_tasks if matching_tasks else None
        else:
            entry["tasks_with_field"] = None


def _task_has_path(task: dict, sub_path: str) -> bool:
    """Check if a task contains a given sub-path (simplified check)."""
    # Remove leading dot
    parts = sub_path.lstrip(".").split(".")

    obj: Any = task
    for part in parts:
        # Handle array notation: field[*]
        clean = part.replace("[*]", "")
        if isinstance(obj, dict) and clean in obj:
            obj = obj[clean]
            if "[*]" in part and isinstance(obj, list) and obj:
                obj = obj[0]  # peek into first element
        elif isinstance(obj, list) and obj:
            if isinstance(obj[0], dict) and clean in obj[0]:
                obj = obj[0][clean]
            else:
                return False
        else:
            return False
    return True


# ─── Generate human-readable ID ──────────────────────────────────────────────

def path_to_id(path: str) -> str:
    """
    Convert a JSON path to a snake_case ID for file naming.

    Examples:
        .predicateType → predicate_type
        .predicate.buildConfig.tasks[*].status → task_status
        .predicate.buildConfig.tasks[*].results[*].name → task_result_name
    """
    # Remove leading dot
    p = path.lstrip(".")

    # Simplify common prefixes
    p = re.sub(r"^predicate\.buildConfig\.tasks\[\*\]\.results\[\*\]\.", "task_result_", p)
    p = re.sub(r"^predicate\.buildConfig\.tasks\[\*\]\.steps\[\*\]\.", "task_step_", p)
    p = re.sub(r"^predicate\.buildConfig\.tasks\[\*\]\.", "task_", p)
    p = re.sub(r"^predicate\.", "predicate_", p)
    p = re.sub(r"^subject\[\*\]\.", "subject_", p)

    # Remove remaining [*]
    p = p.replace("[*]", "")

    # camelCase → snake_case
    p = re.sub(r"([a-z])([A-Z])", r"\1_\2", p)

    # Replace dots and hyphens with underscores
    p = re.sub(r"[.\-/]", "_", p)

    # Collapse multiple underscores
    p = re.sub(r"_+", "_", p)

    return p.lower().strip("_")


def path_to_description(path: str) -> str:
    """Generate a human-readable description from a JSON path."""
    p = path.lstrip(".")

    # Map known paths to descriptions
    descriptions = {
        "_type": "In-toto statement type URI",
        "predicateType": "SLSA predicate type URI",
        "subject": "Attestation subjects (images with digests)",
        "predicate.buildType": "Build system type identifier",
        "predicate.builder.id": "Builder identity URI",
    }
    if p in descriptions:
        return descriptions[p]

    # Generate from path structure
    if "tasks[*].results[*]" in p:
        field = p.split(".")[-1]
        return f"Task result field: {field}"
    if "tasks[*].steps[*]" in p:
        field = p.split(".")[-1]
        return f"Task step field: {field}"
    if "tasks[*].invocation.environment.annotations" in p:
        key = p.split(".")[-1]
        return f"Task annotation: {key}"
    if "tasks[*].invocation.environment.labels" in p:
        key = p.split(".")[-1]
        return f"Task label: {key}"
    if "tasks[*].invocation.parameters" in p:
        field = p.split(".")[-1]
        return f"Task invocation parameter: {field}"
    if "tasks[*].ref" in p:
        field = p.split(".")[-1]
        return f"Task reference field: {field}"
    if "tasks[*]" in p:
        field = p.split(".")[-1]
        return f"Task-level field: {field}"
    if "predicate." in p:
        remainder = p[len("predicate."):]
        return f"Predicate field: {remainder}"

    return f"Field: {p}"


# ─── Main ────────────────────────────────────────────────────────────────────

def build_catalog(attestation_path: str, output_path: str) -> list[dict]:
    """Build the field catalog from an attestation file."""
    with open(attestation_path, "r", encoding="utf-8") as f:
        attestation = json.load(f)

    # Walk the entire attestation
    collector: dict[str, dict] = {}
    walk_json(attestation, "", collector)

    # Enrich with task-level info
    enrich_task_info(attestation, collector)

    # Build final catalog entries
    catalog = []
    for path, entry in sorted(collector.items()):
        # Determine primary value type
        types = entry["value_types"]
        if len(types) == 1:
            value_type = next(iter(types))
        elif types:
            value_type = "|".join(sorted(types))
        else:
            value_type = "unknown"

        tier = classify_tier(path)

        catalog_entry = {
            "id": path_to_id(path),
            "path": path,
            "description": path_to_description(path),
            "tier": tier,
            "value_type": value_type,
            "observed_values": entry["observed_values"],
            "cardinality": "per_task" if "[*]" in path else "single",
            "observation_count": entry["count"],
            "tasks_with_field": entry.get("tasks_with_field"),
        }
        catalog.append(catalog_entry)

    # Write output
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", encoding="utf-8") as f:
        for entry in catalog:
            f.write(json.dumps(entry, default=str) + "\n")

    # Print summary
    tier_counts = defaultdict(int)
    for entry in catalog:
        tier_counts[entry["tier"]] += 1

    print(f"Attestation: {attestation_path}")
    print(f"Output:      {output_path}")
    print(f"Total catalog entries: {len(catalog)}")
    print()
    print("Entries by tier:")
    for tier in ["top_level", "predicate_level", "task_level", "result_level", "step_level"]:
        print(f"  {tier:20s} {tier_counts.get(tier, 0):4d}")
    print()

    # Print a few examples
    print("Sample entries:")
    for entry in catalog[:5]:
        vals = entry["observed_values"]
        val_preview = str(vals[0])[:60] if vals else "(none)"
        print(f"  [{entry['tier']:17s}] {entry['path']:60s} = {val_preview}")
    print(f"  ... and {len(catalog) - 5} more")

    return catalog


def main():
    parser = argparse.ArgumentParser(
        description="Phase 0: Build field catalog from SLSA provenance attestation."
    )
    parser.add_argument(
        "--attestation", type=str, default="data/att.json",
        help="Path to the attestation JSON file (default: data/att.json).",
    )
    parser.add_argument(
        "--output", type=str, default="phase0_catalog/output/field_catalog.jsonl",
        help="Output path for the field catalog (default: phase0_catalog/output/field_catalog.jsonl).",
    )
    args = parser.parse_args()

    build_catalog(args.attestation, args.output)


if __name__ == "__main__":
    main()
