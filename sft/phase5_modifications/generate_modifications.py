#!/usr/bin/env python3
"""Phase 5: Generate rule-modification training examples.

For each of the 60 validated rules from Phase 3, this script generates
several modification tasks. Each task provides:
  - The original Rego rule code
  - A natural-language modification instruction
  - The correctly modified rule code

This teaches the model to READ, UNDERSTAND, and MODIFY existing Rego rules —
a critical skill for real-world policy maintenance.

Modification types:
  1. rename_package       — Rename the package to a new name
  2. improve_message      — Add "VIOLATION: " prefix to deny messages
  3. change_value         — Change an expected literal value (Tier 1)
  4. add_missing_check    — Add a deny rule for missing fields (Tier 1, no iteration)
  5. relax_to_allowlist   — Accept multiple values instead of one (Tier 1, no iteration)

Output: phase5_modifications/output/modifications.jsonl

Each line is:
  {"id": "...", "original_task_id": "...", "tier": N, "package_name": "...",
   "mod_type": "...", "instruction": "...", "original_rule": "...",
   "modified_rule": "..."}

Usage:
    cd sft/
    python phase5_modifications/generate_modifications.py
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
SFT_ROOT = SCRIPT_DIR.parent
INSTRUCTIONS_PATH = SFT_ROOT / "phase1_instructions" / "output" / "instructions.jsonl"
PHASE3_TASKS = SFT_ROOT / "phase3_rules" / "output" / "tasks"
OUTPUT_DIR = SCRIPT_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "modifications.jsonl"


# ===========================================================================
# Loaders
# ===========================================================================

def load_instructions() -> list[dict]:
    records: list[dict] = []
    with open(INSTRUCTIONS_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_rule(task_id: str, pkg: str) -> str | None:
    path = PHASE3_TASKS / task_id / f"{pkg}.rego"
    if not path.exists():
        return None
    return path.read_text()


def load_result(task_id: str) -> dict | None:
    path = PHASE3_TASKS / task_id / "result.json"
    if not path.exists():
        return None
    with open(path) as f:
        r = json.load(f)
    return r if r.get("status") == "pass" else None


# ===========================================================================
# Package rename map (hand-curated for realistic variety)
# ===========================================================================

_RENAME_MAP: dict[str, str] = {
    # Tier 1 — top-level
    "type_check": "intoto_statement_type",
    "predicate_type_check": "slsa_predicate_type",
    "predicate_build_type_check": "build_type_policy",
    "predicate_builder_id_check": "builder_identity",
    "predicate_invocation_parameters_git_url_check": "git_url_policy",
    "predicate_invocation_parameters_hermetic_check": "hermetic_parameter",
    "predicate_invocation_parameters_output_image_check": "output_image_parameter",
    "predicate_invocation_parameters_rebuild_check": "rebuild_parameter",
    "predicate_invocation_parameters_revision_check": "revision_parameter",
    "predicate_invocation_parameters_skip_checks_check": "skip_checks_parameter",
    "predicate_materials_check": "materials_present",
    "predicate_materials_digest_sha256_check": "material_digest_required",
    "predicate_materials_uri_check": "material_uri_policy",
    "predicate_metadata_build_finished_on_check": "build_finished_timestamp",
    "predicate_metadata_build_started_on_check": "build_started_timestamp",
    "predicate_metadata_reproducible_check": "reproducible_flag",
    "subject_digest_sha256_check": "subject_digest_policy",
    "subject_name_check": "subject_name_required",
    # Tier 1 — task-level
    "task_finished_on_check": "task_completion_time",
    "task_started_on_check": "task_start_time",
    "task_name_check": "task_name_policy",
    "task_status_check": "task_status_policy",
    "task_invocation_parameters_commit_sha_check": "commit_sha_policy",
    "task_invocation_parameters_dockerfile_check": "dockerfile_parameter",
    "task_invocation_parameters_hermetic_check": "task_hermetic_parameter",
    "task_invocation_parameters_image_check": "task_image_parameter",
    "task_invocation_parameters_tlsverify_check": "tls_verify_parameter",
    "task_ref_params_name_check": "ref_param_name_policy",
    "task_ref_params_value_check": "ref_param_value_policy",
    "task_ref_resolver_check": "ref_resolver_policy",
    "task_result_name_check": "result_name_policy",
    "task_result_type_check": "result_type_policy",
    "task_result_value_check": "result_value_policy",
    "task_results_check": "task_results_present",
    "task_service_account_name_check": "service_account_policy",
    "task_step_environment_container_check": "step_container_policy",
    "task_step_environment_image_check": "step_image_policy",
    "task_steps_check": "task_steps_present",
    "tls_verify_enabled": "tls_verification_policy",
    # Tier 2
    "all_materials_have_digest": "verify_material_digests",
    "all_materials_have_uri": "verify_material_uris",
    "all_subjects_have_digest": "verify_subject_digests",
    "all_subjects_have_name": "verify_subject_names",
    "all_task_refs_have_required_params": "verify_task_ref_params",
    "all_tasks_bundles_resolver": "verify_resolver_type",
    "all_tasks_have_name": "verify_task_names",
    "all_tasks_have_service_account": "verify_service_accounts",
    "all_tasks_have_steps": "verify_task_steps",
    "all_tasks_have_timestamps": "verify_task_times",
    "all_tasks_succeeded": "verify_task_success",
    "build_tasks_have_image_digest_result": "verify_build_image_digest",
    # Tier 3
    "build_timestamps_chronological": "verify_build_time_order",
    "checks_not_skipped": "verify_checks_enabled",
    "git_revision_matches_material": "verify_git_revision_match",
    "hermetic_build_required": "verify_hermetic_build",
    "image_digest_requires_succeeded": "verify_digest_task_success",
    "scan_tasks_have_test_output": "verify_scan_outputs",
    "source_repo_uses_https": "verify_https_source",
    "subjects_match_build_results": "verify_subject_result_match",
    "trusted_builder_id": "verify_trusted_builder",
}


def _get_new_package_name(pkg: str) -> str:
    if pkg in _RENAME_MAP:
        return _RENAME_MAP[pkg]
    if pkg.endswith("_check"):
        return pkg[:-6] + "_policy"
    return pkg + "_policy"


# ===========================================================================
# Alternative values for change_value
# ===========================================================================

_ALTERNATIVE_VALUES: dict[str, str] = {
    "https://in-toto.io/Statement/v0.1": "https://in-toto.io/Statement/v1.0",
    "https://slsa.dev/provenance/v0.2": "https://slsa.dev/provenance/v1.0",
    "tekton.dev/v1beta1/PipelineRun": "tekton.dev/v1/PipelineRun",
    "https://tekton.dev/chains/v2": "https://tekton.dev/chains/v3",
    "https://github.com/enterprise-contract/golden-container": (
        "https://github.com/my-org/my-application"
    ),
    "true": "1",
    "false": "true",
    "Containerfile": "Dockerfile",
    "init": "initialize",
    "name": "identifier",
    "Succeeded": "Completed",
    "bundles": "git",
    "oci://registry.access.redhat.com/ubi9/skopeo": (
        "oci://registry.example.com/tools/skopeo"
    ),
}


# ===========================================================================
# Allowlist values for relax_to_allowlist
# ===========================================================================

_ALLOWLIST: dict[str, list[str]] = {
    "https://in-toto.io/Statement/v0.1": [
        "https://in-toto.io/Statement/v0.1",
        "https://in-toto.io/Statement/v1.0",
    ],
    "https://slsa.dev/provenance/v0.2": [
        "https://slsa.dev/provenance/v0.2",
        "https://slsa.dev/provenance/v1.0",
    ],
    "tekton.dev/v1beta1/PipelineRun": [
        "tekton.dev/v1beta1/PipelineRun",
        "tekton.dev/v1/PipelineRun",
    ],
    "https://tekton.dev/chains/v2": [
        "https://tekton.dev/chains/v2",
        "https://tekton.dev/chains/v3",
    ],
    "bundles": ["bundles", "git"],
    "Succeeded": ["Succeeded", "Completed"],
}


# ===========================================================================
# Modification generators
#
# Each returns dict | None with keys: mod_type, instruction, modified_rule
# ===========================================================================

def _has_iteration(rule_code: str) -> bool:
    return bool(re.search(r"\bsome\s+\w+\s+in\s+", rule_code))


def mod_rename_package(rule_code: str, instr_rec: dict) -> dict | None:
    """Rename the package to a curated alternative name."""
    pkg = instr_rec["package_name"]
    new_pkg = _get_new_package_name(pkg)
    if new_pkg == pkg:
        return None

    modified = rule_code.replace(f"package {pkg}", f"package {new_pkg}", 1)

    return {
        "mod_type": "rename_package",
        "instruction": f"Rename the package from `{pkg}` to `{new_pkg}`.",
        "modified_rule": modified,
    }


def mod_improve_message_prefix(rule_code: str, instr_rec: dict) -> dict | None:
    """Add 'VIOLATION: ' prefix to all deny messages."""
    modified = rule_code

    # sprintf messages: msg := sprintf("X", ...) → sprintf("VIOLATION: X", ...)
    modified = re.sub(
        r'msg := sprintf\("(?!VIOLATION: )',
        'msg := sprintf("VIOLATION: ',
        modified,
    )

    # Plain string messages: msg := "X" → msg := "VIOLATION: X"
    modified = re.sub(
        r'msg := "(?!VIOLATION: )',
        'msg := "VIOLATION: ',
        modified,
    )

    if modified == rule_code:
        return None

    return {
        "mod_type": "improve_message",
        "instruction": 'Add the prefix "VIOLATION: " to the beginning of every deny message.',
        "modified_rule": modified,
    }


def mod_change_value(rule_code: str, instr_rec: dict) -> dict | None:
    """Change an expected literal value in a comparison (Tier 1 only)."""
    if instr_rec["tier"] != 1:
        return None

    # Find != "value" comparison
    m = re.search(r'!= "(.*?)"', rule_code)
    if not m:
        return None

    old_val = m.group(1)
    new_val = _ALTERNATIVE_VALUES.get(old_val)
    if not new_val:
        return None

    # Replace all occurrences — both in the comparison and in messages.
    # Using the raw value (not quoted) catches it inside sprintf strings too.
    modified = rule_code.replace(old_val, new_val)

    return {
        "mod_type": "change_value",
        "instruction": (
            f'Change the expected value from `"{old_val}"` to `"{new_val}"`. '
            f"Update the deny message to match."
        ),
        "modified_rule": modified,
    }


def mod_add_missing_check(rule_code: str, instr_rec: dict) -> dict | None:
    """Add a deny rule that fires when the field is missing entirely.

    Only applies to Tier 1 rules WITHOUT iteration and WITHOUT an existing
    ``not`` guard.
    """
    if instr_rec["tier"] != 1:
        return None
    if _has_iteration(rule_code):
        return None
    # Skip rules that already check for missing fields
    if re.search(r"\bnot\s+input", rule_code):
        return None

    # Find the field path in the != comparison
    m = re.search(r'(input(?:\.\w+|\["[^"]+"\])+)\s*!=', rule_code)
    if not m:
        return None

    field_path = m.group(1)

    # Derive human-readable field name from the last path segment
    last_segment = re.findall(r'\.(\w+)|\["([^"]+)"\]', field_path)
    if last_segment:
        field_name = last_segment[-1][0] or last_segment[-1][1]
    else:
        field_name = field_path

    # Build the new deny block
    missing_block = (
        f"deny contains msg if {{\n"
        f"\tnot {field_path}\n"
        f'\tmsg := "{field_name} field is missing"\n'
        f"}}"
    )

    # Insert before the first deny rule
    lines = rule_code.rstrip("\n").split("\n")
    new_lines: list[str] = []
    inserted = False
    for line in lines:
        if line.startswith("deny ") and not inserted:
            new_lines.append(missing_block)
            new_lines.append("")
            inserted = True
        new_lines.append(line)

    if not inserted:
        return None

    modified = "\n".join(new_lines) + "\n"

    return {
        "mod_type": "add_missing_check",
        "instruction": (
            f"Add a separate `deny` rule that fires when `{field_path}` is missing "
            f"entirely, before the existing value check."
        ),
        "modified_rule": modified,
    }


def mod_relax_to_allowlist(rule_code: str, instr_rec: dict) -> dict | None:
    """Change from single-value check to allowlist set membership.

    Only applies to Tier 1 rules WITHOUT iteration.
    """
    if instr_rec["tier"] != 1:
        return None
    if _has_iteration(rule_code):
        return None

    # Find the comparison: field != "value"
    m = re.search(
        r'(input(?:\.\w+|\["[^"]+"\])+)\s*!=\s*"(.*?)"',
        rule_code,
    )
    if not m:
        return None

    field_path = m.group(1)
    old_val = m.group(2)

    allowed = _ALLOWLIST.get(old_val)
    if not allowed or len(allowed) < 2:
        return None

    # Build the set literal
    set_items = ", ".join(f'"{v}"' for v in allowed)

    # Replace the comparison line
    old_comparison = f'{field_path} != "{old_val}"'
    new_lines = (
        f'allowed := {{{set_items}}}\n'
        f'\tnot {field_path} in allowed'
    )

    modified = rule_code.replace(old_comparison, new_lines, 1)

    # Update the sprintf expected value in the deny message
    allowed_str = ", ".join(allowed)
    modified = re.sub(
        rf'expected {re.escape(old_val)}',
        f'expected one of: {allowed_str}',
        modified,
    )

    return {
        "mod_type": "relax_to_allowlist",
        "instruction": (
            f"Instead of checking for a single allowed value, accept any of: "
            f"{', '.join(f'`{v}`' for v in allowed)}. "
            f"Use a set variable and `not {field_path} in allowed` for membership."
        ),
        "modified_rule": modified,
    }


# ===========================================================================
# Main
# ===========================================================================

ALL_MODIFIERS = [
    mod_rename_package,
    mod_improve_message_prefix,
    mod_change_value,
    mod_add_missing_check,
    mod_relax_to_allowlist,
]


def main() -> None:
    instructions = load_instructions()
    records: list[dict] = []
    skipped = 0

    for instr_rec in instructions:
        task_id = instr_rec["id"]
        pkg = instr_rec["package_name"]

        # Check Phase 3 passed
        result = load_result(task_id)
        if result is None:
            skipped += 1
            continue

        rule_code = load_rule(task_id, pkg)
        if rule_code is None:
            skipped += 1
            continue

        # Generate all applicable modifications
        for mod_fn in ALL_MODIFIERS:
            mod = mod_fn(rule_code, instr_rec)
            if mod is not None:
                records.append({
                    "id": f"{task_id}__{mod['mod_type']}",
                    "original_task_id": task_id,
                    "tier": instr_rec["tier"],
                    "package_name": pkg,
                    "mod_type": mod["mod_type"],
                    "instruction": mod["instruction"],
                    "original_rule": rule_code,
                    "modified_rule": mod["modified_rule"],
                })

    # Write output
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # Statistics
    type_counts = Counter(r["mod_type"] for r in records)
    tier_counts = Counter(r["tier"] for r in records)

    print(f"Tasks processed:  {len(instructions) - skipped}")
    print(f"Tasks skipped:    {skipped}")
    print(f"Total modifications: {len(records)}")

    print(f"\nBy modification type:")
    for t, c in type_counts.most_common():
        print(f"  {t:25s}: {c}")

    print(f"\nBy tier:")
    for t in sorted(tier_counts):
        print(f"  Tier {t}: {tier_counts[t]}")

    print(f"\nOutput: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
