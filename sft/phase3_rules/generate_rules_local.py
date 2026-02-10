#!/usr/bin/env python3
"""
Phase 3: Generate Rego Rules (local, deterministic).

For each instruction from Phase 1, generates the Rego rule using templates.
Validates every rule with ``opa check`` (syntax) and ``opa test`` (functional).

This script replaces the LLM-based ``generate_rules.py`` with a fully
reproducible, deterministic approach.  Every rule is generated from the
instruction metadata using pattern-matching on the path structure and
instruction text.

Usage:
    cd sft/
    python phase3_rules/generate_rules_local.py
    python phase3_rules/generate_rules_local.py --skip-passing
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import textwrap
from pathlib import Path
from typing import Any


# ─── Path parsing ─────────────────────────────────────────────────────────────

# Variable name hints for arrays encountered during path traversal
_VAR_HINTS = {
    "tasks": "task",
    "subject": "subject",
    "materials": "material",
    "results": "result",
    "steps": "step",
    "params": "param",
}


def _parse_path(input_path: str) -> tuple[list[tuple[str, str]], str]:
    """
    Parse a JSON dot-path into Rego iteration and leaf-access expressions.

    Returns:
        iterations: list of (variable, collection_expr) for ``some var in ...``
        leaf_expr:  Rego expression to access the leaf value

    Examples:
        "._type"
            → ([], "input._type")
        ".predicate.builder.id"
            → ([], "input.predicate.builder.id")
        ".predicate.buildConfig.tasks[*].status"
            → ([("task", "input.predicate.buildConfig.tasks")], "task.status")
        ".predicate.buildConfig.tasks[*].results[*].name"
            → ([("task","input.predicate.buildConfig.tasks"),
                 ("result","task.results")], "result.name")
        ".predicate.invocation.parameters.git-url"
            → ([], 'input.predicate.invocation.parameters["git-url"]')
    """
    segments = input_path.lstrip(".").split(".")
    iterations: list[tuple[str, str]] = []
    prefix = "input"

    for i, seg in enumerate(segments):
        if "[*]" in seg:
            array_name = seg.replace("[*]", "")
            collection = f"{prefix}.{array_name}"
            var = _VAR_HINTS.get(array_name, f"item_{i}")
            iterations.append((var, collection))
            prefix = var
        elif "-" in seg:
            prefix = f'{prefix}["{seg}"]'
        else:
            prefix = f"{prefix}.{seg}"

    return iterations, prefix


def _get_leaf_value(data: Any, path: str) -> Any:
    """Follow a JSON path through nested dict/list, return the leaf value."""
    segments = path.lstrip(".").split(".")
    current = data
    for seg in segments:
        seg_clean = seg.replace("[*]", "")
        if isinstance(current, dict) and seg_clean in current:
            current = current[seg_clean]
        elif isinstance(current, list) and current:
            current = current[0]
            if isinstance(current, dict) and seg_clean in current:
                current = current[seg_clean]
            else:
                return None
        else:
            return None
    return current


def _rego_literal(value: Any) -> str:
    """Format a Python value as a Rego literal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, (int, float)):
        return str(value)
    return repr(value)


def _determine_check_type(instruction: str) -> str:
    """Determine whether the instruction asks for equality or presence check."""
    # Order matters: more specific patterns first
    if "is missing or empty" in instruction:
        return "presence"
    if "is missing or does not match" in instruction:
        return "presence"
    if "is missing or is not" in instruction:
        return "presence"
    if "is missing" in instruction:
        return "presence"
    if "is not" in instruction:
        return "equality"
    return "presence"


# ─── Tier 1 rule generation ──────────────────────────────────────────────────

def _generate_tier1_rule(inst: dict) -> str:
    """Generate a Rego rule for a Tier 1 (single-field) instruction."""
    pkg = inst["package_name"]
    path = inst["input_paths"][0]
    instruction = inst["instruction"]
    mock = inst["mock_data"]

    iterations, leaf_expr = _parse_path(path)
    check_type = _determine_check_type(instruction)
    leaf_value = _get_leaf_value(mock, path)

    # Build the deny rule body lines
    body_lines: list[str] = []

    # Add iteration lines
    for var, collection in iterations:
        body_lines.append(f"some {var} in {collection}")

    # Field name for human-readable message
    field_short = path.split(".")[-1].replace("[*]", "")

    if check_type == "equality":
        rego_val = _rego_literal(leaf_value)
        body_lines.append(f"{leaf_expr} != {rego_val}")
        if isinstance(leaf_value, bool):
            body_lines.append(f'msg := "{field_short} must be {_rego_literal(leaf_value)}"')
        else:
            # Escape any quotes in the expected value for the format string
            escaped_val = str(leaf_value).replace('"', '\\"')
            body_lines.append(
                f'msg := sprintf("{field_short} is %v, expected {escaped_val}", [{leaf_expr}])'
            )
    else:  # presence
        body_lines.append(f"not {leaf_expr}")
        body_lines.append(f'msg := "{field_short} is missing"')

    # Assemble the rule
    lines = [
        f"package {pkg}",
        "",
        "import rego.v1",
        "",
        "deny contains msg if {",
    ]
    for bl in body_lines:
        lines.append(f"\t{bl}")
    lines.append("}")
    lines.append("")
    return "\n".join(lines) + "\n"


# ─── Tier 2 rule generation ──────────────────────────────────────────────────

# Tier 2 rules are hand-crafted since each one has unique logic.
_TIER2_RULES: dict[str, str] = {}

_TIER2_RULES["all_tasks_succeeded"] = textwrap.dedent("""\
    package all_tasks_succeeded

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \ttask.status != "Succeeded"
    \tmsg := sprintf("task %v has status %v, expected Succeeded", [task.name, task.status])
    }
""")

_TIER2_RULES["all_tasks_bundles_resolver"] = textwrap.dedent("""\
    package all_tasks_bundles_resolver

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \ttask.ref.resolver != "bundles"
    \tmsg := sprintf("task %v uses resolver %v, expected bundles", [task.name, task.ref.resolver])
    }
""")

_TIER2_RULES["all_tasks_have_name"] = textwrap.dedent("""\
    package all_tasks_have_name

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \tnot task.name
    \tmsg := "task is missing name field"
    }
""")

_TIER2_RULES["all_tasks_have_service_account"] = textwrap.dedent("""\
    package all_tasks_have_service_account

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \tnot task.serviceAccountName
    \tmsg := "task is missing serviceAccountName"
    }

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \ttask.serviceAccountName == ""
    \tmsg := sprintf("task %v has empty serviceAccountName", [task.name])
    }
""")

_TIER2_RULES["all_tasks_have_timestamps"] = textwrap.dedent("""\
    package all_tasks_have_timestamps

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \tnot task.startedOn
    \tmsg := sprintf("task %v is missing startedOn", [task.name])
    }

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \tnot task.finishedOn
    \tmsg := sprintf("task %v is missing finishedOn", [task.name])
    }
""")

_TIER2_RULES["all_task_refs_have_required_params"] = textwrap.dedent("""\
    package all_task_refs_have_required_params

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \tparam_names := {p.name | some p in task.ref.params}
    \trequired := {"name", "bundle", "kind"}
    \tmissing := required - param_names
    \tcount(missing) > 0
    \tmsg := sprintf("task %v is missing required ref params: %v", [task.name, missing])
    }
""")

_TIER2_RULES["all_subjects_have_digest"] = textwrap.dedent("""\
    package all_subjects_have_digest

    import rego.v1

    deny contains msg if {
    \tsome subject in input.subject
    \tnot subject.digest.sha256
    \tmsg := "subject is missing digest.sha256"
    }
""")

_TIER2_RULES["all_subjects_have_name"] = textwrap.dedent("""\
    package all_subjects_have_name

    import rego.v1

    deny contains msg if {
    \tsome subject in input.subject
    \tnot subject.name
    \tmsg := "subject is missing name field"
    }
""")

_TIER2_RULES["all_materials_have_digest"] = textwrap.dedent("""\
    package all_materials_have_digest

    import rego.v1

    deny contains msg if {
    \tsome material in input.predicate.materials
    \tnot material.digest
    \tmsg := "material is missing digest"
    }
""")

_TIER2_RULES["all_materials_have_uri"] = textwrap.dedent("""\
    package all_materials_have_uri

    import rego.v1

    deny contains msg if {
    \tsome material in input.predicate.materials
    \tnot material.uri
    \tmsg := "material is missing uri field"
    }
""")

_TIER2_RULES["build_tasks_have_image_digest_result"] = textwrap.dedent("""\
    package build_tasks_have_image_digest_result

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \tstartswith(task.name, "build-container")
    \tnot _has_result(task, "IMAGE_DIGEST")
    \tmsg := sprintf("build task %v is missing IMAGE_DIGEST result", [task.name])
    }

    _has_result(task, name) if {
    \tsome result in task.results
    \tresult.name == name
    }
""")

_TIER2_RULES["all_tasks_have_steps"] = textwrap.dedent("""\
    package all_tasks_have_steps

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \tnot task.steps
    \tmsg := sprintf("task %v is missing steps", [task.name])
    }

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \ttask.steps
    \tcount(task.steps) == 0
    \tmsg := sprintf("task %v has empty steps", [task.name])
    }
""")


# ─── Tier 3 rule generation ──────────────────────────────────────────────────

_TIER3_RULES: dict[str, str] = {}

_TIER3_RULES["image_digest_requires_succeeded"] = textwrap.dedent("""\
    package image_digest_requires_succeeded

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \t_has_image_digest(task)
    \ttask.status != "Succeeded"
    \tmsg := sprintf("task %v produces IMAGE_DIGEST but has status %v", [task.name, task.status])
    }

    _has_image_digest(task) if {
    \tsome result in task.results
    \tresult.name == "IMAGE_DIGEST"
    }
""")

_TIER3_RULES["hermetic_build_required"] = textwrap.dedent("""\
    package hermetic_build_required

    import rego.v1

    deny contains msg if {
    \tinput.predicate.invocation.parameters.hermetic != "true"
    \tmsg := "build is not hermetic at pipeline level"
    }

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \tstartswith(task.name, "build-container")
    \ttask.invocation.parameters.HERMETIC != "true"
    \tmsg := sprintf("task %v has HERMETIC=%v, expected true", [task.name, task.invocation.parameters.HERMETIC])
    }
""")

_TIER3_RULES["trusted_builder_id"] = textwrap.dedent("""\
    package trusted_builder_id

    import rego.v1

    deny contains msg if {
    \tinput.predicate.builder.id != "https://tekton.dev/chains/v2"
    \tmsg := sprintf("untrusted builder.id: %v", [input.predicate.builder.id])
    }

    deny contains msg if {
    \tinput.predicate.buildType != "tekton.dev/v1beta1/PipelineRun"
    \tmsg := sprintf("unexpected buildType: %v", [input.predicate.buildType])
    }
""")

_TIER3_RULES["subjects_match_build_results"] = textwrap.dedent("""\
    package subjects_match_build_results

    import rego.v1

    deny contains msg if {
    \tsome subject in input.subject
    \tdigest := subject.digest.sha256
    \tnot _digest_in_results(digest)
    \tmsg := sprintf("subject digest %v not found in any task IMAGE_DIGEST result", [digest])
    }

    _digest_in_results(digest) if {
    \tsome task in input.predicate.buildConfig.tasks
    \tsome result in task.results
    \tresult.name == "IMAGE_DIGEST"
    \tresult.value == sprintf("sha256:%s", [digest])
    }
""")

_TIER3_RULES["git_revision_matches_material"] = textwrap.dedent("""\
    package git_revision_matches_material

    import rego.v1

    deny contains msg if {
    \trevision := input.predicate.invocation.parameters.revision
    \tsome material in input.predicate.materials
    \tstartswith(material.uri, "git+")
    \tmaterial.digest.sha1 != revision
    \tmsg := sprintf("git material sha1 %v does not match revision %v", [material.digest.sha1, revision])
    }
""")

_TIER3_RULES["tls_verify_enabled"] = textwrap.dedent("""\
    package tls_verify_enabled

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \ttask.invocation.parameters.TLSVERIFY
    \ttask.invocation.parameters.TLSVERIFY != "true"
    \tmsg := sprintf("task %v has TLSVERIFY=%v, must be true", [task.name, task.invocation.parameters.TLSVERIFY])
    }
""")

_TIER3_RULES["build_timestamps_chronological"] = textwrap.dedent("""\
    package build_timestamps_chronological

    import rego.v1

    deny contains msg if {
    \tstarted := time.parse_rfc3339_ns(input.predicate.metadata.buildStartedOn)
    \tfinished := time.parse_rfc3339_ns(input.predicate.metadata.buildFinishedOn)
    \tstarted > finished
    \tmsg := "buildStartedOn is after buildFinishedOn"
    }
""")

_TIER3_RULES["source_repo_uses_https"] = textwrap.dedent("""\
    package source_repo_uses_https

    import rego.v1

    deny contains msg if {
    \turl := input.predicate.invocation.parameters["git-url"]
    \tnot startswith(url, "https://")
    \tmsg := sprintf("git-url %v does not use HTTPS", [url])
    }
""")

_TIER3_RULES["checks_not_skipped"] = textwrap.dedent("""\
    package checks_not_skipped

    import rego.v1

    deny contains msg if {
    \tinput.predicate.invocation.parameters["skip-checks"] == "true"
    \tmsg := "skip-checks is set to true, production builds must not skip checks"
    }
""")

_TIER3_RULES["scan_tasks_have_test_output"] = textwrap.dedent("""\
    package scan_tasks_have_test_output

    import rego.v1

    deny contains msg if {
    \tsome task in input.predicate.buildConfig.tasks
    \t_is_scan_task(task)
    \tnot _has_result(task, "TEST_OUTPUT")
    \tmsg := sprintf("scan task %v is missing TEST_OUTPUT result", [task.name])
    }

    _is_scan_task(task) if contains(task.name, "scan")

    _is_scan_task(task) if contains(task.name, "sast")

    _has_result(task, name) if {
    \tsome result in task.results
    \tresult.name == name
    }
""")


# ─── OPA validation ──────────────────────────────────────────────────────────

def _run_opa_check(task_dir: Path) -> tuple[bool, str]:
    """Run ``opa check .`` in the task directory."""
    try:
        result = subprocess.run(
            ["opa", "check", "."],
            cwd=str(task_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"ERROR: {e}"


def _run_opa_test(task_dir: Path) -> tuple[bool, str]:
    """Run ``opa test . -v`` in the task directory."""
    try:
        result = subprocess.run(
            ["opa", "test", ".", "-v"],
            cwd=str(task_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        passed = result.returncode == 0 and "FAIL" not in output
        return passed, output
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"ERROR: {e}"


# ─── Main pipeline ───────────────────────────────────────────────────────────

def _load_instructions(path: str) -> list[dict]:
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _generate_rule(inst: dict) -> str:
    """Generate a Rego rule for any instruction, dispatching by tier."""
    tier = inst["tier"]
    task_id = inst["id"]

    if tier == 2 and task_id in _TIER2_RULES:
        return _TIER2_RULES[task_id]
    if tier == 3 and task_id in _TIER3_RULES:
        return _TIER3_RULES[task_id]

    # Tier 1 (and any uncovered tier 2/3) use the template engine
    return _generate_tier1_rule(inst)


def generate_rules(
    instructions_path: str,
    tests_dir: str,
    output_dir: str,
    skip_passing: bool = False,
) -> list[dict]:
    """Run the full Phase 3 pipeline."""
    instructions = _load_instructions(instructions_path)
    tests_root = Path(tests_dir)
    out_root = Path(output_dir)

    results: list[dict] = []
    stats = {"pass": 0, "fail": 0, "skipped": 0}

    total = len(instructions)
    print(f"Phase 3: Generating Rego rules (local templates)")
    print(f"  Tasks: {total}")
    print()

    for idx, inst in enumerate(instructions, 1):
        task_id = inst["id"]
        pkg = inst["package_name"]

        # Find the test file from Phase 2
        test_file = tests_root / "tasks" / task_id / f"{pkg}_test.rego"
        if not test_file.exists():
            print(f"  [{idx}/{total}] {task_id}: SKIP (no test file)")
            stats["skipped"] += 1
            continue

        test_content = test_file.read_text(encoding="utf-8")

        # Set up output directory
        task_dir = out_root / "tasks" / task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        # Skip if already passing and --skip-passing
        result_file = task_dir / "result.json"
        if skip_passing and result_file.exists():
            try:
                existing = json.loads(result_file.read_text(encoding="utf-8"))
                if existing.get("status") == "pass":
                    print(f"  [{idx}/{total}] {task_id}: SKIP (already passing)")
                    results.append(existing)
                    stats["pass"] += 1
                    continue
            except (json.JSONDecodeError, KeyError):
                pass

        # Generate the rule
        rego_code = _generate_rule(inst)

        # Write rule + test to task directory
        rule_file = task_dir / f"{pkg}.rego"
        rule_file.write_text(rego_code, encoding="utf-8")
        (task_dir / f"{pkg}_test.rego").write_text(test_content, encoding="utf-8")

        # Validate
        result = {
            "task_id": task_id,
            "tier": inst["tier"],
            "package_name": pkg,
            "opa_check": "not_run",
            "opa_test": "not_run",
            "test_output": "",
            "errors": [],
            "status": "pending",
        }

        check_ok, check_output = _run_opa_check(task_dir)
        result["opa_check"] = "pass" if check_ok else "fail"

        if not check_ok:
            result["errors"].append(f"opa check: {check_output}")
            result["status"] = "fail"
            stats["fail"] += 1
            print(f"  [{idx}/{total}] {task_id}: CHECK FAIL")
        else:
            test_ok, test_output = _run_opa_test(task_dir)
            result["opa_test"] = "pass" if test_ok else "fail"
            result["test_output"] = test_output

            if test_ok:
                result["status"] = "pass"
                stats["pass"] += 1
                print(f"  [{idx}/{total}] {task_id}: PASS")
            else:
                result["errors"].append(f"opa test: {test_output}")
                result["status"] = "fail"
                stats["fail"] += 1
                print(f"  [{idx}/{total}] {task_id}: TEST FAIL")

        result_file.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        results.append(result)

    # Summary
    print()
    print("=" * 60)
    print(f"Phase 3 Results (local)")
    print(f"  Total:   {total}")
    print(f"  Passed:  {stats['pass']}")
    print(f"  Failed:  {stats['fail']}")
    print(f"  Skipped: {stats['skipped']}")
    processed = total - stats["skipped"]
    rate = 100 * stats["pass"] / max(1, processed)
    print(f"  Pass rate: {stats['pass']}/{processed} ({rate:.0f}%)")
    print("=" * 60)

    # Write summary
    summary_file = out_root / "summary.json"
    summary_file.write_text(
        json.dumps({"total": total, "stats": stats, "method": "local_templates"},
                   indent=2) + "\n",
        encoding="utf-8",
    )

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Phase 3: Generate Rego rules (local templates) and validate with OPA.",
    )
    parser.add_argument(
        "--instructions", type=str,
        default="phase1_instructions/output/instructions.jsonl",
        help="Path to instructions JSONL.",
    )
    parser.add_argument(
        "--tests", type=str,
        default="phase2_tests/output",
        help="Phase 2 test output directory.",
    )
    parser.add_argument(
        "--output", type=str,
        default="phase3_rules/output",
        help="Output directory.",
    )
    parser.add_argument(
        "--skip-passing", action="store_true",
        help="Skip tasks that already have a passing result.json.",
    )
    args = parser.parse_args()

    generate_rules(
        instructions_path=args.instructions,
        tests_dir=args.tests,
        output_dir=args.output,
        skip_passing=args.skip_passing,
    )


if __name__ == "__main__":
    main()
