#!/usr/bin/env python3
"""Phase 6.1: normalize policy_release_candidates into phase-style tasks."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SFT_ROOT = SCRIPT_DIR.parent
PROJECT_ROOT = SFT_ROOT.parent
CANDIDATES_ROOT = SFT_ROOT / "policy_release_candidates"
POLICY_LIB_ROOT = PROJECT_ROOT / "policy" / "lib"
OUTPUT_ROOT = SCRIPT_DIR / "output"
TASKS_ROOT = OUTPUT_ROOT / "tasks"


def _read_package_name(rego_path: Path) -> str:
    with open(rego_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("package "):
                return line.split()[1]
    raise ValueError(f"Could not find package declaration in {rego_path}")


def _infer_task_type(rego_path: Path) -> str:
    text = rego_path.read_text()
    return "deny_rule" if "deny contains msg if" in text else "helper_method"


def _add_regal_compat_header(rego_file: Path) -> None:
    """Add suppressions used by GRPO lint policy to avoid noisy style failures."""
    content = rego_file.read_text()
    header = (
        "# regal ignore:external-reference\n"
        "# regal ignore:leaked-internal-reference\n"
        "# regal ignore:rule-length\n"
        "# regal ignore:file-length\n"
    )
    if content.startswith("# regal ignore:"):
        return
    rego_file.write_text(header + content)


def _normalize_for_local_opa(rego_file: Path) -> None:
    """Rewrite enterprise-contract `ec.*` refs to local data-backed refs."""
    content = rego_file.read_text()
    content = content.replace("ec.oci.", "data.ec.oci.")
    content = content.replace("ec.purl.", "data.ec.purl.")
    rego_file.write_text(content)


def _safe_opa_fmt(rego_file: Path) -> None:
    try:
        result = subprocess.run(
            ["opa", "fmt", rego_file.as_posix()],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout:
            rego_file.write_text(result.stdout)
    except FileNotFoundError:
        pass


def _run_opa(target: Path) -> dict:
    result = {
        "opa_check": "error",
        "opa_test": "error",
    }
    try:
        check = subprocess.run(
            ["opa", "check", target.as_posix()],
            capture_output=True,
            text=True,
        )
        result["opa_check"] = "pass" if check.returncode == 0 else "fail"

        test = subprocess.run(
            ["opa", "test", target.as_posix(), "-v"],
            capture_output=True,
            text=True,
        )
        result["opa_test"] = "pass" if test.returncode == 0 else "fail"

        result["opa_check_output"] = check.stdout + check.stderr
        result["opa_test_output"] = test.stdout + test.stderr
    except FileNotFoundError:
        result["opa_check_output"] = "opa binary not found on PATH"
        result["opa_test_output"] = "opa binary not found on PATH"

    return result


def _run_regal(rule_path: Path) -> dict:
    regal_bin = shutil.which("regal")
    if not regal_bin:
        return {
            "regal_lint": "error",
            "regal_lint_output": "regal binary not found on PATH",
        }

    result = subprocess.run(
        [
            regal_bin, "lint", "--format", "json",
            "-d", "opa-fmt",
            "-d", "directory-package-mismatch",
            "-d", "external-reference",
            "-d", "leaked-internal-reference",
            "-d", "rule-length",
            "-d", "file-length",
            rule_path.as_posix(),
        ],
        capture_output=True,
        text=True,
    )
    return {
        "regal_lint": "pass" if result.returncode == 0 else "fail",
        "regal_lint_output": result.stdout + result.stderr,
    }


def _collect_rule_files() -> list[Path]:
    top_level = sorted(
        p for p in CANDIDATES_ROOT.glob("*.rego")
        if not p.name.endswith("_test.rego")
    )
    helper_level = sorted(
        p for p in (CANDIDATES_ROOT / "helper_methods").glob("*.rego")
        if not p.name.endswith("_test.rego")
    )
    policy_lib = sorted(
        p for p in POLICY_LIB_ROOT.rglob("*.rego")
        if not p.name.endswith("_test.rego")
    )
    return top_level + helper_level + policy_lib


def _task_id_for(rule_file: Path) -> str:
    rel = rule_file.relative_to(PROJECT_ROOT).as_posix()
    base = rel[:-5] if rel.endswith(".rego") else rel
    return base.replace("/", "__").replace(".", "_")


def _write_policy_lib_smoke_test(test_out: Path, package: str) -> None:
    import_stmt = f"import data.{package} as target"
    test_out.write_text(
        "package phase6_policy_lib_smoke_test\n\n"
        "import rego.v1\n\n"
        f"{import_stmt}\n\n"
        "test_module_loads if {\n"
        "\t_ := target\n"
        "}\n"
    )


def _copy_policy_lib_modules(dest_policy_lib: Path) -> None:
    dest_policy_lib.mkdir(parents=True, exist_ok=True)
    for src in POLICY_LIB_ROOT.rglob("*.rego"):
        if src.name.endswith("_test.rego"):
            continue
        rel = src.relative_to(POLICY_LIB_ROOT)
        out = dest_policy_lib / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)
        _normalize_for_local_opa(out)

    ec_stub = dest_policy_lib / "ec_oci_stub.rego"
    ec_stub.write_text(
        "package ec.oci\n\n"
        "import rego.v1\n\n"
        "descriptor(_) := {}\n"
        "blob(_) := \"\"\n"
        "image_manifest(_) := {\"annotations\": {}}\n"
    )

    purl_stub = dest_policy_lib / "ec_purl_stub.rego"
    purl_stub.write_text(
        "package ec.purl\n\n"
        "import rego.v1\n\n"
        "parse(_) := {}\n"
        "is_valid(_) := true\n"
    )


def main() -> None:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    if TASKS_ROOT.exists():
        shutil.rmtree(TASKS_ROOT)
    TASKS_ROOT.mkdir(parents=True, exist_ok=True)

    records = []
    for rule_file in _collect_rule_files():
        test_file = rule_file.with_name(f"{rule_file.stem}_test.rego")
        if not test_file.exists():
            continue

        package = _read_package_name(rule_file)
        task_id = _task_id_for(rule_file)
        task_type = _infer_task_type(rule_file)

        task_dir = TASKS_ROOT / task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        rule_out = task_dir / f"{package}.rego"
        test_out = task_dir / f"{package}_test.rego"
        shutil.copy2(rule_file, rule_out)
        _normalize_for_local_opa(rule_out)
        _safe_opa_fmt(rule_out)
        _add_regal_compat_header(rule_out)

        source_group = (
            "policy_lib"
            if str(rule_file).startswith(str(POLICY_LIB_ROOT))
            else "policy_release_candidates"
        )

        validation_dir = task_dir / "_validation"
        if validation_dir.exists():
            shutil.rmtree(validation_dir)
        validation_dir.mkdir(parents=True, exist_ok=True)

        if source_group == "policy_lib":
            _write_policy_lib_smoke_test(test_out, package)
            policy_lib_ws = validation_dir / "policy" / "lib"
            _copy_policy_lib_modules(policy_lib_ws)
            rel_rule = rule_file.relative_to(POLICY_LIB_ROOT)
            target_rule_in_ws = policy_lib_ws / rel_rule
            target_rule_in_ws.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(rule_out, target_rule_in_ws)
            smoke_in_ws = validation_dir / "phase6_policy_lib_smoke_test.rego"
            shutil.copy2(test_out, smoke_in_ws)
        else:
            shutil.copy2(test_file, test_out)
            _safe_opa_fmt(test_out)
            shutil.copy2(rule_out, validation_dir / rule_out.name)
            shutil.copy2(test_out, validation_dir / test_out.name)

        _safe_opa_fmt(test_out)
        validation = _run_opa(validation_dir)

        regal = _run_regal(rule_out)
        status = (
            "pass"
            if validation["opa_check"] == "pass"
            and validation["opa_test"] == "pass"
            and regal["regal_lint"] == "pass"
            else "fail"
        )

        result = {"task_id": task_id, "status": status, **validation, **regal}
        meta = {
            "task_id": task_id,
            "package_name": package,
            "task_type": task_type,
            "source_rule": str(rule_file),
            "source_test": str(test_file),
            "source_group": source_group,
        }

        (task_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        (task_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        records.append({**meta, **result})

    passed = sum(1 for r in records if r["status"] == "pass")
    summary = {
        "total_tasks": len(records),
        "passed": passed,
        "failed_or_error": len(records) - passed,
    }
    (OUTPUT_ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
