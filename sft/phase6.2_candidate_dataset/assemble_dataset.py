#!/usr/bin/env python3
"""Phase 6.2: assemble candidate tasks into messages-format SFT records."""

from __future__ import annotations

import json
import random
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SFT_ROOT = SCRIPT_DIR.parent
PHASE61_TASKS = SFT_ROOT / "phase6.1_policy_candidates" / "output" / "tasks"
OUTPUT_DIR = SCRIPT_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "policy_candidates_sft.jsonl"
random.seed(42)

SYSTEM_PROMPT = """\
You are an expert in the Rego policy language (Open Policy Agent). You write policy code for SLSA provenance checks.

Conventions:
- Use `import rego.v1`.
- If requested behavior is policy decision logic, write `deny contains msg if { ... }`.
- If requested behavior is reusable logic, write a standalone helper function/rule.
- Use `some x in collection` for iteration when needed.
- For deny-rule tests: use `count(<pkg>.deny) == 0` and `count(<pkg>.deny) > 0`.
- For helper tests: assert helper return values directly.
"""


def _load_text(path: Path) -> str:
    with open(path) as f:
        return f.read().strip()


def _make_messages(user: str, assistant_code: str, think: str) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
        {"role": "assistant", "content": f"<think>\n{think}\n</think>\n\n{assistant_code}"},
    ]


def _instruction_for(task_id: str, task_type: str, out_type: str, rule: str, test: str) -> str:
    if out_type == "rule_only":
        if task_type == "deny_rule":
            return f"Write a Rego deny rule in package `{task_id}` that satisfies the expected checks."
        return f"Write a standalone Rego helper method in package `{task_id}` that satisfies the expected checks."
    if out_type == "test_only":
        return f"Write positive and negative Rego tests for package `{task_id}`."
    if out_type == "rule_and_test":
        return f"Write Rego code and tests for package `{task_id}`."
    if out_type == "rule_from_test":
        return f"Given these tests:\n```rego\n{test}\n```\n\nWrite the Rego code that passes them."
    return f"Given this Rego code:\n```rego\n{rule}\n```\n\nWrite positive and negative tests."


def _helper_variant_prompts(task_id: str, out_type: str, rule: str, test: str) -> list[tuple[str, str]]:
    if out_type == "rule_only":
        return [
            ("phase6_helper_canonical", f"Write a standalone Rego helper method in package `{task_id}` that satisfies the expected checks."),
            ("phase6_helper_terse", f"Implement helper logic for `{task_id}`."),
            ("phase6_helper_reuse", f"Create a reusable helper function in package `{task_id}` with deterministic return behavior."),
        ]
    if out_type == "test_only":
        return [
            ("phase6_helper_canonical", f"Write positive and negative Rego tests for helper package `{task_id}`."),
            ("phase6_helper_behavior", f"Write tests that verify helper behavior (expected and failure cases) for `{task_id}`."),
        ]
    if out_type == "rule_and_test":
        return [
            ("phase6_helper_canonical", f"Write helper code and tests for package `{task_id}`."),
            ("phase6_helper_spec", f"Implement the helper in `{task_id}` and include tests that prove deterministic outputs."),
        ]
    if out_type == "rule_from_test":
        return [
            ("phase6_helper_canonical", f"Given these helper tests:\n```rego\n{test}\n```\n\nWrite the standalone helper code that passes them."),
            ("phase6_helper_inverse", f"Derive the helper implementation from these tests:\n```rego\n{test}\n```\n\nReturn only Rego code."),
        ]
    return [
        ("phase6_helper_canonical", f"Given this helper code:\n```rego\n{rule}\n```\n\nWrite positive and negative helper tests."),
        ("phase6_helper_inverse", f"Read this helper implementation and produce tests that validate expected and failing behavior:\n```rego\n{rule}\n```"),
    ]


def _think_for(task_type: str, out_type: str) -> str:
    base = (
        "I should produce a deny rule with clear failure semantics."
        if task_type == "deny_rule"
        else "I should produce a reusable helper with deterministic return behavior."
    )
    if out_type == "test_only":
        return base + " I will create one passing and one failing test case."
    if out_type == "rule_and_test":
        return base + " Then I will add tests that validate both positive and negative behavior."
    if out_type == "rule_from_test":
        return base + " I will infer required behavior from test expectations."
    if out_type == "test_from_rule":
        return base + " I will derive tests directly from rule semantics."
    return base


def assemble() -> list[dict]:
    examples = []
    for task_dir in sorted(PHASE61_TASKS.iterdir()):
        if not task_dir.is_dir():
            continue
        result_path = task_dir / "result.json"
        meta_path = task_dir / "meta.json"
        if not result_path.exists() or not meta_path.exists():
            continue

        result = json.loads(result_path.read_text())
        if result.get("status") != "pass":
            continue
        meta = json.loads(meta_path.read_text())
        task_id = meta["task_id"]
        task_type = meta["task_type"]
        pkg = meta["package_name"]

        rule_path = task_dir / f"{pkg}.rego"
        test_path = task_dir / f"{pkg}_test.rego"
        if not rule_path.exists() or not test_path.exists():
            continue
        rule_code = _load_text(rule_path)
        test_code = _load_text(test_path)

        out_types = ["rule_only", "test_only", "rule_and_test", "rule_from_test", "test_from_rule"]
        for out_type in out_types:
            if task_type == "helper_method":
                prompt_variants = _helper_variant_prompts(task_id, out_type, rule_code, test_code)
            else:
                prompt_variants = [("phase6_canonical", _instruction_for(task_id, task_type, out_type, rule_code, test_code))]

            for variant_name, user in prompt_variants:
                assistant = (
                    rule_code if out_type in {"rule_only", "rule_from_test"}
                    else test_code if out_type in {"test_only", "test_from_rule"}
                    else f"{rule_code}\n---\n{test_code}"
                )
                think = _think_for(task_type, out_type)
                examples.append({
                    "messages": _make_messages(user, assistant, think),
                    "task_id": task_id,
                    "tier": 3,
                    "variant": variant_name,
                    "type": out_type,
                    "task_type": task_type,
                    "source": "phase6_policy_candidates",
                })

    random.shuffle(examples)
    return examples


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    examples = assemble()
    with open(OUTPUT_FILE, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"Wrote {len(examples)} examples to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
