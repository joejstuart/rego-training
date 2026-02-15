#!/usr/bin/env python3
"""Phase 6.2: assemble candidate tasks into messages-format SFT records.

Reads validated Phase 6.1 tasks and produces Qwen3 ``messages`` JSONL
records for SFT training.  Each record includes:

- ``messages``  – system / user / assistant conversation
- ``task_id``   – unique task identifier
- ``tier``      – fixed to 3 (supplemental data)
- ``variant``   – prompt style label
- ``type``      – output type (rule_only, test_only, etc.)
- ``task_type`` – deny_rule or helper_method
- ``source``    – ``phase6_policy_candidates``
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SFT_ROOT = SCRIPT_DIR.parent
REPO_ROOT = SFT_ROOT.parent
PHASE61_TASKS = SFT_ROOT / "phase6.1_policy_candidates" / "output" / "tasks"
OUTPUT_DIR = SCRIPT_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "policy_candidates_sft.jsonl"
random.seed(42)

# Ensure repo root is on sys.path for cross-package imports
import sys  # noqa: E402
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------------------
# Use the SAME canonical system prompt as Phase 4
# ---------------------------------------------------------------------------
from sft.phase4_dataset.assemble_dataset import SYSTEM_PROMPT  # noqa: E402


# ---------------------------------------------------------------------------
# Behavioral description extraction (shared with GRPO builder)
# ---------------------------------------------------------------------------
from grpo.build_dataset import (  # noqa: E402
    _extract_func_descriptions,
    _build_helper_description,
    _build_deny_description,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_text(path: Path) -> str:
    with open(path) as f:
        return f.read().strip()


def _make_messages(user: str, assistant_code: str, think: str) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
        {"role": "assistant", "content": f"<think>\n{think}\n</think>\n\n{assistant_code}"},
    ]


# ---------------------------------------------------------------------------
# Prompt generators — use package name and behavioral descriptions
# ---------------------------------------------------------------------------

def _instruction_for(
    pkg: str,
    task_type: str,
    out_type: str,
    rule_code: str,
    test_code: str,
) -> str:
    """Build the user instruction for deny-rule tasks."""
    if out_type == "rule_only":
        return _build_deny_description(pkg, rule_code)
    if out_type == "test_only":
        return f"Write positive and negative Rego tests for the deny rules in package `{pkg}`."
    if out_type == "rule_and_test":
        return f"Write Rego deny rules and their tests for package `{pkg}`."
    if out_type == "rule_from_test":
        return (
            f"Given these tests:\n```rego\n{test_code}\n```\n\n"
            f"Write the Rego deny rules in package `{pkg}` that pass them."
        )
    # test_from_rule
    return (
        f"Given this Rego code:\n```rego\n{rule_code}\n```\n\n"
        f"Write positive and negative tests for the deny rules."
    )


def _helper_variant_prompts(
    pkg: str,
    out_type: str,
    rule_code: str,
    test_code: str,
) -> list[tuple[str, str]]:
    """Build prompt variants for helper-method tasks."""
    funcs = _extract_func_descriptions(rule_code)
    canonical_desc = _build_helper_description(pkg, funcs)
    names_only = ", ".join(f"`{f['name']}`" for f in funcs[:8])
    terse_desc = (
        f"Create helper functions in package `{pkg}`: {names_only}. No deny rules."
        if funcs else canonical_desc
    )

    if out_type == "rule_only":
        return [
            ("phase6_helper_canonical", canonical_desc),
            ("phase6_helper_terse", terse_desc),
            ("phase6_helper_reuse", (
                f"Create reusable helper logic in package `{pkg}` with "
                f"deterministic return behavior. Do not produce deny policy output."
            )),
        ]
    if out_type == "test_only":
        return [
            ("phase6_helper_canonical", (
                f"Write positive and negative Rego tests for the helper "
                f"functions in package `{pkg}`."
            )),
            ("phase6_helper_behavior", (
                f"Write tests that verify helper behavior (expected and "
                f"failure cases) for package `{pkg}`."
            )),
        ]
    if out_type == "rule_and_test":
        return [
            ("phase6_helper_canonical", (
                f"Write helper code and tests for package `{pkg}`. "
                f"Do not write deny rules."
            )),
            ("phase6_helper_spec", (
                f"Implement the helpers in package `{pkg}` and include "
                f"tests that prove deterministic outputs. No deny rules."
            )),
        ]
    if out_type == "rule_from_test":
        return [
            ("phase6_helper_canonical", (
                f"Given these helper tests:\n```rego\n{test_code}\n```\n\n"
                f"Write the standalone helper code in package `{pkg}` that passes them. "
                f"Do not produce deny rules."
            )),
            ("phase6_helper_inverse", (
                f"Derive the helper implementation from these tests:\n"
                f"```rego\n{test_code}\n```\n\n"
                f"Return only Rego code for package `{pkg}`. No deny rules."
            )),
        ]
    # test_from_rule
    return [
        ("phase6_helper_canonical", (
            f"Given this helper code:\n```rego\n{rule_code}\n```\n\n"
            f"Write positive and negative tests for the helper functions."
        )),
        ("phase6_helper_inverse", (
            f"Read this helper implementation and produce tests that "
            f"validate expected and failing behavior:\n"
            f"```rego\n{rule_code}\n```"
        )),
    ]


# ---------------------------------------------------------------------------
# Think traces — task-specific reasoning
# ---------------------------------------------------------------------------

def _think_for(
    task_type: str,
    out_type: str,
    pkg: str,
    funcs: list[dict] | None = None,
) -> str:
    """Generate a task-specific reasoning trace."""
    if task_type == "deny_rule":
        base = (
            f"I need to write deny rules for package `{pkg}`. "
            f"Each rule should use `deny contains msg if` with clear "
            f"failure messages via `sprintf`."
        )
    else:
        if funcs:
            func_list = ", ".join(f"`{f['name']}`" for f in funcs[:5])
            base = (
                f"I need to implement helper functions for package `{pkg}`: "
                f"{func_list}. Each should have deterministic return behavior. "
                f"I must not produce deny rules."
            )
        else:
            base = (
                f"I need to implement reusable helper code for package `{pkg}`. "
                f"The helpers should have deterministic return behavior. "
                f"I must not produce deny rules."
            )

    if out_type == "test_only":
        return base + (
            " I will create tests with positive cases (expected behavior) "
            "and negative cases (error/failure behavior)."
        )
    if out_type == "rule_and_test":
        return base + (
            " Then I will add tests that validate both positive and "
            "negative behavior."
        )
    if out_type == "rule_from_test":
        return base + (
            " I will infer the required behavior from the test expectations "
            "and implement code that satisfies all test cases."
        )
    if out_type == "test_from_rule":
        return base + (
            " I will derive tests directly from the implementation, "
            "covering both expected outputs and edge cases."
        )
    return base


# ---------------------------------------------------------------------------
# Main assembly
# ---------------------------------------------------------------------------

def assemble() -> list[dict]:
    examples: list[dict] = []
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

        # Pre-extract function descriptions for helpers
        funcs = (
            _extract_func_descriptions(rule_code)
            if task_type == "helper_method"
            else None
        )

        out_types = [
            "rule_only", "test_only", "rule_and_test",
            "rule_from_test", "test_from_rule",
        ]
        for out_type in out_types:
            if task_type == "helper_method":
                prompt_variants = _helper_variant_prompts(
                    pkg, out_type, rule_code, test_code,
                )
            else:
                prompt_variants = [
                    (
                        "phase6_canonical",
                        _instruction_for(
                            pkg, task_type, out_type,
                            rule_code, test_code,
                        ),
                    )
                ]

            for variant_name, user in prompt_variants:
                assistant = (
                    rule_code
                    if out_type in {"rule_only", "rule_from_test"}
                    else test_code
                    if out_type in {"test_only", "test_from_rule"}
                    else f"{rule_code}\n---\n{test_code}"
                )
                think = _think_for(task_type, out_type, pkg, funcs)
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
