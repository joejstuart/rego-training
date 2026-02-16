#!/usr/bin/env python3
"""
Phase 7b — deterministic quality fixes for distilled <think> traces.

This script takes rego_sft_distilled.jsonl (assembled in Phase 7a) and fixes
quality problems that were identified in a post-distillation audit:

  P0  modify_rule      (456 examples) — traces were 100% generic templates
  P1  rule_and_test    (513 examples) — traces were 100% generic templates
  P2  factual error    (~40 examples) — "empty string is falsy in Rego" (wrong)
  P3  wrong framing    (44 examples)  — test_only traces framed as rule_and_test
  P4  generic tier-2   (~116 examples) — rule_from_test / test_from_rule generic
  P5  think/code       (~9 examples)  — all_materials_have_digest mismatch

This script is DETERMINISTIC — no LLM calls, pure string processing.  Given the
same input it always produces the same output.

Usage:
    python redistill.py                          # reads/writes default paths
    python redistill.py --input X --output Y     # custom paths

Input:  output/rego_sft_distilled.jsonl   (Phase 7a output)
Output: output/rego_sft_distilled.jsonl   (overwritten in-place by default)
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_INPUT  = Path(__file__).parent / "output" / "rego_sft_distilled.jsonl"
DEFAULT_OUTPUT = DEFAULT_INPUT  # overwrite in-place


# ── helpers ───────────────────────────────────────────────────────────────────

def extract_think(content: str) -> str:
    m = re.search(r'<think>\s*(.*?)\s*</think>', content, re.DOTALL)
    return m.group(1) if m else ''


def extract_code(content: str) -> str:
    m = re.search(r'</think>\s*(.*)', content, re.DOTALL)
    return m.group(1).strip() if m else content.strip()


def replace_think(content: str, new_think: str) -> str:
    return re.sub(
        r'<think>.*?</think>',
        f'<think>\n{new_think}\n</think>',
        content, count=1, flags=re.DOTALL,
    )


def extract_user_code(user_msg: str) -> str:
    m = re.search(r'```(?:rego)?\s*\n(.*?)```', user_msg, re.DOTALL)
    return m.group(1).strip() if m else ''


def extract_instruction(user_msg: str) -> str:
    without_code = re.sub(r'```(?:rego)?\s*\n.*?```', '', user_msg, flags=re.DOTALL)
    without_code = re.sub(
        r'^(?:Here is an existing Rego rule:|I have this Rego rule:)\s*',
        '', without_code.strip(),
    )
    return without_code.strip()


def extract_package(code: str) -> str:
    m = re.search(r'^package\s+(\S+)', code, re.MULTILINE)
    return m.group(1) if m else ''


def extract_field_paths(code: str) -> list[str]:
    paths = re.findall(r'input(?:\.\w+)+(?:\[\"[^\"]+\"\])*(?:\.\w+)*', code)
    return list(dict.fromkeys(paths))


def extract_deny_messages(code: str) -> list[str]:
    msgs = re.findall(r'msg\s*:=\s*(?:sprintf\(\s*"([^"]+)"|"([^"]+)")', code)
    return [m[0] or m[1] for m in msgs]


# ── trace generators ──────────────────────────────────────────────────────────

def gen_modify_trace(ex: dict) -> str:
    """Task-specific <think> trace for modify_rule examples."""
    user_msg = ex['messages'][1]['content']
    assistant_content = ex['messages'][2]['content']
    original_code = extract_user_code(user_msg)
    modified_code = extract_code(assistant_content)

    mod_type = ex['task_id'].split('__')[-1] if '__' in ex['task_id'] else 'unknown'
    orig_pkg = extract_package(original_code)
    mod_pkg  = extract_package(modified_code)
    field_paths = extract_field_paths(original_code)
    orig_msgs = extract_deny_messages(original_code)
    mod_msgs  = extract_deny_messages(modified_code)

    orig_deny_n = len(re.findall(r'deny\s+contains\s+msg\s+if', original_code))
    mod_deny_n  = len(re.findall(r'deny\s+contains\s+msg\s+if', modified_code))
    has_iter = bool(re.search(r'some\s+\w+\s+in', original_code))

    parts: list[str] = []

    # --- describe original rule ------------------------------------------------
    if has_iter:
        m = re.search(r'some\s+(\w+)\s+in\s+([\w.]+)', original_code)
        if m:
            parts.append(
                f"The original rule in package `{orig_pkg}` iterates over "
                f"`{m.group(2)}` using `some {m.group(1)} in ...` and validates each element."
            )
        else:
            parts.append(
                f"The original rule in package `{orig_pkg}` iterates over a "
                f"collection to validate elements."
            )
    elif field_paths:
        parts.append(f"The original rule in package `{orig_pkg}` checks `{field_paths[0]}`.")
    else:
        parts.append(f"The original rule in package `{orig_pkg}` performs a field-level validation.")

    if orig_deny_n > 1:
        parts.append(f"It has {orig_deny_n} deny rules.")

    # --- describe modification -------------------------------------------------
    if mod_type == 'rename_package':
        parts.append(f"\n**Modification**: Rename the package from `{orig_pkg}` to `{mod_pkg}`.")
        parts.append(
            "This is a straightforward change to the `package` declaration on line 1. "
            "All rule logic, imports, and deny messages remain identical — only the namespace changes."
        )
        parts.append("The deny messages are independent of the package name, so no message changes needed.")

    elif mod_type == 'improve_message':
        parts.append('\n**Modification**: Improve the deny messages by adding a `"VIOLATION: "` prefix.')
        if orig_msgs:
            parts.append(f'The original message is: `"{orig_msgs[0]}"`')
        if mod_msgs:
            parts.append(f'The updated message becomes: `"{mod_msgs[0]}"`')
        parts.append(
            "In Rego, this means updating the format string inside `sprintf()` (or the raw string literal). "
            "The `VIOLATION:` prefix makes policy violations immediately identifiable in logs and CI output."
        )
        if orig_deny_n > 1:
            parts.append(f"Since there are {orig_deny_n} deny rules, each message string needs the prefix added.")

    elif mod_type == 'change_value':
        ov = re.findall(r'!=\s*"([^"]+)"', original_code)
        mv = re.findall(r'!=\s*"([^"]+)"', modified_code)
        if ov and mv:
            parts.append(f'\n**Modification**: Change the expected value from `"{ov[0]}"` to `"{mv[0]}"`.')
            parts.append("Two things must change in sync:")
            parts.append(f'1. The comparison: `!= "{ov[0]}"` → `!= "{mv[0]}"`')
            parts.append("2. The deny message: update the sprintf format string to show the new expected value")
            parts.append(
                "Keeping these in sync is important — a mismatch between what the rule checks "
                "and what the message reports would confuse operators."
            )
        else:
            parts.append("\n**Modification**: Change the expected value in the comparison and update the deny message to match.")

    elif mod_type == 'add_missing_check':
        parts.append("\n**Modification**: Add a new deny rule that fires when the field is missing (undefined).")
        if field_paths:
            parts.append(
                f"The original rule checks when `{field_paths[0]}` has a wrong value, "
                f"but doesn't handle the case where the field doesn't exist at all."
            )
            parts.append(
                "In Rego, accessing a missing key returns `undefined`, which silently fails "
                "the comparison — the original `!=` check would NOT fire for a missing field."
            )
            parts.append(
                f"The new rule uses `not {field_paths[0]}` to explicitly catch the undefined "
                f'case with a clear "field is missing" message.'
            )
        parts.append(f"After this change, the package has {mod_deny_n} deny rules: one for wrong values, one for missing fields.")

    elif mod_type == 'relax_to_allowlist':
        ov = re.findall(r'!=\s*"([^"]+)"', original_code)
        allowlist_raw = re.findall(r'\{([^}]+)\}', modified_code)
        av = re.findall(r'"([^"]+)"', allowlist_raw[0]) if allowlist_raw else []
        parts.append("\n**Modification**: Replace single-value check with a set-based allowlist.")
        if ov:
            parts.append(f'The original rule only accepts `"{ov[0]}"`. The new version accepts any value in the allowlist set.')
        if av:
            parts.append(f"Allowed values: {', '.join(f'`\"{v}\"`' for v in av)}")
        parts.append("In Rego, this means:")
        if av:
            parts.append(f'1. Define a set literal: `allowed := {{"{"\", \"".join(av)}"}}` ')
        else:
            parts.append("1. Define an allowed set")
        parts.append("2. Replace `!=` with `not X in allowed` — this checks set membership")
        parts.append("3. Update the deny message to show the full allowed set instead of a single expected value")

    else:
        instruction = extract_instruction(user_msg)
        parts.append(f"\n**Modification**: {instruction[:200]}")

    # --- changes summary -------------------------------------------------------
    changes: list[str] = []
    if orig_pkg != mod_pkg:
        changes.append(f"package renamed: `{orig_pkg}` → `{mod_pkg}`")
    for om, mm in zip(orig_msgs, mod_msgs):
        if om != mm:
            changes.append(f'message changed: "{om}" → "{mm}"')
    for mm in mod_msgs[len(orig_msgs):]:
        changes.append(f'new message added: "{mm}"')
    if mod_deny_n > orig_deny_n:
        changes.append(f"added {mod_deny_n - orig_deny_n} new deny rule(s)")
    # Set membership introduction
    if '{' in modified_code and '{' not in original_code:
        sets = re.findall(r'\{([^}]+)\}', modified_code)
        for s in sets:
            if '"' in s and ',' in s:
                changes.append("introduced allowlist set")
                break
    # `not X in Y` pattern
    if 'not' in modified_code and 'in' in modified_code and (
        'not' not in original_code or 'in' not in original_code
    ):
        changes.append("uses set membership check (`not X in allowed`)")
    # `not field` pattern (missing-field check)
    # Match `not input.X.Y` and `not input.X["key"]` etc., but stop at
    # bracket-quoted keys to match the original script's behaviour.
    not_pat = r'not\s+input(?:\.\w+)+'
    new_nots = [
        p for p in re.findall(not_pat, modified_code)
        if p not in re.findall(not_pat, original_code)
    ]
    if new_nots:
        changes.append(f"added missing-field check: `{new_nots[0]}`")
    # Value changes
    ov_all = re.findall(r'!=\s*"([^"]+)"', original_code)
    mv_all = re.findall(r'!=\s*"([^"]+)"', modified_code)
    if ov_all and mv_all and ov_all != mv_all:
        for o, m in zip(ov_all, mv_all):
            if o != m:
                changes.append(f'expected value changed: `"{o}"` → `"{m}"`')
    if changes:
        parts.append(f"\n**Changes applied**: " + "; ".join(changes) + ".")

    return "\n".join(parts)


def gen_rule_and_test_trace(
    ex: dict,
    rule_only_traces: dict[str, str],
    test_only_traces: dict[str, str],
) -> str:
    """Compose rule_and_test trace from good rule_only + test info."""
    task_id = ex['task_id']
    code = extract_code(ex['messages'][2]['content'])
    pkg  = extract_package(code)

    parts: list[str] = []
    rt = rule_only_traces.get(task_id, '')
    if rt:
        parts.append(f"**Rule implementation reasoning**:\n{rt}")
    else:
        fps = extract_field_paths(code)
        if fps:
            parts.append(f"This rule validates `{fps[0]}` in package `{pkg}`.")

    parts.append(f"\n**Test approach**: Write both positive and negative tests in package `{pkg}_test`.")
    parts.append(f"- Import the rule: `import data.{pkg}`")
    parts.append(f"- Positive test: `count({pkg}.deny) == 0` with valid input")
    parts.append(f"- Negative test: `count({pkg}.deny) > 0` with invalid input")
    parts.append(f"- Use `with input as {{...}}` to inject minimal test data covering only the fields the rule accesses.")
    return "\n".join(parts)


def gen_test_only_trace(ex: dict, test_only_traces: dict[str, str]) -> str:
    """Fix wrong-framing test_only traces."""
    task_id = ex['task_id']

    good = test_only_traces.get(task_id, '')
    if good and 'deny rule AND comprehensive tests' not in good:
        return good

    code = extract_code(ex['messages'][2]['content'])
    pkg_m = re.search(r'import\s+data\.(\S+)', code)
    pkg = pkg_m.group(1) if pkg_m else task_id
    is_helper = 'helper' in ex.get('task_type', '') or 'lib.' in pkg

    parts: list[str] = []
    if is_helper:
        parts.append(f"The user requests tests for helper functions in package `{pkg}`. "
                      "These are utility functions, not deny rules, so tests assert return "
                      "values directly rather than checking deny sets.")
        parts.append("\n**Test structure**: Each exported function needs at least one positive "
                      "test (expected behavior) and one negative test (edge case or wrong input).")
        parts.append("Use `with input as {...}` only if the helpers access `input`; otherwise, pass arguments directly.")
    else:
        parts.append(f"The user requests Rego unit tests for a deny rule in package `{pkg}`.")
        tier = ex['tier']
        if tier == 2:
            parts.append(f"\n**Tier 2 collection validation**: The rule iterates over a collection "
                          "(e.g., tasks, materials, subjects) and checks each element. Test data must include arrays with multiple items.")
            parts.append(f"- **Positive test**: ALL items in the collection satisfy the requirement → `count({pkg}.deny) == 0`")
            parts.append(f"- **Negative test**: At least ONE item violates the requirement → `count({pkg}.deny) > 0`")
            parts.append("- Mix valid and invalid items in the negative test to verify the rule catches "
                          "individual violations without false positives on valid items.")
        elif tier == 3:
            parts.append(f"\n**Tier 3 complex validation**: The rule may use helper functions, "
                          "cross-field references, or nested structures. Test data needs to be comprehensive.")
            parts.append(f"- **Positive test**: `count({pkg}.deny) == 0` with fully valid input")
            parts.append(f"- **Negative test**: `count({pkg}.deny) > 0` targeting a specific failure mode")
            parts.append("- The test data may need to include nested objects, arrays of arrays, or cross-referencing structures.")
        else:
            parts.append("\n**Test structure**: Write positive and negative tests.")
            parts.append(f"- **Positive test**: `count({pkg}.deny) == 0` with valid input")
            parts.append(f"- **Negative test**: `count({pkg}.deny) > 0` with invalid input")
        parts.append(f"\nUse `with input as {{...}}` to inject minimal test data. "
                      f"Import the package under test with `import data.{pkg}`.")
    return "\n".join(parts)


def gen_rule_from_test_trace(ex: dict, rule_only_traces: dict[str, str]) -> str:
    """TDD framing + rule reasoning for rule_from_test."""
    task_id = ex['task_id']
    code = extract_code(ex['messages'][2]['content'])
    pkg  = extract_package(code)
    fps  = extract_field_paths(code)

    parts = [
        "The user provides Rego tests and asks me to write the rule that passes them. "
        "This is test-driven development: the tests define the specification.",
        "\n**Approach**: Analyze the test assertions and test data to reverse-engineer the rule logic:",
        "1. The positive test shows what VALID input looks like → the rule must NOT fire for this data",
        "2. The negative test shows what INVALID input looks like → the rule MUST fire for this data",
        "3. Compare the two to identify which field/value triggers the denial",
    ]

    rt = rule_only_traces.get(task_id, '')
    if rt:
        parts.append(f"\n**Rule logic**: {rt}")
    elif fps:
        parts.append(f"\n**Key field**: `{fps[0]}`")
        parts.append(f"The rule in package `{pkg}` validates this field and denies when the value is wrong or missing.")
    return "\n".join(parts)


def gen_test_from_rule_trace(ex: dict, test_only_traces: dict[str, str]) -> str:
    """Given-rule framing + test reasoning for test_from_rule."""
    task_id = ex['task_id']
    user_code = extract_user_code(ex['messages'][1]['content'])
    pkg = extract_package(user_code)
    fps = extract_field_paths(user_code)
    has_iter = bool(re.search(r'some\s+\w+\s+in', user_code))
    deny_msgs = extract_deny_messages(user_code)

    parts = [
        "The user provides a Rego deny rule and asks me to write tests for it. "
        "I need to analyze the rule to design appropriate test cases.",
        f"\n**Rule analysis** (package `{pkg}`):",
    ]
    if fps:
        parts.append(f"- Accesses: {', '.join(f'`{fp}`' for fp in fps[:3])}")
    if has_iter:
        parts.append("- Uses collection iteration (`some X in ...`) — tests need arrays with multiple elements")
    if deny_msgs:
        parts.append(f'- Deny message: `"{deny_msgs[0]}"`')

    tt = test_only_traces.get(task_id, '')
    if tt and 'deny rule AND' not in tt:
        parts.append(f"\n**Test strategy**: {tt}")
    else:
        parts.append("\n**Test design**:")
        parts.append(f"- Positive: `count({pkg}.deny) == 0` — provide valid values for all fields the rule checks")
        parts.append(f"- Negative: `count({pkg}.deny) > 0` — violate the condition the rule enforces")
        parts.append("- Use `with input as {...}` with minimal data covering only accessed fields")
    return "\n".join(parts)


# ── targeted fixes ────────────────────────────────────────────────────────────

def fix_service_account_trace(think: str) -> str:
    """P2: Fix factual error — empty string is NOT falsy in Rego."""
    think = think.replace(
        'not ""` → true (empty string is falsy in Rego) ✓',
        'not ""` → false (empty string IS a defined value in Rego, so `not` does not catch it)',
    )
    think = think.replace(
        'empty string is falsy in Rego',
        'empty string is a defined value in Rego (not undefined)',
    )
    think = think.replace(
        'both cases could be caught by rule 1 alone!',
        "rule 1 only catches truly undefined fields, not empty strings — that's why rule 2 is needed!",
    )
    return think


def fix_materials_digest_trace(think: str) -> str:
    """P5: Fix think/code mismatch for all_materials_have_digest."""
    think = re.sub(
        r'The instruction says.*?first-level check\.',
        'The implementation checks whether the `digest` object is missing entirely from each material.',
        think, flags=re.DOTALL,
    )
    think = re.sub(
        r'But the instruction wants.*?first-level check\.',
        (
            'The implementation checks `not material.digest` which catches materials where the '
            'digest object is completely absent. This is the right level of validation — if the '
            'digest object exists but is empty or missing specific algorithms, that would be a '
            'separate, more granular check.'
        ),
        think, flags=re.DOTALL,
    )
    return think


# ── main ──────────────────────────────────────────────────────────────────────

GENERIC_MARKERS = [
    "The user provides existing Rego code and requests a modification. I need to analyze the original code structure",
    "The user requests both a Rego deny rule AND comprehensive tests in a single response",
]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input",  type=Path, default=DEFAULT_INPUT,  help="Input JSONL")
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output JSONL")
    args = ap.parse_args()

    examples: list[dict] = []
    with open(args.input) as f:
        for line in f:
            examples.append(json.loads(line))
    print(f"Loaded {len(examples)} examples from {args.input}")

    # ── build lookup tables of GOOD traces ────────────────────────────────
    rule_only_traces: dict[str, str] = {}
    test_only_traces: dict[str, str] = {}

    for ex in examples:
        think = extract_think(ex['messages'][2]['content'])
        is_generic = any(p in think for p in GENERIC_MARKERS)
        if ex['type'] == 'rule_only' and not is_generic:
            if ex['task_id'] not in rule_only_traces or len(think) > len(rule_only_traces[ex['task_id']]):
                rule_only_traces[ex['task_id']] = think
        if ex['type'] == 'test_only' and not is_generic:
            if ex['task_id'] not in test_only_traces or len(think) > len(test_only_traces[ex['task_id']]):
                test_only_traces[ex['task_id']] = think

    # Apply P2/P5 fixes to lookup tables BEFORE composing derived traces
    for tid in list(rule_only_traces):
        t = rule_only_traces[tid]
        if tid == 'all_tasks_have_service_account' and 'empty string is falsy' in t:
            rule_only_traces[tid] = fix_service_account_trace(t)
        if tid == 'all_materials_have_digest' and 'sha256' in t:
            rule_only_traces[tid] = fix_materials_digest_trace(t)

    print(f"Good rule_only traces: {len(rule_only_traces)}")
    print(f"Good test_only traces: {len(test_only_traces)}")

    # ── process each example ──────────────────────────────────────────────
    stats: dict[str, int] = defaultdict(int)

    for ex in examples:
        think = extract_think(ex['messages'][2]['content'])
        is_generic = any(p in think for p in GENERIC_MARKERS)
        new_think: str | None = None

        if ex['type'] == 'modify_rule':
            new_think = gen_modify_trace(ex)
            stats['modify_rule'] += 1

        elif ex['type'] == 'rule_and_test':
            new_think = gen_rule_and_test_trace(ex, rule_only_traces, test_only_traces)
            stats['rule_and_test'] += 1

        elif ex['type'] == 'test_only' and 'deny rule AND comprehensive tests' in think:
            new_think = gen_test_only_trace(ex, test_only_traces)
            stats['test_only_wrong_frame'] += 1

        elif ex['type'] == 'rule_from_test' and is_generic:
            new_think = gen_rule_from_test_trace(ex, rule_only_traces)
            stats['rule_from_test'] += 1

        elif ex['type'] == 'test_from_rule' and is_generic:
            new_think = gen_test_from_rule_trace(ex, test_only_traces)
            stats['test_from_rule'] += 1

        elif ex['task_id'] == 'all_tasks_have_service_account' and 'empty string is falsy' in think:
            new_think = fix_service_account_trace(think)
            stats['factual_fix'] += 1

        elif ex['task_id'] == 'all_materials_have_digest' and ex['type'] == 'rule_only' and 'sha256' in think:
            new_think = fix_materials_digest_trace(think)
            stats['mismatch_fix'] += 1

        if new_think is not None:
            ex['messages'][2]['content'] = replace_think(ex['messages'][2]['content'], new_think)

    # ── write output ──────────────────────────────────────────────────────
    with open(args.output, 'w') as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + '\n')

    total_changed = sum(stats.values())
    print(f"\nRe-distillation complete → {args.output}")
    print(f"Changes by category:")
    for cat, count in sorted(stats.items()):
        print(f"  {cat}: {count}")
    print(f"  TOTAL changed: {total_changed}")
    print(f"  Unchanged:     {len(examples) - total_changed}")


if __name__ == '__main__':
    main()
