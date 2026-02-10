#!/usr/bin/env python3
"""Phase 4: Assemble the SFT dataset optimized for Qwen3-4B.

For each of the 60 tasks that passed Phase 3, this script:
  1. Loads the canonical instruction (Phase 1), rule (Phase 3), and test (Phase 3).
  2. Generates 7 instruction variants × 3 output types = 21 examples per task.
  3. Adds 2 direction-reversal examples (rule→test, test→rule) per task.
  4. Formats everything in Qwen3 messages format with system prompt.
  5. Adds <think> reasoning traces to teach the model HOW to approach each problem.
  6. Runs a token-length audit with the Qwen3 tokenizer.

Output: phase4_dataset/output/rego_sft.jsonl

Each line is:
  {"messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": "<think>\\n...\\n</think>\\n\\n...code..."}
  ], "task_id": "...", "tier": N, "variant": "...", "type": "..."}

Usage:
    cd sft/
    python phase4_dataset/assemble_dataset.py

    # Inspect
    wc -l phase4_dataset/output/rego_sft.jsonl
    head -1 phase4_dataset/output/rego_sft.jsonl | python -m json.tool

    # Token audit (requires transformers + jinja2)
    python phase4_dataset/assemble_dataset.py --audit
"""

from __future__ import annotations

import argparse
import json
import random
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
OUTPUT_FILE = OUTPUT_DIR / "rego_sft.jsonl"

# Reproducible shuffling
random.seed(42)


# ===========================================================================
# System prompt
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
- Tests use `count(<pkg>.deny) == 0` for positive cases and `count(<pkg>.deny) > 0` for negative cases.\
"""


# ===========================================================================
# <think> trace generators
# ===========================================================================

def _detect_rule_patterns(rule_code: str) -> dict:
    """Analyze rule code to detect which Rego patterns are used."""
    patterns = {
        "has_iteration": "some " in rule_code and " in " in rule_code,
        "has_helper_fn": bool(re.search(r"\n_\w+\(", rule_code)),
        "has_startswith": "startswith(" in rule_code,
        "has_time_parse": "time.parse_rfc3339_ns" in rule_code,
        "has_set_ops": bool(re.search(r"\b(required|missing)\b", rule_code) and " - " in rule_code),
        "has_multiple_deny": rule_code.count("deny contains msg if") > 1,
        "has_not": bool(re.search(r"\bnot\s+_?\w+", rule_code)),
        "has_comprehension": bool(re.search(r"\{.*\|.*some", rule_code)),
    }
    return patterns


def _think_for_rule(instr_rec: dict, rule_code: str, out_type: str) -> str:
    """Generate a <think> reasoning trace for rule generation."""
    tier = instr_rec["tier"]
    paths = instr_rec.get("input_paths", [])
    pkg = instr_rec["package_name"]
    patterns = _detect_rule_patterns(rule_code)

    lines = []

    if tier == 1:
        # Brief reasoning for simple field checks
        path = paths[0] if paths else "the field"
        lines.append(f"This is a field-level check on `{path}`.")

        if any(p for p in paths if "[*]" in p):
            lines.append(
                "The field is inside an array, so I need `some item in collection` "
                "to iterate and check each element."
            )
        else:
            lines.append(
                "I need a simple comparison: deny if the value doesn't match the expected one."
            )

        lines.append(
            "Pattern: `deny contains msg if { <condition>; msg := sprintf(...) }`"
        )

    elif tier == 2:
        # Medium reasoning for pattern-level checks
        lines.append(f"This requires iterating over a collection and checking each element.")

        if len(paths) > 1:
            lines.append(f"Relevant paths: {', '.join(f'`{p}`' for p in paths)}.")

        if patterns["has_iteration"]:
            # Identify what's being iterated
            iter_match = re.search(r"some (\w+) in ([\w.]+)", rule_code)
            if iter_match:
                var, collection = iter_match.group(1), iter_match.group(2)
                lines.append(
                    f"I'll use `some {var} in {collection}` to iterate over each element."
                )

        if patterns["has_set_ops"]:
            lines.append(
                "I need set operations: collect the actual values into a set, "
                "define the required set, and compute the difference."
            )

        if patterns["has_helper_fn"]:
            lines.append(
                "A helper function will keep the main deny rule clean "
                "and make the logic easier to test."
            )

        if patterns["has_not"]:
            lines.append(
                "I'll use negation (`not`) with a helper to check for absence."
            )

        lines.append(
            "Each failing element produces its own deny message with `sprintf`."
        )

    elif tier == 3:
        # Detailed reasoning for composite/semantic checks
        lines.append("This is a composite check involving multiple fields or conditions.")

        if patterns["has_multiple_deny"]:
            lines.append(
                "I need multiple deny rules — each covering a different aspect of the check."
            )

        if patterns["has_time_parse"]:
            lines.append(
                "For timestamp comparison, I'll use `time.parse_rfc3339_ns()` "
                "to parse ISO-8601 strings into comparable nanosecond values."
            )

        if patterns["has_startswith"]:
            lines.append("I'll use `startswith()` for prefix matching.")

        if patterns["has_helper_fn"]:
            lines.append(
                "I'll extract the lookup logic into a helper function for clarity."
            )

        if patterns["has_iteration"] and patterns["has_not"]:
            lines.append(
                "The pattern is: iterate over items, use negation with a helper "
                "to check if each item satisfies a cross-reference condition."
            )
        elif patterns["has_iteration"]:
            lines.append(
                "I need to iterate with `some item in collection` and check "
                "a condition on each element."
            )

        if patterns["has_comprehension"]:
            lines.append(
                "I'll use a set comprehension to collect values for comparison."
            )

        # Add step-by-step based on the specific check
        if len(paths) > 1:
            lines.append(f"Fields involved: {', '.join(f'`{p}`' for p in paths)}.")

        lines.append("The deny message should clearly explain what failed and why.")

    return "\n".join(lines)


def _think_for_test(instr_rec: dict, rule_code: str) -> str:
    """Generate a <think> reasoning trace for test generation."""
    pkg = instr_rec["package_name"]
    patterns = _detect_rule_patterns(rule_code)

    lines = [
        f"I need positive and negative tests for the `{pkg}` rule.",
        "",
        "Positive test: provide valid input where the deny set is empty "
        "(`count(<pkg>.deny) == 0`). All fields must satisfy the rule's conditions.",
        "",
        "Negative test: provide input that violates the rule, so the deny set "
        "is non-empty (`count(<pkg>.deny) > 0`).",
    ]

    if patterns["has_iteration"]:
        lines.append(
            "\nSince the rule iterates, the negative test should include at least "
            "one valid and one invalid element to confirm per-element checking."
        )

    if patterns["has_helper_fn"]:
        lines.append(
            "\nThe rule uses a helper function, so my test data needs to exercise "
            "both the present and absent cases for the helper."
        )

    lines.append(
        "\nI'll use minimal mock data via `with input as { ... }` — "
        "only the fields the rule actually accesses."
    )

    return "\n".join(lines)


def _think_for_rule_and_test(instr_rec: dict, rule_code: str) -> str:
    """Generate a <think> trace for combined rule + test output."""
    rule_think = _think_for_rule(instr_rec, rule_code, "rule_and_test")
    lines = [
        rule_think,
        "",
        "Now for the tests:",
        "- Positive test: valid input → `count(deny) == 0`",
        "- Negative test: invalid input → `count(deny) > 0`",
        "I'll use minimal mock data with `with input as { ... }`.",
    ]
    return "\n".join(lines)


def _think_for_rule_from_test(instr_rec: dict, rule_code: str, test_code: str) -> str:
    """Generate a <think> trace for test→rule direction."""
    pkg = instr_rec["package_name"]
    patterns = _detect_rule_patterns(rule_code)

    lines = [
        "Let me analyze what these tests expect.",
        "",
        f"The positive test provides valid input and asserts `count({pkg}.deny) == 0`.",
        f"The negative test provides invalid input and asserts `count({pkg}.deny) > 0`.",
        "",
        "Comparing the valid and invalid inputs tells me what the rule checks:",
    ]

    # Try to identify the key difference
    if patterns["has_iteration"]:
        lines.append(
            "- The negative test has an element that fails a condition (iteration pattern)."
        )
    if patterns["has_multiple_deny"]:
        lines.append("- Multiple conditions need to be checked (multiple deny rules).")

    lines.append("")
    lines.append(
        f"I'll write a `deny contains msg if` rule in package `{pkg}` "
        "that fires on the invalid case but not the valid one."
    )

    return "\n".join(lines)


def _think_for_test_from_rule(instr_rec: dict, rule_code: str) -> str:
    """Generate a <think> trace for rule→test direction."""
    pkg = instr_rec["package_name"]
    patterns = _detect_rule_patterns(rule_code)

    lines = [
        "Let me analyze what this rule checks to design appropriate tests.",
        "",
    ]

    if patterns["has_iteration"]:
        lines.append("The rule iterates over a collection, so I need test data with arrays.")
    if patterns["has_not"]:
        lines.append("The rule uses negation, so I need cases where the helper succeeds and fails.")
    if patterns["has_startswith"]:
        lines.append("The rule uses `startswith`, so I need matching and non-matching prefixes.")
    if patterns["has_time_parse"]:
        lines.append("The rule parses timestamps, so I need valid RFC3339 timestamps.")

    lines.append("")
    lines.append(
        f"Positive test: input that satisfies all conditions → `count({pkg}.deny) == 0`."
    )
    lines.append(
        f"Negative test: input that violates a condition → `count({pkg}.deny) > 0`."
    )
    lines.append("")
    lines.append("I'll use `with input as { ... }` with minimal mock data.")

    return "\n".join(lines)


def generate_think_trace(
    instr_rec: dict,
    rule_code: str,
    test_code: str,
    out_type: str,
) -> str:
    """Generate the appropriate <think> trace for a given output type."""
    if out_type == "rule_only":
        return _think_for_rule(instr_rec, rule_code, out_type)
    elif out_type == "test_only":
        return _think_for_test(instr_rec, rule_code)
    elif out_type == "rule_and_test":
        return _think_for_rule_and_test(instr_rec, rule_code)
    elif out_type == "rule_from_test":
        return _think_for_rule_from_test(instr_rec, rule_code, test_code)
    elif out_type == "test_from_rule":
        return _think_for_test_from_rule(instr_rec, rule_code)
    else:
        return "I need to carefully consider the requirements and write correct Rego code."


# ===========================================================================
# Instruction-variant generators
# ===========================================================================

def _variant_canonical(instr: str, _pkg: str, _paths: list[str]) -> str:
    """Return the original instruction unchanged."""
    return instr


def _variant_terse(instr: str, pkg: str, paths: list[str]) -> str:
    """Compress to a minimal, telegram-style prompt."""
    m = re.search(
        r"(?:Write a Rego deny rule that rejects the attestation if |"
        r"Write a Rego deny rule that rejects the attestation if the build was not )",
        instr,
    )
    if m:
        tail = instr[m.end():]
        tail = re.sub(r"\s*\([^)]+\)\s*$", "", tail).strip().rstrip(".")
        return f"deny if {tail}"

    return re.sub(
        r"^Write a Rego deny rule that ",
        "rego deny: ",
        instr,
    )


def _variant_verbose(instr: str, pkg: str, paths: list[str]) -> str:
    """Over-explain with redundant detail."""
    path_str = ", ".join(f"`{p}`" for p in paths)
    return (
        f"I need you to write a Rego policy rule using the deny pattern. "
        f"The rule should be in a package called `{pkg}`. "
        f"Specifically, {instr.lower()} "
        f"The relevant JSON path(s) in the attestation are: {path_str}. "
        f"Make sure to import rego.v1 and use the `deny contains msg if` pattern."
    )


def _variant_poor_grammar(instr: str, _pkg: str, _paths: list[str]) -> str:
    """Introduce realistic grammar/spelling mistakes."""
    text = instr
    replacements = [
        ("Write a Rego deny rule that rejects the attestation if",
         "write rego deny rule that reject attestation if"),
        ("is not", "isnt"),
        ("does not", "dont"),
        ("is missing", "is miss"),
        ("or is not a valid", "or not valid"),
        ("Additionally, verify", "also verify"),
        ("must not", "must not be"),
        ("at least", "atleast"),
        ("The rule should", "rule should"),
        ("This ensures", "this ensure"),
        (" the ", " "),
        ("parameters", "params"),
    ]
    for old, new in replacements:
        text = text.replace(old, new, 1)
    return text


def _variant_reordered(instr: str, pkg: str, paths: list[str]) -> str:
    """Put the constraint first, then the context."""
    m = re.search(
        r"Write a Rego deny rule that rejects the attestation if (.+?)(?:\.\s*\((.+)\))?$",
        instr,
    )
    if m:
        constraint = m.group(1).strip().rstrip(".")
        note = m.group(2)
        result = f"If {constraint}, the attestation must be rejected. Write a Rego deny rule for this."
        if note:
            result += f" ({note})"
        return result

    sentences = instr.split(". ")
    if len(sentences) > 1:
        return ". ".join(reversed(sentences))
    return instr


def _variant_keyword_heavy(instr: str, pkg: str, paths: list[str]) -> str:
    """Use Rego jargon throughout."""
    path_str = ", ".join(paths)
    m = re.search(r"rejects the attestation if (.+?)(?:\.\s*\(|$)", instr)
    constraint = m.group(1).strip().rstrip(".") if m else "the input is invalid"
    return (
        f"Create a Rego partial set rule `deny contains msg if {{ ... }}` "
        f"in package `{pkg}` with `import rego.v1`. "
        f"The rule fires when {constraint}. "
        f"Relevant input paths: {path_str}. "
        f"Use `sprintf` for the deny message."
    )


def _variant_vague(instr: str, pkg: str, _paths: list[str]) -> str:
    """Under-specified but still answerable."""
    m = re.search(r"\(([^)]+)\)\s*$", instr)
    note = m.group(1) if m else None

    m2 = re.search(
        r"rejects the attestation if (.+?)(?:\.\s*\(|\.?\s*$)",
        instr,
    )
    constraint_fragment = m2.group(1).strip().rstrip(".") if m2 else None

    if note:
        return f"Write a Rego rule to verify the {note.lower()}."
    elif constraint_fragment and len(constraint_fragment) < 120:
        simplified = constraint_fragment.replace("`.predicate.", "the ").replace("`", "")
        return f"Make a deny rule checking {simplified}."
    else:
        return f"Write a Rego deny rule for the `{pkg}` check."


VARIANT_GENERATORS = [
    ("canonical", _variant_canonical),
    ("terse", _variant_terse),
    ("verbose", _variant_verbose),
    ("poor_grammar", _variant_poor_grammar),
    ("reordered", _variant_reordered),
    ("keyword_heavy", _variant_keyword_heavy),
    ("vague", _variant_vague),
]


# ===========================================================================
# Output-type instruction wrappers
# ===========================================================================

def _wrap_rule_only(variant_instr: str) -> str:
    return variant_instr


def _wrap_test_only(variant_instr: str) -> str:
    text = variant_instr
    for old, new in [
        ("Write a Rego deny rule that", "Write Rego tests for a deny rule that"),
        ("write rego deny rule that", "write rego tests for deny rule that"),
        ("deny if", "write tests for a rule that denies if"),
        ("Create a Rego partial set rule", "Write Rego tests for a partial set rule"),
        ("Write a Rego rule to", "Write Rego tests for a rule that"),
        ("Make a deny rule checking", "Write tests for a deny rule that checks"),
        ("Write a Rego deny rule for", "Write Rego tests for"),
    ]:
        if old in text:
            text = text.replace(old, new, 1)
            break
    else:
        text = f"Write Rego tests (positive and negative) for: {text}"
    return text


def _wrap_rule_and_test(variant_instr: str) -> str:
    text = variant_instr
    for old, new in [
        ("Write a Rego deny rule that",
         "Write a Rego deny rule AND tests that"),
        ("write rego deny rule that",
         "write rego deny rule and tests that"),
        ("deny if",
         "write a deny rule and tests. deny if"),
        ("Create a Rego partial set rule",
         "Create a Rego partial set rule AND tests"),
        ("Write a Rego rule to",
         "Write a Rego rule AND tests to"),
        ("Make a deny rule checking",
         "Make a deny rule and tests checking"),
        ("Write a Rego deny rule for",
         "Write a Rego deny rule AND tests for"),
    ]:
        if old in text:
            text = text.replace(old, new, 1)
            break
    else:
        text = f"Write a Rego deny rule AND tests for: {text}"
    return text


# ===========================================================================
# Response formatters (code only, think is added separately)
# ===========================================================================

def _format_rule_only(rule_code: str, _test_code: str) -> str:
    return rule_code.strip()


def _format_test_only(_rule_code: str, test_code: str) -> str:
    return test_code.strip()


def _format_rule_and_test(rule_code: str, test_code: str) -> str:
    return f"{rule_code.strip()}\n---\n{test_code.strip()}"


OUTPUT_TYPES = [
    ("rule_only", _wrap_rule_only, _format_rule_only),
    ("test_only", _wrap_test_only, _format_test_only),
    ("rule_and_test", _wrap_rule_and_test, _format_rule_and_test),
]


# ===========================================================================
# Message formatting
# ===========================================================================

def make_messages(
    user_content: str,
    assistant_code: str,
    think_trace: str,
) -> list[dict]:
    """Build the Qwen3 messages list with system prompt and <think> trace."""
    # Embed <think> in the assistant content — Qwen3's template parses it out.
    if think_trace.strip():
        assistant_content = f"<think>\n{think_trace.strip()}\n</think>\n\n{assistant_code}"
    else:
        assistant_content = f"<think>\n\n</think>\n\n{assistant_code}"

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
        {"role": "assistant", "content": assistant_content},
    ]


# ===========================================================================
# Direction-reversal instruction builders
# ===========================================================================

def _make_rule_from_test_instruction(test_code: str) -> str:
    return (
        f"Given these Rego tests:\n```rego\n{test_code.strip()}\n```\n\n"
        f"Write the Rego deny rule that passes them."
    )


def _make_test_from_rule_instruction(rule_code: str) -> str:
    return (
        f"Given this Rego rule:\n```rego\n{rule_code.strip()}\n```\n\n"
        f"Write positive and negative Rego tests for it."
    )


# ===========================================================================
# Main assembly
# ===========================================================================

def load_instructions() -> list[dict]:
    instructions = []
    with open(INSTRUCTIONS_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                instructions.append(json.loads(line))
    return instructions


def load_phase3_result(task_id: str) -> dict | None:
    result_path = PHASE3_TASKS / task_id / "result.json"
    if not result_path.exists():
        return None
    with open(result_path) as f:
        result = json.load(f)
    if result.get("status") != "pass":
        return None
    return result


def load_file(path: Path) -> str:
    with open(path) as f:
        return f.read()


def assemble() -> list[dict]:
    """Build the full SFT dataset in Qwen3 messages format."""
    instructions = load_instructions()
    examples: list[dict] = []
    skipped = 0

    for instr_rec in instructions:
        task_id = instr_rec["id"]
        pkg = instr_rec["package_name"]
        tier = instr_rec["tier"]
        canonical_instr = instr_rec["instruction"]
        input_paths = instr_rec.get("input_paths", [])

        # Check Phase 3 passed
        result = load_phase3_result(task_id)
        if result is None:
            skipped += 1
            continue

        # Load rule and test code
        rule_path = PHASE3_TASKS / task_id / f"{pkg}.rego"
        test_path = PHASE3_TASKS / task_id / f"{pkg}_test.rego"
        if not rule_path.exists() or not test_path.exists():
            skipped += 1
            continue

        rule_code = load_file(rule_path)
        test_code = load_file(test_path)

        # --- Generate variant × output-type examples ---
        for variant_name, variant_fn in VARIANT_GENERATORS:
            variant_instr = variant_fn(canonical_instr, pkg, input_paths)

            for out_type, wrap_fn, fmt_fn in OUTPUT_TYPES:
                wrapped_instr = wrap_fn(variant_instr)
                response_code = fmt_fn(rule_code, test_code)
                think = generate_think_trace(instr_rec, rule_code, test_code, out_type)
                messages = make_messages(wrapped_instr, response_code, think)

                examples.append({
                    "messages": messages,
                    "task_id": task_id,
                    "tier": tier,
                    "variant": variant_name,
                    "type": out_type,
                })

        # --- Direction-reversal examples (canonical only) ---
        # rule_from_test
        rft_instr = _make_rule_from_test_instruction(test_code)
        rft_think = generate_think_trace(instr_rec, rule_code, test_code, "rule_from_test")
        rft_messages = make_messages(rft_instr, rule_code.strip(), rft_think)
        examples.append({
            "messages": rft_messages,
            "task_id": task_id,
            "tier": tier,
            "variant": "canonical",
            "type": "rule_from_test",
        })

        # test_from_rule
        tfr_instr = _make_test_from_rule_instruction(rule_code)
        tfr_think = generate_think_trace(instr_rec, rule_code, test_code, "test_from_rule")
        tfr_messages = make_messages(tfr_instr, test_code.strip(), tfr_think)
        examples.append({
            "messages": tfr_messages,
            "task_id": task_id,
            "tier": tier,
            "variant": "canonical",
            "type": "test_from_rule",
        })

    print(f"Tasks loaded:   {len(instructions)}")
    print(f"Tasks skipped:  {skipped}")
    print(f"Tasks used:     {len(instructions) - skipped}")
    print(f"Total examples: {len(examples)}")

    return examples


def write_dataset(examples: list[dict]) -> None:
    """Write the JSONL dataset, shuffled for training."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    random.shuffle(examples)

    with open(OUTPUT_FILE, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"\nDataset written to: {OUTPUT_FILE}")
    print(f"File size: {OUTPUT_FILE.stat().st_size / 1024:.1f} KB")


def print_stats(examples: list[dict]) -> None:
    """Print breakdown statistics."""
    print("\n--- Dataset Statistics ---")

    tier_counts = Counter(ex["tier"] for ex in examples)
    print(f"\nBy tier:")
    for tier in sorted(tier_counts):
        print(f"  Tier {tier}: {tier_counts[tier]}")

    type_counts = Counter(ex["type"] for ex in examples)
    print(f"\nBy output type:")
    for t in ["rule_only", "test_only", "rule_and_test", "rule_from_test", "test_from_rule"]:
        print(f"  {t:20s}: {type_counts.get(t, 0)}")

    variant_counts = Counter(ex["variant"] for ex in examples)
    print(f"\nBy variant:")
    for v, c in variant_counts.most_common():
        print(f"  {v:20s}: {c}")

    # Think trace stats
    think_lens = []
    for ex in examples:
        assistant_msg = ex["messages"][2]["content"]
        m = re.search(r"<think>\n(.*?)\n</think>", assistant_msg, re.DOTALL)
        if m:
            think_lens.append(len(m.group(1)))
        else:
            think_lens.append(0)

    print(f"\n<think> trace lengths (chars):")
    print(f"  min={min(think_lens)}, median={sorted(think_lens)[len(think_lens)//2]}, max={max(think_lens)}")
    has_think = sum(1 for t in think_lens if t > 0)
    print(f"  examples with thinking: {has_think}/{len(examples)}")

    print(f"\nTotal: {len(examples)}")


def run_token_audit(examples: list[dict]) -> None:
    """Run token-length audit using the Qwen3 tokenizer."""
    try:
        from transformers import AutoTokenizer
    except ImportError:
        print("\n⚠ transformers not installed — skipping token audit.")
        print("  Install: pip install transformers jinja2")
        return

    print("\n--- Token Audit (Qwen3-4B tokenizer) ---")
    print("Loading tokenizer...")

    tok = AutoTokenizer.from_pretrained("Qwen/Qwen3-4B", trust_remote_code=True)

    token_counts = []
    for ex in examples:
        text = tok.apply_chat_template(ex["messages"], tokenize=False)
        tokens = tok.encode(text)
        token_counts.append(len(tokens))

    token_counts.sort()
    n = len(token_counts)

    print(f"\nToken counts per example:")
    print(f"  min:    {token_counts[0]}")
    print(f"  p25:    {token_counts[n // 4]}")
    print(f"  median: {token_counts[n // 2]}")
    print(f"  p75:    {token_counts[3 * n // 4]}")
    print(f"  p95:    {token_counts[int(n * 0.95)]}")
    print(f"  max:    {token_counts[-1]}")
    print(f"  total:  {sum(token_counts):,}")

    # Flag any that exceed common training lengths
    for limit in [1024, 2048, 4096]:
        over = sum(1 for t in token_counts if t > limit)
        if over > 0:
            print(f"  > {limit} tokens: {over} examples ({over * 100 / n:.1f}%)")

    # Recommended max_seq_length
    p99 = token_counts[int(n * 0.99)]
    recommended = 512
    for candidate in [512, 1024, 2048, 4096]:
        if candidate >= p99:
            recommended = candidate
            break
    print(f"\n  Recommended max_seq_length: {recommended} (covers p99={p99})")

    # By tier
    print(f"\n  By tier:")
    for tier in [1, 2, 3]:
        tier_token_counts = [
            tc for tc, ex in zip(token_counts, examples)
            if ex["tier"] == tier
        ]
        if tier_token_counts:
            tier_sorted = sorted(tier_token_counts)
            print(
                f"    Tier {tier}: median={tier_sorted[len(tier_sorted)//2]}, "
                f"max={max(tier_sorted)}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Assemble Qwen3-optimized SFT dataset")
    parser.add_argument(
        "--audit", action="store_true",
        help="Run token-length audit with Qwen3 tokenizer (requires transformers + jinja2)",
    )
    args = parser.parse_args()

    examples = assemble()
    write_dataset(examples)
    print_stats(examples)

    if args.audit:
        run_token_audit(examples)


if __name__ == "__main__":
    main()
