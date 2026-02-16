# Phase 7: Distill `<think>` Reasoning Traces

## Purpose

Replace template-generated `<think>` traces in the SFT dataset with genuine,
high-quality reasoning traces that teach the model **how** to think through
Rego policy problems — not just **what** patterns to use.

## Problem

The Phase 6.3 merged dataset (2,448 examples) has template-generated `<think>`
traces that are short, formulaic, and repetitive:

**Template trace (tier 1, ~25 tokens):**
```
This is a field-level check on `.predicate.buildType`.
I need a simple comparison on the target value.
Pattern: `deny contains msg if { <condition>; msg := sprintf(...) }`
```

## Solution

Distill rich reasoning traces inspired by QED-Nano's approach of training with
genuine chain-of-thought reasoning:

**Distilled trace (tier 1, ~145 tokens):**
```
The user wants to enforce that the buildType field matches a specific Tekton
pipeline identifier. Let me break down the requirements:

1. The field path is `input.predicate.buildType` — top-level predicate field,
   not nested in an array
2. The expected value is the exact string "tekton.dev/v1beta1/PipelineRun"
3. I need to reject (deny) when it does NOT match this value

Since this is a simple scalar comparison, I don't need iteration — just a direct
inequality check. In Rego, I'll use `!=` to catch when the value differs.

For the deny message, I should use sprintf to show both the actual value and
what was expected — this makes debugging easier for operators...
```

## Quality Results

All 612 unique (task_id, type) combinations have task-specific `<think>` traces
mapped to all 2,448 training examples.

| Metric | Template (Before) | Distilled (After) | Change |
|--------|-------------------|-------------------|--------|
| Mean trace length | 399 chars | 1,195 chars | **3.0×** |
| Min trace length | 127 chars | 500 chars | **3.9×** |
| Generic/template traces | 1,129 (46%) | **0 (0%)** | ✅ |
| Unique traces | 394 | **612** | 1:1 with task combos |
| Cross-task duplicates | 12 | **0** | ✅ |
| Factual errors | ~40 | **0** | ✅ |

### Key Improvements Over Templates

1. **Domain context** — explains *why* the check matters (SLSA, Tekton, supply chain)
2. **Step-by-step reasoning** — walks through the implementation approach
3. **Edge case awareness** — missing fields, empty arrays, Rego truthiness
4. **Alternative approaches** — notes better implementations where applicable
5. **Debugging insights** — explains how error messages help operators

## How It Was Built (Current Process)

### Overview

The final `rego_sft_distilled.jsonl` was built in two phases:

1. **Phase 7a (LLM distillation)** — An LLM generates `<think>` traces for the
   92 unique `rule_only` and 92 unique `test_only` tasks.  These are the
   irreplaceable "seed" traces stored in the intermediate batch files.

2. **Phase 7b (`redistill.py`)** — A deterministic Python script derives all
   remaining traces (modify_rule, rule_and_test, rule_from_test, test_from_rule)
   from the seed traces + code analysis.  It also fixes factual errors and
   framing issues.

### Step-by-step

```
Phase 6.3 merged dataset (2,448 examples with template <think> traces)
        │
        ▼
  ┌─────────────────────────────────────────────┐
  │  Phase 7a: LLM distillation (not automated) │
  │                                             │
  │  An LLM reads each unique task's:           │
  │    • user instruction                       │
  │    • expected Rego code output              │
  │    • SLSA attestation context               │
  │                                             │
  │  …and writes a detailed reasoning trace     │
  │  explaining the approach step-by-step.      │
  │                                             │
  │  Outputs → intermediate batch files:        │
  │    distilled_tier1_rule_only.jsonl     (20) │
  │    distilled_tier1_rule_only_part2.jsonl(18)│
  │    distilled_tier2_rule_only.jsonl     (12) │
  │    tier3_rule_only_batch*_part*.jsonl  (42) │
  │    test_only_distilled_complete.jsonl  (20) │
  │    test_only_batch2-5.jsonl           (72) │
  │                                             │
  │  Total: 92 rule_only + 92 test_only = 184  │
  │  unique seed traces                         │
  └──────────────────┬──────────────────────────┘
                     │
                     ▼
  ┌─────────────────────────────────────────────┐
  │  Assembly: map traces → 2,448 examples      │
  │                                             │
  │  For each example in the merged dataset:    │
  │    1. Look up distilled trace by task_id    │
  │    2. Replace template <think> with it      │
  │    3. Keep all code output unchanged        │
  │                                             │
  │  Output → rego_sft_distilled.jsonl (v1)     │
  └──────────────────┬──────────────────────────┘
                     │
                     ▼
  ┌─────────────────────────────────────────────┐
  │  Phase 7b: redistill.py (deterministic)     │
  │                                             │
  │  Fixes 1,148 traces that were generic:      │
  │    • modify_rule (456)  — code-diff analysis│
  │    • rule_and_test (513) — compose from     │
  │      good rule_only + test_only traces      │
  │    • test_only wrong framing (44)           │
  │    • rule_from_test generic (58)            │
  │    • test_from_rule generic (58)            │
  │    • factual errors (10)                    │
  │    • think/code mismatches (9)              │
  │                                             │
  │  Output → rego_sft_distilled.jsonl (final)  │
  └─────────────────────────────────────────────┘
```

### Running Phase 7b (deterministic)

```bash
cd sft/phase7_distill_think/

# The script is idempotent — safe to re-run on already-fixed data
python redistill.py

# Or with explicit paths:
python redistill.py --input output/rego_sft_distilled.jsonl \
                    --output output/rego_sft_distilled.jsonl
```

### What redistill.py does (no LLM needed)

| Fix | How it works | Examples |
|-----|-------------|----------|
| `modify_rule` traces | Parses original→modified Rego code, identifies what changed (rename, value change, allowlist, etc.), generates trace describing the specific modification | 456 |
| `rule_and_test` traces | Composes from existing good `rule_only` trace + test-writing boilerplate with the specific package name | 513 |
| Wrong-framing `test_only` | Detects traces that say "rule AND tests" and replaces with proper test-only framing | 44 |
| Generic `rule_from_test` | Adds TDD framing + the good `rule_only` trace for the same task_id | 58 |
| Generic `test_from_rule` | Adds rule-analysis framing + the good `test_only` trace for the same task_id | 58 |
| Rego factual error | Fixes "empty string is falsy in Rego" → correctly notes it's a defined value | 10 |
| Think/code mismatch | Fixes `all_materials_have_digest` trace to match what code actually does | 9 |

### What is NOT reproducible without an LLM

The **184 seed traces** (92 `rule_only` + 92 `test_only`) were generated by an
LLM reasoning about each task.  They are stored in the intermediate batch files
under `output/`.  If both the intermediate files AND `rego_sft_distilled.jsonl`
were deleted, an LLM would need to regenerate them — producing similar but not
identical traces.

---

## Improved Process (Recommended for Future Runs)

The current process required a two-phase approach (LLM generation → deterministic
fix-up) because the initial distillation produced generic traces for compound
output types. If starting from scratch, use this single-pass process instead.

### Why the Current Process Needed redistill.py

The initial distillation treated every `(task_id, output_type)` combination as
an independent generation task. This caused problems:

| Issue | Root cause | Affected |
|-------|-----------|----------|
| Generic `modify_rule` traces | LLM wasn't shown the original→modified code diff | 456 examples |
| Generic `rule_and_test` traces | LLM generated a single trace for "rule + tests" instead of composing from rule and test reasoning | 513 examples |
| Wrong-framing `test_only` traces | Prompt didn't enforce "test-only" framing | 44 examples |
| Generic `rule_from_test` / `test_from_rule` | LLM wasn't given the complementary trace for composition | 116 examples |
| Factual errors | No validation against Rego semantics | 10 examples |
| Think/code mismatches | No post-generation check that trace matches the actual code | 9 examples |

### Improved Single-Pass Architecture

```
Phase 6.3 merged dataset (2,448 examples)
        │
        ▼
  ┌──────────────────────────────────────────────────┐
  │  Step 1: Identify unique tasks                   │
  │                                                  │
  │  Group examples by (task_id, output_type).       │
  │  Only 612 unique combinations → 612 LLM calls.  │
  │  Classify each into a generation strategy:       │
  │                                                  │
  │    • rule_only (92)     → generate directly      │
  │    • test_only (92)     → generate directly      │
  │    • modify_rule (152)  → generate with diff     │
  │    • rule_and_test (171)→ compose from r+t seeds │
  │    • rule_from_test (58)→ compose with TDD frame │
  │    • test_from_rule (47)→ compose with analysis  │
  └──────────────────┬───────────────────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────────────────┐
  │  Step 2: Generate seed traces (LLM)              │
  │                                                  │
  │  Generate rule_only + test_only traces first.    │
  │  These are the "seed" traces — all other types   │
  │  are derived from them.                          │
  │                                                  │
  │  Quality gate per trace:                         │
  │    ✓ Minimum 400 chars                           │
  │    ✓ References specific field paths from code   │
  │    ✓ No Rego factual errors (see checklist)      │
  │    ✓ Framing matches output_type                 │
  │    ✓ Step-by-step structure present              │
  │                                                  │
  │  If a trace fails → retry with feedback.         │
  └──────────────────┬───────────────────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────────────────┐
  │  Step 3: Derive compound traces (deterministic)  │
  │                                                  │
  │  modify_rule:                                    │
  │    • Parse original + modified Rego code          │
  │    • Diff to find what changed                   │
  │    • Generate trace describing the modification  │
  │      with the rule_only seed as context          │
  │                                                  │
  │  rule_and_test:                                  │
  │    • Compose rule_only trace + test_only trace   │
  │    • Add bridging text for test-writing section  │
  │                                                  │
  │  rule_from_test / test_from_rule:                │
  │    • Add TDD/analysis framing                    │
  │    • Include the complementary seed trace        │
  └──────────────────┬───────────────────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────────────────┐
  │  Step 4: Validate & assemble                     │
  │                                                  │
  │  For every trace in the final dataset:           │
  │    ✓ Length ≥ 400 chars                          │
  │    ✓ No cross-task duplicate traces              │
  │    ✓ Trace framing matches output_type           │
  │    ✓ Field paths in trace exist in the code      │
  │    ✓ Rego semantics checklist passes             │
  │    ✓ Code output unchanged from source           │
  │                                                  │
  │  Output → rego_sft_distilled.jsonl (final)       │
  └──────────────────────────────────────────────────┘
```

### Type-Specific Prompt Design

Each output type needs a different prompt to produce high-quality traces:

#### `rule_only` and `test_only` (seed traces)

```
Given:
  - The user instruction (what policy to write)
  - The expected Rego code output
  - The SLSA attestation structure

Write a detailed reasoning trace that:
  1. Identifies the domain context (SLSA, supply chain, Tekton, etc.)
  2. Breaks down the user's requirement into sub-problems
  3. Maps requirements to specific Rego constructs
  4. Notes edge cases (missing fields, empty arrays, Rego truthiness)
  5. Explains the deny message format and why it helps operators

For test_only: frame as "the user wants tests for an existing rule"
  — never mention writing the rule itself.
```

#### `modify_rule` (requires code diff)

```
Given:
  - The original Rego rule
  - The modified Rego rule
  - The user instruction describing the change

Write a reasoning trace that:
  1. Identifies exactly what changed (diff the two versions)
  2. Explains WHY the change was needed
  3. Describes the implementation approach for the specific change
  4. Notes any Rego-specific considerations
```

#### `rule_and_test` (composed from seeds)

Do NOT generate with an LLM — compose deterministically:
```
{rule_only_trace}

Now I need to write tests for this rule. {test_only_trace_with_adjusted_framing}
```

#### `rule_from_test` / `test_from_rule` (composed from seeds)

Do NOT generate with an LLM — compose deterministically:
```
rule_from_test: "I have tests that define the expected behavior.
  Let me work backward to derive the rule. {rule_only_trace}"

test_from_rule: "I have a working rule. Let me analyze what it does
  and write comprehensive tests. {test_only_trace}"
```

### Rego Semantics Checklist (Validate Every Trace)

Common Rego misconceptions to reject during generation:

| Claim | Correct? | Fix |
|-------|----------|-----|
| "empty string is falsy in Rego" | ❌ | Empty string `""` is a defined value; `not ""` is `false` |
| "`not x` means x is false" | ❌ | `not x` means x is **undefined** |
| "checking `.digest` verifies sha256" | ❌ | It only checks that the field **exists** |
| "Rego uses if/else" | ❌ | Rego uses rule **heads** with **bodies**; no traditional if/else |
| "`some x in arr` filters" | ❌ | `some x in arr` **iterates**; filtering is via conditions in the body |

### Key Differences from Current Process

| Aspect | Current (2-phase) | Improved (1-pass) |
|--------|-------------------|-------------------|
| LLM calls | 184 seed + none | 184 seed + 152 modify_rule = **336** |
| Compound types | Generated generically, then fixed | Composed deterministically from seeds |
| Validation | Post-hoc audit | Built into generation loop |
| Fix-up script needed | Yes (`redistill.py`) | **No** |
| Intermediate files | ~20 batch files | 1 seed file + 1 final file |
| Reproducibility | Seeds: LLM, rest: deterministic | Same — seeds still require LLM |
| Total quality issues | 1,148 (fixed by redistill.py) | **0** (prevented by design) |

### Implementation Notes

If implementing this as a script:

1. **Use the Anthropic API** (or equivalent) with `claude-sonnet` or better
   for seed trace generation. Budget ~$2-5 for 184 seed traces.

2. **Batch by task_id** — generate `rule_only` and `test_only` for the same
   task_id in the same session so the LLM has full context.

3. **Retry on validation failure** — if a trace fails the quality gate,
   re-prompt with specific feedback (e.g., "trace is too short" or
   "trace mentions if/else but Rego doesn't have if/else").

4. **Deterministic composition is key** — the insight from the current process
   is that compound types (`rule_and_test`, `rule_from_test`, `test_from_rule`)
   should NEVER be independently generated. They should always be composed
   from the seed traces. This eliminates the largest class of quality issues
   (1,087 of 1,148 fixes in `redistill.py`).

5. **`modify_rule` needs the diff** — always include both the original and
   modified code in the prompt. Without the diff, the LLM generates generic
   "modification" traces that don't describe what actually changed.

## Output Files

```
phase7_distill_think/
├── README.md                              ← This file
├── AUDIT_REPORT.md                        ← Full validation report
├── redistill.py                           ← Deterministic quality fixes (Phase 7b)
└── output/
    ├── rego_sft_distilled.jsonl           ← Final dataset (2,448 examples) ★
    │
    │  Intermediate batch files (Phase 7a seed traces):
    ├── distilled_tier1_rule_only.jsonl    ← Tier 1 rule_only (20 tasks)
    ├── distilled_tier1_rule_only_part2.jsonl  ← Tier 1 rule_only (18 tasks)
    ├── distilled_tier2_rule_only.jsonl    ← Tier 2 rule_only (12 tasks)
    ├── tier3_rule_only_batch*_part*.jsonl ← Tier 3 rule_only (42 tasks)
    ├── test_only_distilled_complete.jsonl ← test_only (20 tasks)
    ├── test_only_batch2-5.jsonl          ← test_only (72 tasks)
    │
    │  Other intermediate files (used during distillation):
    ├── modify_rule_*.jsonl               ← modify_rule intermediates
    ├── combined_batch*.jsonl             ← cross-type intermediates
    └── *_remaining.jsonl, *_input.jsonl  ← working files
```

## Usage

The final distilled dataset is the default for `sft/train.py`:

```bash
cd sft/

# Train with distilled traces (default)
python train.py

# Explicitly specify the distilled dataset
python train.py --dataset phase7_distill_think/output/rego_sft_distilled.jsonl

# Compare: train on the older merged dataset (template traces)
python train.py --dataset phase6.3_dataset_merge/output/rego_sft_merged.jsonl
```
