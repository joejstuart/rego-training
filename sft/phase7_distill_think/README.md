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

All 612 unique (task_id, type) combinations were distilled and mapped back
to all 2,448 training examples. See `AUDIT_REPORT.md` for the full validation.

| Metric | Template (Before) | Distilled (After) | Change |
|--------|-------------------|-------------------|--------|
| Mean trace length | 399 chars | 1,195 chars | **3.0×** |
| Min trace length | 127 chars | 500 chars | **3.9×** |
| Traces improved | — | 2,448/2,448 | **100%** |
| Code preserved | — | 2,448/2,448 | **100%** |

### By Task Type

| Type | Improvement |
|------|-------------|
| modify_rule | **8.2×** |
| rule_only | **3.0×** |
| test_only | **2.6×** |
| test_from_rule | **2.5×** |
| rule_from_test | **2.2×** |
| rule_and_test | **1.9×** |

### Key Improvements Over Templates

1. **Domain context** — explains *why* the check matters (SLSA, Tekton, supply chain)
2. **Step-by-step reasoning** — walks through the implementation approach
3. **Edge case awareness** — missing fields, empty arrays, Rego truthiness
4. **Alternative approaches** — notes better implementations where applicable
5. **Debugging insights** — explains how error messages help operators

## Distillation Approach

### Strategy

Instead of distilling all 2,448 examples individually, we leveraged the task
structure:

- **612 unique (task_id, type) combinations** — each gets one distilled trace
- The trace is mapped back to all instruction variants (canonical, terse, verbose, etc.)
- **89.4%** direct match by (task_id, type), **10.6%** matched via fallback on task_id

### Coverage Breakdown

| Category | Tasks | Status |
|----------|-------|--------|
| Tier 1 rule_only | 38 | ✅ Complete |
| Tier 2 rule_only | 12 | ✅ Complete |
| Tier 3 rule_only | 42 | ✅ Complete |
| test_only (all tiers) | 92 | ✅ Complete |
| modify_rule (all tiers) | 152 | ✅ Complete |
| rule_and_test | 92 | ✅ Complete |
| rule_from_test | 92 | ✅ Complete |
| test_from_rule | 92 | ✅ Complete |
| **Total** | **612/612** | **100%** |

## Output Files

```
phase7_distill_think/
├── README.md                              ← This file
├── AUDIT_REPORT.md                        ← Full validation report (before/after)
├── batch_distill.py                       ← Helper script for batch processing
└── output/
    ├── rego_sft_distilled.jsonl           ← Final dataset (2,448 examples) ★
    ├── distilled_tier1_rule_only.jsonl    ← Tier 1 rule_only (20 tasks)
    ├── distilled_tier1_rule_only_part2.jsonl  ← Tier 1 rule_only (18 tasks)
    ├── distilled_tier2_rule_only.jsonl    ← Tier 2 rule_only (12 tasks)
    ├── tier3_rule_only_batch*.jsonl       ← Tier 3 rule_only (42 tasks)
    ├── test_only_*.jsonl                  ← test_only (92 tasks)
    ├── modify_rule_*.jsonl                ← modify_rule (152 tasks)
    └── combined_batch*.jsonl              ← rule_and_test, rule_from_test,
                                             test_from_rule (276 tasks)
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

## Regeneration

To regenerate the distilled dataset from the Phase 6.3 merged dataset, the
assembly script reads all distilled JSONL files in `output/` and maps them
back to the 2,448 examples. The distilled traces themselves were generated
by reasoning over each unique task's instruction, code, and domain context.
