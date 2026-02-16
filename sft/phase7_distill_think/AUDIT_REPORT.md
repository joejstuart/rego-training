# Phase 7 Distillation — Audit Report

**Date**: 2026-02-15
**Input**: `sft/phase6.3_dataset_merge/output/rego_sft_merged.jsonl` (2,448 examples)
**Output**: `sft/phase7_distill_think/output/rego_sft_distilled.jsonl` (2,448 examples)

---

## Executive Summary

All 2,448 SFT training examples have been upgraded with high-quality distilled `<think>` reasoning traces. The average trace length increased **3.0×** (399 → 1,195 chars), and **100% of traces were improved**. Code, metadata, system prompts, and user instructions are preserved exactly.

---

## Validation Results

| Check | Status |
|-------|--------|
| Example count (2,448 = 2,448) | ✅ Pass |
| Schema keys identical | ✅ Pass |
| Message roles identical | ✅ Pass |
| System messages unchanged | ✅ Pass |
| User messages unchanged | ✅ Pass |
| Code after `</think>` identical | ✅ 2,448/2,448 (100%) |
| All have `<think>` tag | ✅ Pass |
| All have `</think>` tag | ✅ Pass |
| Metadata preserved (task_id, tier, variant, type, task_type, source) | ✅ 0 mismatches |

---

## Trace Quality Improvement

### Overall

| Metric | Original | Distilled | Change |
|--------|----------|-----------|--------|
| Mean length | 399 chars | 1,195 chars | **3.0×** |
| Median length | 421 chars | 1,140 chars | **2.7×** |
| Min length | 127 chars | 500 chars | **3.9×** |
| Max length | 1,043 chars | 2,254 chars | **2.2×** |
| Traces changed | — | 2,448/2,448 | **100%** |

### By Tier

| Tier | Count | Original Avg | Distilled Avg | Improvement |
|------|-------|-------------|--------------|-------------|
| Tier 1 | 1,408 | 371 chars | 1,150 chars | **3.1×** |
| Tier 2 | 383 | 414 chars | 1,078 chars | **2.6×** |
| Tier 3 | 657 | 449 chars | 1,360 chars | **3.0×** |

### By Task Type

| Type | Count | Original Avg | Distilled Avg | Improvement |
|------|-------|-------------|--------------|-------------|
| rule_only | 730 | 324 chars | 974 chars | **3.0×** |
| test_only | 513 | 540 chars | 1,388 chars | **2.6×** |
| rule_and_test | 513 | 506 chars | 980 chars | **1.9×** |
| modify_rule | 456 | 196 chars | 1,604 chars | **8.2×** |
| test_from_rule | 118 | 454 chars | 1,145 chars | **2.5×** |
| rule_from_test | 118 | 507 chars | 1,130 chars | **2.2×** |

### By Variant

| Variant | Count | Improvement |
|---------|-------|-------------|
| casual | 152 | **8.2×** |
| phase6_canonical | 30 | **5.6×** |
| terse | 332 | **4.1×** |
| phase6_helper_terse | 26 | **4.0×** |
| canonical | 452 | **3.6×** |
| phase6_helper_behavior | 52 | **3.4×** |
| keyword_heavy, poor_grammar, reordered, vague, verbose | 900 | **2.5×** |
| custom_value_operator_flip, custom_value_value_swap | 58 | **1.8–2.2×** |

---

## Matching Strategy

| Method | Examples | Percentage |
|--------|----------|------------|
| **Direct match** (exact task_id + type) | 2,188 | 89.4% |
| **Fallback match** (same task_id, different type) | 260 | 10.6% |
| **Generated placeholder** | 0 | 0.0% |
| **Total** | **2,448** | **100%** |

- **Direct match**: The distilled trace was generated specifically for that (task_id, type) pair.
- **Fallback match**: Used a distilled trace from the same task_id but a different output type. This occurs for combined types (rule_and_test, rule_from_test, test_from_rule) where a closely related trace from the same task was available.

---

## What Changed (Qualitative)

### Before (Template Traces)
Template-generated traces were short and formulaic:
```
This is a field-level check on `.predicate.buildConfig.tasks[*].invocation.parameters.COMMIT_SHA`.
The field is inside an array, so I need `some item in collection` to iterate and check each element.
Pattern: `deny contains msg if { <condition>; msg := sprintf(...) }`
```

### After (Distilled Traces)
Distilled traces demonstrate deeper domain reasoning:
```
This validates that each task has the COMMIT_SHA parameter recorded. Note this is task-level
commit SHA, different from the pipeline-level `invocation.parameters.revision`.

The path is deeply nested: `input.predicate.buildConfig.tasks[*].invocation.parameters.COMMIT_SHA`.

Pattern:
- Iterate over tasks array with `some task in input.predicate.buildConfig.tasks`
- Check existence with `not task.invocation.parameters.COMMIT_SHA`
- Generate descriptive error message using sprintf with task index

In Tekton, individual task steps may reference specific commits for reproducibility...
```

### Key Improvements
1. **Domain context**: Traces explain *why* the check matters (e.g., SLSA provenance, Tekton pipeline context)
2. **Implementation reasoning**: Step-by-step explanation of the approach, not just the pattern
3. **Edge cases**: Consideration of what happens with missing fields, empty arrays, etc.
4. **Connections**: Links between related concepts (e.g., task-level vs pipeline-level parameters)

---

## File Sizes

| File | Size |
|------|------|
| Original (`rego_sft_merged.jsonl`) | 13 MB |
| Distilled (`rego_sft_distilled.jsonl`) | 15 MB |
| Delta | +2 MB (15% increase) |

---

## Distillation Sources (41 Output Files)

The distilled traces were generated across 41 JSONL files in `sft/phase7_distill_think/output/`:
- `distilled_tier1_rule_only.jsonl` + `_part2.jsonl` — 38 tier 1 rule_only tasks
- `distilled_tier2_rule_only.jsonl` — 12 tier 2 rule_only tasks
- `tier3_rule_only_batch{1-5}*.jsonl` — 42 tier 3 rule_only tasks
- `test_only_distilled_complete.jsonl` + `test_only_batch{2-5}.jsonl` — 92 test_only tasks
- `modify_rule_distilled_complete.jsonl` + `modify_rule_batch{2-8}.jsonl` — 152 modify_rule tasks
- `combined_batch{1-10}.jsonl` — 276 combined tasks (rule_and_test, rule_from_test, test_from_rule)

**Total unique tasks distilled: 612/612 (100%)**

---

## Next Steps

1. **Use the distilled dataset for SFT training**:
   ```
   sft/phase7_distill_think/output/rego_sft_distilled.jsonl
   ```
   This is a drop-in replacement for `rego_sft_merged.jsonl` — same schema, same keys, improved traces.

2. **Update train.py** (if needed): Point `DATA_PATH` to the new file.

3. **Compare training runs**: Train with both original and distilled datasets to measure downstream impact on model reasoning quality.
