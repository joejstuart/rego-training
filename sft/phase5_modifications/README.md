# Phase 5: Rule Modification Examples

## Purpose

Generate training examples that teach the model to **read, understand, and
modify** existing Rego rules — a critical skill for real-world policy
maintenance. While Phases 1–3 teach the model to write rules from scratch,
Phase 5 teaches it to work with existing code.

## Approach

For each of the 60 validated rules from Phase 3, the script generates several
modification tasks. Each task provides:

1. The **original** Rego rule code
2. A **natural-language modification instruction**
3. The correctly **modified** rule code

The modifications are deterministic and programmatic — no LLM required.

## Modification Types

| Type | Applicability | Description |
|------|---------------|-------------|
| `rename_package` | All rules (60) | Rename the package to a curated alternative name |
| `improve_message` | All rules (~58) | Add "VIOLATION: " prefix to all deny messages |
| `change_value` | Tier 1 with literal comparison (~20) | Change an expected literal value |
| `add_missing_check` | Tier 1, no iteration, no existing guard (~12) | Add a deny rule for missing fields |
| `relax_to_allowlist` | Tier 1, no iteration, has set alternatives (~8) | Accept multiple values via set membership |

## Output

- `output/modifications.jsonl` — one record per modification

Each record contains:

```json
{
  "id": "type_check__rename_package",
  "original_task_id": "type_check",
  "tier": 1,
  "package_name": "type_check",
  "mod_type": "rename_package",
  "instruction": "Rename the package from `type_check` to `intoto_statement_type`.",
  "original_rule": "package type_check\n...",
  "modified_rule": "package intoto_statement_type\n..."
}
```

## Integration with Phase 4

Phase 4's `assemble_dataset.py` loads these modification records and generates
training examples with:

- **3 instruction variants** per modification: canonical, terse, casual
- **`<think>` reasoning traces** explaining the modification approach
- The same Qwen3 messages format as all other examples

The user message includes the original code + modification instruction.
The assistant response is the complete modified rule.

## Running

```bash
cd sft/
python phase5_modifications/generate_modifications.py
```

Then re-run Phase 4:

```bash
python phase4_dataset/assemble_dataset.py
```
