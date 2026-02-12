# Phase 6.2: Candidate Dataset Assembly

## Purpose

Convert validated Phase 6.1 tasks into Qwen3 `messages` JSONL records.

This phase emits a focused dataset for policy candidate rules and helper methods.
Helper tasks get extra prompt variants to increase helper-method coverage.

## Input

- `sft/phase6.1_policy_candidates/output/tasks/*`

## Output

- `sft/phase6.2_candidate_dataset/output/policy_candidates_sft.jsonl`

Each line includes:

- `messages`
- `task_id`
- `tier` (fixed to `3` for this phase)
- `variant` (`phase6_canonical`)
  - helper variants: `phase6_helper_*`
- `type` (`rule_only`, `test_only`, `rule_and_test`, `rule_from_test`, `test_from_rule`)
- `task_type` (`deny_rule` or `helper_method`)
- `source` (`phase6_policy_candidates`)

## Running

```bash
cd /Users/jstuart/Documents/repos/aiagent/sft
python phase6.2_candidate_dataset/assemble_dataset.py
```
