# Phase 6.3: Dataset Merge

## Purpose

Merge:

- base Phase 4 SFT dataset
- Phase 6.2 policy-candidate dataset

into one reproducible training JSONL file.

## Input

- `sft/phase4_dataset/output/rego_sft.jsonl`
- `sft/phase6.2_candidate_dataset/output/policy_candidates_sft.jsonl`

## Output

- `sft/phase6.3_dataset_merge/output/rego_sft_merged.jsonl`

## Running

```bash
cd /Users/jstuart/Documents/repos/aiagent/sft
python phase6.3_dataset_merge/merge_datasets.py
```
