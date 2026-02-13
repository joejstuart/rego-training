# Phase 6.1: Policy Candidate Tasks

## Purpose

Normalize `sft/policy_release_candidates` into a phase-style task layout
compatible with the rest of the pipeline, and validate each task with OPA and Regal.

Also ingests helper-oriented Rego library files from:

- `policy/lib/**`

This phase creates one task directory per candidate package with:

- `<package>.rego`
- `<package>_test.rego`
- `_validation/` temporary validation workspace (generated during run)
- `result.json` (`pass` / `fail` / `error`) with `opa_check`, `opa_test`, `regal_lint`
- `meta.json` (`task_type`, source path)

## Input

- `sft/policy_release_candidates/*.rego`
- `sft/policy_release_candidates/*_test.rego`
- `sft/policy_release_candidates/helper_methods/*.rego`
- `sft/policy_release_candidates/helper_methods/*_test.rego`
- `policy/lib/**/*.rego`
- `policy/lib/**/*_test.rego`

## Output

- `sft/phase6.1_policy_candidates/output/tasks/<task_id>/...`
- `sft/phase6.1_policy_candidates/output/summary.json`

## Running

```bash
cd /Users/jstuart/Documents/repos/aiagent/sft
python phase6.1_policy_candidates/build_tasks.py
```
