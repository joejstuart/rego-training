# Phase 0: Field Catalog

## Purpose

Parse the source attestation (`data/att.json`) into a structured catalog of
every unique JSON path, its observed values, and metadata. This catalog is the
foundation for all subsequent phases — instructions, tests, and rules are all
derived from it.

## What it does

The `build_catalog.py` script:

1. **Loads** the attestation JSON.
2. **Recursively walks** every field, tracking the full JSON path.
3. **Deduplicates** across repeated structures (e.g., the 16 tasks in
   `predicate.buildConfig.tasks` share many identical annotation keys).
4. **Classifies** each entry by tier:
   - `top_level` — Statement-level fields (`_type`, `predicateType`, `subject`)
   - `predicate_level` — Predicate metadata (`buildType`, `builder`, `materials`)
   - `task_level` — Per-task fields found across multiple tasks
   - `result_level` — Task result fields
   - `step_level` — Task step fields
5. **Outputs** `field_catalog.jsonl` — one JSON object per line.

## Output format

Each line in `field_catalog.jsonl` is a JSON object:

```json
{
  "id": "predicate_type",
  "path": ".predicateType",
  "description": "SLSA predicate type URI",
  "tier": "top_level",
  "value_type": "string",
  "observed_values": ["https://slsa.dev/provenance/v0.2"],
  "cardinality": "single",
  "tasks_with_field": null
}
```

For task-level fields, `tasks_with_field` lists which tasks contain it:

```json
{
  "id": "task_status",
  "path": ".predicate.buildConfig.tasks[*].status",
  "description": "Task execution status",
  "tier": "task_level",
  "value_type": "string",
  "observed_values": ["Succeeded"],
  "cardinality": "per_task",
  "tasks_with_field": ["init", "clone-repository", "build-container-amd64", ...]
}
```

## Running

```bash
cd sft/
python phase0_catalog/build_catalog.py
```

Output is written to `phase0_catalog/output/field_catalog.jsonl`.

## Field count expectations

From the golden-container attestation, expect roughly:

| Tier | Estimated unique fields |
|------|------------------------|
| top_level | 4-5 |
| predicate_level | 5-6 |
| task_level | 15-20 (annotations, labels, parameters, ref, status, etc.) |
| result_level | 10-15 unique result names |
| step_level | 3-5 |
| **Total** | **~40-50 unique catalog entries** |

These become the seeds for ~230+ training examples in Phase 4.
