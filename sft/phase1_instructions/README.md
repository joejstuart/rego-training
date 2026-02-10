# Phase 1: Derive Natural Language Instructions

## Purpose

Transform the field catalog from Phase 0 into natural language instructions
that describe what each Rego rule should verify. These instructions become
the "prompt" side of the SFT training data.

## Input

- `phase0_catalog/output/field_catalog.jsonl` — the field catalog

## Output

- `phase1_instructions/output/instructions.jsonl` — one instruction per line

## Instruction tiers

Instructions are generated at three levels of complexity:

### Tier 1 — Field-level (simple, auto-generated)

One rule per catalog entry. These check a single field against an expected
value or pattern.

Example:
> Write a Rego rule that denies an attestation if `.predicateType` is not
> `https://slsa.dev/provenance/v0.2`.

### Tier 2 — Pattern-level (across tasks, auto-generated)

Rules that iterate across arrays (tasks, results, subjects) checking a
property holds for all/some elements.

Example:
> Write a Rego rule that denies if any task in
> `.predicate.buildConfig.tasks` does not use a `bundles` resolver for its
> task reference.

### Tier 3 — Composite/semantic (human-curated or LLM-assisted)

Cross-cutting rules combining multiple fields for real-world policy logic.
These require understanding the *meaning* of the fields, not just their
structure.

Example:
> Write a Rego rule that denies if any task producing an `IMAGE_DIGEST`
> result did not complete with status `Succeeded`.

## Output format

```json
{
  "id": "predicate_type_check",
  "tier": 1,
  "catalog_ids": ["predicate_type"],
  "instruction": "Write a Rego deny rule that rejects an attestation if the predicateType is not...",
  "package_name": "predicate_type_check",
  "input_paths": [".predicateType"],
  "mock_data": {"predicateType": "https://slsa.dev/provenance/v0.2"}
}
```

## Running

```bash
cd sft/
python phase1_instructions/derive_instructions.py
```
