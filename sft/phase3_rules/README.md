# Phase 3: Generate Rego Rules and Validate

## Purpose

For each (instruction, test) pair from Phases 1 and 2, generate the Rego rule
that satisfies the tests. Validate every rule by running `opa test`.

Two scripts are available:

| Script | Method | Reproducible | Notes |
|--------|--------|:---:|-------|
| `generate_rules_local.py` | Deterministic templates | ✅ | 100% pass rate, no API needed |
| `generate_rules.py` | LLM via OpenAI-compatible API | ❌ | ~90% pass rate, needs API access |

## Input

- `phase1_instructions/output/instructions.jsonl` — instructions
- `phase2_tests/output/tasks/` — test files

## Output

- `phase3_rules/output/tasks/<task_id>/` — directories containing:
  - `<package_name>.rego` — the rule file
  - `<package_name>_test.rego` — copied from Phase 2
  - `result.json` — validation result (`pass`/`fail`/`error`)

## Rule convention

All rules follow the Enterprise Contract `deny` pattern:

```rego
package predicate_type_check

import rego.v1

deny contains msg if {
    input.predicateType != "https://slsa.dev/provenance/v0.2"
    msg := "Attestation predicateType is not SLSA provenance v0.2"
}
```

Key conventions:
- Package name matches the instruction ID
- `import rego.v1` for modern Rego syntax
- `deny contains msg if { ... }` — fires when something is wrong
- `msg` is a human-readable string describing the violation

### Rule patterns by tier

**Tier 1 (field-level):** Single-field equality or presence checks.
```rego
deny contains msg if {
    some task in input.predicate.buildConfig.tasks
    task.status != "Succeeded"
    msg := sprintf("status is %v, expected Succeeded", [task.status])
}
```

**Tier 2 (pattern-level):** Iterate collections, check all elements satisfy.
```rego
deny contains msg if {
    some task in input.predicate.buildConfig.tasks
    param_names := {p.name | some p in task.ref.params}
    missing := {"name", "bundle", "kind"} - param_names
    count(missing) > 0
    msg := sprintf("task %v is missing ref params: %v", [task.name, missing])
}
```

**Tier 3 (composite):** Cross-field logic with helper rules.
```rego
deny contains msg if {
    some task in input.predicate.buildConfig.tasks
    _is_scan_task(task)
    not _has_result(task, "TEST_OUTPUT")
    msg := sprintf("scan task %v missing TEST_OUTPUT", [task.name])
}

_is_scan_task(task) if contains(task.name, "scan")
_is_scan_task(task) if contains(task.name, "sast")

_has_result(task, name) if {
    some result in task.results
    result.name == name
}
```

## Validation

Each rule is validated by running:

```bash
cd phase3_rules/output/tasks/<task_id>/
opa check .          # Syntax check (rule + test)
opa test . -v        # Functional check (tests pass)
```

Results are recorded in `result.json`:
```json
{
  "task_id": "predicate_type_check",
  "opa_check": "pass",
  "opa_test": "pass",
  "status": "pass"
}
```

## Running

```bash
cd sft/

# Local (deterministic, recommended):
python phase3_rules/generate_rules_local.py

# LLM-assisted (requires API):
python phase3_rules/generate_rules.py \
    --api-url http://localhost:11434/v1 \
    --model qwen3-coder:30b \
    --api-key ollama

# Resume, skipping already-passing tasks:
python phase3_rules/generate_rules.py --skip-passing
```

## Results

60 rules generated and validated, 60/60 passing `opa test`:

| Tier | Count | Pattern |
|------|-------|---------|
| 1    | 38    | Single-field equality/presence checks |
| 2    | 12    | All-elements-must-satisfy iteration |
| 3    | 10    | Cross-field composite logic |
