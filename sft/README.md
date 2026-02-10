# SFT Data Pipeline — Rego Expert for SLSA Provenance Attestations

This directory contains the full pipeline for building a Supervised Fine-Tuning
(SFT) dataset to teach Qwen3-4B to write expert Rego rules for SLSA provenance
attestation verification.

## Approach

Rather than scraping generic Rego examples, we derive training data directly
from a **real SLSA provenance attestation** (`data/att.json`). For every
meaningful field and pattern in the attestation, we:

1. Derive a natural language instruction describing what to verify.
2. Write Rego tests that exercise the rule (positive and negative cases).
3. Write the Rego rule that passes those tests.
4. Assemble training examples in multiple flavors.

This bottom-up approach ensures every training example is grounded in
production-realistic data and is machine-verifiable via `opa test`.

## Pipeline Overview

```
att.json
   │
   ▼
┌──────────────────────────┐
│  Phase 0: Field Catalog  │  Parse attestation → structured catalog of
│  phase0_catalog/         │  every unique JSON path, value, and type.
└──────────┬───────────────┘
           │  field_catalog.jsonl
           ▼
┌──────────────────────────┐
│  Phase 1: Instructions   │  Derive natural language instructions at
│  phase1_instructions/    │  three tiers: field-level, pattern-level,
└──────────┬───────────────┘  and composite/semantic.
           │  instructions.jsonl
           ▼
┌──────────────────────────┐
│  Phase 2: Rego Tests     │  Generate Rego test files for each
│  phase2_tests/           │  instruction. Every test has positive
└──────────┬───────────────┘  AND negative cases. Validate with
           │  tasks/*/          `opa check`.
           ▼
┌──────────────────────────┐
│  Phase 3: Rego Rules     │  Generate rules (template-based, no LLM)
│  phase3_rules/           │  that pass the tests. Validate with
└──────────┬───────────────┘  `opa test`. 60/60 pass.
           │  tasks/*/
           ▼
┌──────────────────────────┐
│  Phase 4: SFT Dataset    │  Assemble 1,380 training examples with
│  phase4_dataset/         │  7 instruction variants × 5 output types:
└──────────────────────────┘    variants: canonical, terse, verbose,
                                poor_grammar, reordered, keyword_heavy,
                                vague
                                types: rule_only, test_only,
                                rule_and_test, rule_from_test,
                                test_from_rule
```

## Directory Structure

```
sft/
├── README.md                          ← You are here
├── data/
│   ├── att.json                       ← Source attestation (symlinked)
│   ├── opa_policy_testing.md          ← OPA testing reference (symlinked)
│   ├── opa-policy-language.md         ← Rego language guide (symlinked)
│   └── rego-style-guide.md            ← Rego style guide (symlinked)
│
├── phase0_catalog/
│   ├── README.md                      ← Phase 0 documentation
│   ├── build_catalog.py               ← Parses att.json → field catalog
│   └── output/
│       └── field_catalog.jsonl        ← Generated catalog
│
├── phase1_instructions/
│   ├── README.md                      ← Phase 1 documentation
│   ├── derive_instructions.py         ← Generates NL instructions from catalog
│   └── output/
│       └── instructions.jsonl         ← Generated instructions
│
├── phase2_tests/
│   ├── README.md                      ← Phase 2 documentation
│   ├── generate_tests.py              ← Generates Rego test files
│   └── output/
│       └── tasks/                     ← One directory per instruction
│           └── <task_id>/
│               └── <name>_test.rego
│
├── phase3_rules/
│   ├── README.md                      ← Phase 3 documentation
│   ├── generate_rules_local.py        ← Template-based rule generation (no LLM)
│   ├── generate_rules.py              ← LLM-assisted generation (alternative)
│   └── output/
│       └── tasks/                     ← One directory per instruction
│           └── <task_id>/
│               ├── <name>.rego
│               ├── <name>_test.rego   ← Copied from Phase 2
│               └── result.json        ← opa check + opa test results
│
├── phase4_dataset/
│   ├── README.md                      ← Phase 4 documentation
│   ├── assemble_dataset.py            ← Assembles final JSONL dataset
│   └── output/
│       └── rego_sft.jsonl             ← 1,380 training examples
│
├── train.py                           ← SFT training script (LoRA default)
└── output/
    └── rego-expert/                   ← Trained model checkpoints
```

## Prerequisites

- Python 3.10+
- OPA CLI (`opa`) — used for `opa check` (syntax) and `opa test` (validation)
- The source attestation at `../att.json`

For training (A100 GPU):
```bash
pip install torch transformers trl peft datasets
```

Install OPA:
```bash
# Linux (amd64)
curl -L -o /usr/local/bin/opa \
  https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod 755 /usr/local/bin/opa

# macOS
brew install opa
```

## Running the Pipeline

Each phase is run independently and reads from the previous phase's output:

```bash
# Phase 0: Build field catalog from attestation
python phase0_catalog/build_catalog.py

# Phase 1: Derive natural language instructions
python phase1_instructions/derive_instructions.py

# Phase 2: Generate Rego tests
python phase2_tests/generate_tests.py

# Phase 3: Generate Rego rules and validate (template-based, no LLM)
python phase3_rules/generate_rules_local.py

# Phase 4: Assemble final SFT dataset
python phase4_dataset/assemble_dataset.py

# Train (on A100 GPU)
python train.py              # LoRA (default, ~20GB VRAM)
python train.py --no-lora    # Full fine-tuning (~60GB VRAM)
python train.py --dry-run    # Print config without training
```

## Design Decisions

### Why start from a real attestation?

Every field in the catalog exists in production. This prevents the model from
learning to write rules for hallucinated fields or schemas that don't match
reality.

### Why three instruction tiers?

- **Tier 1 (field-level):** Simple single-field checks. Builds basic Rego
  fluency.
- **Tier 2 (pattern-level):** Rules that iterate across tasks or array
  elements. Teaches `some x in collection` patterns.
- **Tier 3 (composite/semantic):** Cross-cutting rules combining multiple
  fields. Teaches real-world policy logic.

### Why positive AND negative tests?

A rule with only positive tests could be vacuously true (`deny` never fires).
Negative tests prove the rule actually catches problems. Every test file must
contain at least one case where `deny` fires and one where it doesn't.

### Why five SFT flavors?

Different use cases require the model to work in different directions:
- User provides requirements → model writes rule + tests
- User has existing tests → model writes rule to pass them
- User has existing rule → model writes tests for it

Training on all five directions builds flexible understanding rather than
one-directional pattern matching.

### The `deny` convention

Following the Enterprise Contract policy pattern, all rules use
`deny contains result if { ... }` — the rule fires when something is **wrong**
with the attestation. Instructions are phrased as "deny if X is missing/wrong."
