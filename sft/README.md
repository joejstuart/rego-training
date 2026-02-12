# SFT Data Pipeline — Rego Expert for SLSA Provenance Attestations

This directory contains the full pipeline for building a Supervised Fine-Tuning
(SFT) dataset to teach Qwen3-14B to write expert Rego rules for SLSA provenance
attestation verification.

## Approach

Rather than scraping generic Rego examples, we derive training data directly
from a **real SLSA provenance attestation** (`data/att.json`). For every
meaningful field and pattern in the attestation, we:

1. Derive a natural language instruction describing what to verify.
2. Write Rego tests that exercise the rule (positive and negative cases).
3. Write the Rego rule that passes those tests.
4. Assemble training examples in multiple flavors with `<think>` reasoning traces.

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
│  Phase 5: Modifications  │  Generate rule-modification training
│  phase5_modifications/   │  examples (rename, change value, add
└──────────┬───────────────┘  guard, relax to set, improve message).
           │                    152 modifications × 3 variants = 456.
           ▼
┌──────────────────────────┐
│  Phase 4: SFT Dataset    │  Assemble training examples with
│  phase4_dataset/         │  12+ instruction variants × 6 output types
└──────────┬───────────────┘  + ambiguous, return directive, and
           │                    custom value compositional variants.
           ▼
┌──────────────────────────┐
│  Phase 6.1: Candidates   │  Normalize policy candidate rules/helpers
│  phase6.1_policy_candidates/ │ into task directories + OPA validation.
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  Phase 6.2: Candidate    │  Assemble candidate tasks into messages
│  Dataset                 │  format records with task_type tags.
│  phase6.2_candidate_dataset/ │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  Phase 6.3: Merge        │  Merge phase4 + phase6.2 into one
│  Datasets                │  reproducible training dataset JSONL.
│  phase6.3_dataset_merge/ │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  SFT Training            │  LoRA fine-tuning on Qwen3-14B
│  train.py                │  (A100 GPU, ~20GB VRAM)
└──────────┬───────────────┘
           │  output/rego-expert-14b/
           ▼
┌──────────────────────────┐
│  GRPO (Stage 2)          │  Reinforcement learning for reasoning
│  ../grpo/                │  See grpo/README.md
└──────────────────────────┘

Total: 2,132 SFT training examples
  write/reversal:     1,380  (7+ variants × 3 types + 2 reversals)
  ambiguous:            105  (schema resolution examples)
  compositional:        133  (return directive variants)
  custom value:          58  (value swap + operator flip)
  modifications:        456  (152 mods × 3 variants)
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
│       └── rego_sft.jsonl             ← 2,132 training examples
│
├── phase5_modifications/
│   ├── README.md                      ← Phase 5 documentation
│   ├── generate_modifications.py      ← Generates rule-modification examples
│   └── output/
│       └── modifications.jsonl        ← 152 modification records
│
├── train.py                           ← SFT training script (LoRA default)
├── inference.py                       ← Inference script (LoRA stacking support)
└── output/
    └── rego-expert-14b/               ← Trained model checkpoints
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
cd sft/

# Phase 0: Build field catalog from attestation
python phase0_catalog/build_catalog.py

# Phase 1: Derive natural language instructions
python phase1_instructions/derive_instructions.py

# Phase 2: Generate Rego tests
python phase2_tests/generate_tests.py

# Phase 3: Generate Rego rules and validate (template-based, no LLM)
python phase3_rules/generate_rules_local.py

# Phase 5: Generate rule-modification examples
python phase5_modifications/generate_modifications.py

# Phase 4: Assemble final SFT dataset (includes all variants + Phase 5)
python phase4_dataset/assemble_dataset.py

# Phase 6.1: Build phase-style tasks from policy_release_candidates
python phase6.1_policy_candidates/build_tasks.py

# Phase 6.2: Assemble candidate-only SFT records
python phase6.2_candidate_dataset/assemble_dataset.py

# Phase 6.3: Merge phase4 dataset + phase6.2 dataset
python phase6.3_dataset_merge/merge_datasets.py

# Train (on A100 GPU)
python train.py              # LoRA (default, ~20GB VRAM)
python train.py --dataset ./phase6.3_dataset_merge/output/rego_sft_merged.jsonl
python train.py --no-lora    # Full fine-tuning (~60GB VRAM)
python train.py --dry-run    # Print config without training
```

## Inference

After training, use the inference script:

```bash
cd sft/

# Interactive chat
python inference.py --model ./output/rego-expert-14b

# Single prompt
python inference.py --model ./output/rego-expert-14b \
    --prompt "Write Rego policy code to validate predicateType"

# Use the base model (no fine-tuning) for comparison
python inference.py --model Qwen/Qwen3-14B

# Disable thinking (faster, no <think> block)
python inference.py --model ./output/rego-expert-14b --no-think

# GRPO model (stacks SFT + GRPO LoRAs)
python inference.py \
    --model ../grpo/output/rego-expert-grpo-14b \
    --sft-model ./output/rego-expert-14b \
    --prompt "Write a deny rule that checks task status"
```

## Instruction Variants

The SFT dataset includes the following instruction variant types:

| Variant | Description |
|---------|-------------|
| **canonical** | Original clean instruction from Phase 1 |
| **terse** | Minimal, telegram-style |
| **verbose** | Over-explained, redundant |
| **poor_grammar** | Typos, missing articles, broken syntax |
| **reordered** | Constraint before context |
| **keyword_heavy** | Rego jargon throughout |
| **vague** | Under-specified but answerable |
| **casual** | Informal "can you" framing (modifications only) |
| **ambiguous** | Schema-ambiguous prompts requiring path resolution |
| **return_directive** | Explicit instructions on what the `msg` should contain |
| **custom_value_value_swap** | Different literal value, same operator |
| **custom_value_operator_flip** | Flipped operator (`!=` ↔ `==`) with new literal |

## Dataset Composition

```
Write from scratch:
  60 tasks × 7 variants × 3 output types  = 1,260
  60 tasks × 1 canonical × 2 reversals    =   120
                                  Subtotal: 1,380

Ambiguous (schema resolution):
  35 tasks × 3 output types               =   105

Compositional (return directives):
  ~44 tasks × ~3 variants                 =   133

Custom value (value swap + operator flip):
  29 value_swap + 29 operator_flip         =    58

Rule modifications (Phase 5):
  152 modifications × 3 variants           =   456

                                     Total: 2,132
```

## `<think>` Reasoning Traces

Every example includes a `<think>` block that teaches the model HOW to
approach the problem before writing code:

- **Standard traces** (tier-aware): Identify fields, iteration strategy,
  comparison pattern.
- **Schema-resolution traces** (ambiguous variants): Map informal field names
  to correct attestation paths.
- **Compositional traces** (return directives, custom values): Explicitly
  decompose the task into DATA → CONDITION → RETURN components.

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

### Why six SFT output types?

Different use cases require the model to work in different directions:
- User provides requirements → model writes rule + tests
- User has existing tests → model writes rule to pass them
- User has existing rule → model writes tests for it
- User has existing rule → model modifies it as instructed

Training on all six directions builds flexible understanding rather than
one-directional pattern matching. The modification type (Phase 5) is
critical for real-world policy maintenance where rules evolve over time.

### Why compositional variants (return directives, custom values)?

These teach the model that rules follow a **DATA → CONDITION → RETURN**
structure. By varying only the RETURN or the CONDITION independently, the
model learns to compose rules from parts rather than memorize fixed examples.
This is critical for instruction following — the model must obey what the
user asks for in the return value, not always produce a default message.

### The `deny` convention

Following the Enterprise Contract policy pattern, all rules use
`deny contains result if { ... }` — the rule fires when something is **wrong**
with the attestation. Instructions are phrased as "deny if X is missing/wrong."

## Interpreting Training Metrics

During SFT training, the trainer logs a set of metrics every 10 steps (and
at each epoch boundary for eval). This section explains what each number means,
what healthy values look like, and how to spot problems.

### Metric Reference

| Metric | What it measures |
|--------|-----------------|
| `loss` | Cross-entropy loss on the **training** set. How surprised the model is by the correct next token, averaged over the logging window. Lower is better. |
| `eval_loss` | Same cross-entropy loss measured on the **held-out eval set** (~5% of data). The ground-truth measure of generalization. |
| `mean_token_accuracy` | Fraction of tokens where the model's top-1 prediction matches the target, averaged over the logging window. A direct readability proxy — 0.95 means the model gets 95 out of 100 tokens right. |
| `eval_mean_token_accuracy` | Token accuracy on the held-out eval set. |
| `entropy` | Shannon entropy of the model's output distribution, averaged across tokens. High entropy = the model spreads probability across many tokens (uncertain). Low entropy = the model is nearly deterministic. |
| `grad_norm` | L2 norm of the gradient vector before clipping (`max_grad_norm=1.0`). Measures how aggressively the optimizer wants to update the weights. |
| `learning_rate` | Current learning rate after the scheduler (warmup + cosine decay). |
| `num_tokens` | Cumulative tokens processed so far (across all steps). |
| `epoch` | Fractional epoch progress (0.0 → `num_train_epochs`). |

### Healthy Training Trajectory

A well-behaved SFT run on this dataset (~2,132 examples, 3 epochs) looks
roughly like this:

**Epoch 1 — Rapid learning phase:**
- `loss` drops steeply (1.7 → 0.17). This is where most of the Rego syntax
  and pattern learning happens.
- `mean_token_accuracy` climbs from ~0.76 to ~0.96.
- `grad_norm` starts high (~1.8) and settles to ~0.5–0.6.
- `entropy` may spike early during LR warmup (the model temporarily becomes
  *more* uncertain as the learning rate ramps up), then falls steadily.

**Epoch 2 — Refinement phase:**
- `loss` continues to improve but decelerates (0.15 → 0.06).
- `mean_token_accuracy` climbs from ~0.96 to ~0.98.
- `grad_norm` settles to ~0.2–0.35.
- `entropy` drops below 0.10 — the model is becoming very confident.

**Epoch 3 — Diminishing returns:**
- `loss` is nearly flat (0.06–0.07). Very little new learning.
- `mean_token_accuracy` plateaus around 0.98–0.99.
- `entropy` may drop to 0.06 or lower — near-deterministic predictions.
- Gradient norms are small and stable.

### What to Watch For

#### Overfitting
- **Symptom:** `eval_loss` starts *increasing* while `loss` continues to
  decrease (or `eval_mean_token_accuracy` drops while training accuracy rises).
- **Cause:** The model is memorizing training examples rather than learning
  generalizable patterns.
- **Fix:** Reduce epochs (try 2 instead of 3), increase `weight_decay`, or
  add more training data.

#### Entropy Collapse
- **Symptom:** `entropy` drops below ~0.05 and keeps falling.
- **Cause:** The model is outputting near-deterministic distributions. Fine for
  structured code generation (Rego is formulaic), but problematic if the model
  becomes brittle on novel prompts.
- **Watch for:** This is expected to some degree on a small, formulaic dataset.
  If downstream evaluation shows degraded performance on out-of-distribution
  prompts, use an earlier checkpoint with higher entropy.

#### Gradient Explosion / Instability
- **Symptom:** `grad_norm` spikes above 1.0 or oscillates wildly.
- **Cause:** Learning rate too high, batch too small, or corrupted data.
- **Fix:** The `max_grad_norm=1.0` clipping should prevent catastrophe, but
  persistent spikes suggest lowering the learning rate or increasing batch size.

#### Loss Plateau Early
- **Symptom:** `loss` stops improving within the first epoch.
- **Cause:** Learning rate too low, model capacity issue, or data quality
  problem (e.g., empty/malformed examples).
- **Fix:** Increase learning rate, check dataset for quality issues with
  `--dry-run`.

### Eval Checkpoints

The trainer evaluates at each epoch boundary and saves checkpoints. The eval
metrics are the most trustworthy signal:

| Checkpoint | Key question | Decision |
|-----------|--------------|----------|
| Epoch 1 | Is `eval_loss` substantially lower than the start? | If not, something is wrong. |
| Epoch 2 | Is `eval_loss` still improving over epoch 1? | If yes, epoch 2 is worth it. |
| Epoch 3 | Is `eval_loss` improving over epoch 2? | If barely / not at all, use the epoch 2 checkpoint. |

For this dataset, the sweet spot is typically **epoch 2**: strong `eval_loss`
(~0.055) and high accuracy (~98.6%) without excessive entropy collapse.

### Reading the Progress Bar

```
62%|████████████████████▋            | 236/381 [1:01:51<37:29, 15.52s/it]
```

| Part | Meaning |
|------|---------|
| `62%` | Percentage of total training steps completed |
| `236/381` | Current step / total steps |
| `1:01:51` | Elapsed time |
| `37:29` | Estimated time remaining |
| `15.52s/it` | Seconds per step (one step = one optimizer update = `batch_size × grad_accum` examples) |

### Tips for Downstream Use (GRPO)

If this SFT model feeds into the GRPO reinforcement learning stage
(`../grpo/`), consider the following:

- **GRPO benefits from exploration.** A slightly under-trained SFT model
  (epoch 1.5–2) with higher entropy gives GRPO more room to discover improved
  reasoning strategies through its reward signal.
- **A fully converged SFT model** (epoch 3, entropy ~0.06) may be too rigid
  for GRPO to improve, because the policy already assigns near-zero probability
  to alternative phrasings.
- **Recommendation:** Use the **epoch 2 checkpoint** as the GRPO starting
  point unless downstream evaluation shows otherwise.
