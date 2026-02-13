# Phase 4: Assemble SFT Dataset (Qwen3-Optimized)

## Purpose

Combine validated (instruction, rule, test) triples from Phases 1-3 into the
final SFT training dataset, optimized for **Qwen3-8B**. Each triple is expanded
with multiple instruction variants across 6 output types, with a domain-specific
system prompt (including schema map) and `<think>` reasoning traces.

## Qwen3 Optimizations

### 1. Messages format (ChatML)

Each example uses the Qwen3 `messages` format directly compatible with
HuggingFace's `SFTTrainer`:

```json
{
  "messages": [
    {"role": "system", "content": "You are an expert in the Rego policy language..."},
    {"role": "user", "content": "Write Rego policy code (deny rule or helper method) that..."},
    {"role": "assistant", "content": "<think>\n...reasoning...\n</think>\n\n...code..."}
  ],
  "task_type": "deny_rule | helper_method"
}
```

### 2. Domain-specific system prompt (with schema map)

A consistent system prompt establishes the Rego expert persona and conventions:
- Rego v1 syntax (`import rego.v1`)
- choose the right output for the task: deny rule or standalone helper method
- `deny contains msg if { ... }` when the task is a policy decision check
- `some x in collection` iteration
- `sprintf` for deny messages
- deny-rule tests: `count(<pkg>.deny) == 0` / `> 0`; helper tests assert helper output directly
- **SLSA Attestation Schema Map** — a structured reference showing all valid
  `input.*` paths, enabling the model to resolve ambiguous field names
  (e.g., "digest.sha" → `input.predicate.materials[*].digest.sha256`)

### 3. `<think>` reasoning traces

Every example includes a `<think>` block that teaches the model HOW to
approach the problem before writing code. The traces are deterministic and
vary by context:

**Standard traces (tier-aware):**
- **Tier 1** (field-level): Brief — identifies the field, notes whether
  iteration is needed, states the comparison pattern.
- **Tier 2** (pattern-level): Medium — describes the iteration strategy,
  set operations, helper functions, and per-element deny messages.
- **Tier 3** (composite): Detailed — breaks down multi-field logic, identifies
  needed built-ins, helper functions, and comprehensions.

**Schema-resolution traces (ambiguous variants):**
- Map informal user language to the correct attestation path
- Show the reasoning: "I don't see `digest.sha` but I do see `digest.sha256`"

**Compositional traces (return directives, custom values):**
- Explicitly decompose the task into DATA → CONDITION → RETURN
- Include VALUE / OPERATOR reasoning for custom value variants

Traces are also tailored to the output type:
- `rule_only`: Focuses on rule construction approach
- `test_only`: Focuses on positive/negative test design
- `rule_and_test`: Combines both
- `rule_from_test`: Analyzes test expectations to derive the rule
- `test_from_rule`: Analyzes rule behavior to derive test cases

### 4. Token-length audit

The script includes a `--audit` flag that runs the Qwen3-8B tokenizer over
every example and reports token statistics.

## Input

- `phase1_instructions/output/instructions.jsonl` — 60 canonical instructions
- `phase3_rules/output/tasks/` — 60 validated rule + test pairs (all passing)
- `phase5_modifications/output/modifications.jsonl` — 152 rule-modification records

## Output

- `phase4_dataset/output/rego_sft.jsonl` — final training dataset

## Instruction Variants

| Variant | Description | Example |
|---------|-------------|---------|
| **canonical** | Original clean instruction from Phase 1 | "Write Rego policy code that rejects..." |
| **terse** | Minimal, telegram-style | "rego check if predicateType wrong" |
| **verbose** | Over-explained, redundant | "I need you to write a Rego policy rule..." |
| **poor_grammar** | Typos, missing articles, broken syntax | "write rego rule/helper that reject attestation if..." |
| **reordered** | Constraint before context | "If the predicateType is wrong, reject. Write a rule." |
| **keyword_heavy** | Rego jargon throughout | "Create Rego policy code; use `deny contains msg if` when needed..." |
| **vague** | Under-specified but answerable | "Write a rule to verify the SLSA predicate type." |
| **casual** | Informal "can you" framing (modifications only) | "Can you rename the package from X to Y?" |
| **ambiguous** | Schema-ambiguous prompts | "deny if materials digest.sha equals '1234'" |
| **return_directive** | Explicit return instructions | "Return only the task name in the deny message" |
| **custom_value_value_swap** | Different literal value, same operator | Changes `"Succeeded"` to `"Running"` |
| **custom_value_operator_flip** | Flipped operator with new literal | Changes `!= "Succeeded"` to `== "Failed"` |

## Output Types

| Type | Count | Description |
|------|-------|-------------|
| `rule_only` | 646 | instruction → rule |
| `test_only` | 455 | instruction → tests |
| `rule_and_test` | 455 | instruction → rule + tests |
| `rule_from_test` | 60 | tests → rule (canonical only) |
| `test_from_rule` | 60 | rule → tests (canonical only) |
| `modify_rule` | 456 | original rule + instruction → modified rule |

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

## Results

- **2,132 training examples** generated
- **0 tasks skipped** (all 60 passed Phase 3)
- **2,132/2,132 examples have `<think>` traces**
- **0 empty responses**

### Breakdown by tier

| Tier | Examples |
|------|----------|
| Tier 1 (field-level) | 1,408 |
| Tier 2 (pattern-level) | 383 |
| Tier 3 (composite) | 341 |

### Breakdown by variant

| Variant | Count |
|---------|-------|
| canonical | 452 |
| terse | 332 |
| reordered | 180 |
| poor_grammar | 180 |
| keyword_heavy | 180 |
| verbose | 180 |
| vague | 180 |
| casual | 152 |
| return_directive | 133 |
| ambiguous | 105 |
| custom_value_operator_flip | 29 |
| custom_value_value_swap | 29 |

## Running

```bash
cd sft/

# Generate dataset
python phase4_dataset/assemble_dataset.py

# Generate dataset + run token audit (requires: pip install transformers jinja2)
python phase4_dataset/assemble_dataset.py --audit

# Inspect
wc -l phase4_dataset/output/rego_sft.jsonl
head -1 phase4_dataset/output/rego_sft.jsonl | python -m json.tool
```

## SFT Training

The dataset is ready for use with `trl`'s `SFTTrainer`. Example config:

```python
from trl import SFTConfig, SFTTrainer

training_args = SFTConfig(
    output_dir="./rego-expert-8b",
    max_seq_length=2048,         # covers p99 of our data
    per_device_train_batch_size=4,
    num_train_epochs=3,
    learning_rate=2e-5,
    bf16=True,                   # A100 optimization
)
```

Or use the provided training script:

```bash
cd sft/
python train.py              # LoRA (default)
python train.py --no-lora    # Full fine-tuning
python train.py --dry-run    # Print config only
```
