# Phase 4: Assemble SFT Dataset (Qwen3-Optimized)

## Purpose

Combine validated (instruction, rule, test) triples from Phases 1-3 into the
final SFT training dataset, optimized for **Qwen3-4B**. Each triple is expanded
with 7 instruction variants across 5 output types, with a domain-specific
system prompt and `<think>` reasoning traces.

## Qwen3 Optimizations

### 1. Messages format (ChatML)

Each example uses the Qwen3 `messages` format directly compatible with
HuggingFace's `SFTTrainer`:

```json
{
  "messages": [
    {"role": "system", "content": "You are an expert in the Rego policy language..."},
    {"role": "user", "content": "Write a Rego deny rule that..."},
    {"role": "assistant", "content": "<think>\n...reasoning...\n</think>\n\n...code..."}
  ]
}
```

### 2. Domain-specific system prompt

A consistent system prompt establishes the Rego expert persona and conventions:
- Rego v1 syntax (`import rego.v1`)
- `deny contains msg if { ... }` partial set pattern
- `some x in collection` iteration
- `sprintf` for deny messages
- `count(<pkg>.deny) == 0` / `> 0` test assertions

### 3. `<think>` reasoning traces

Every example includes a `<think>` block that teaches the model HOW to
approach the problem before writing code. The traces are deterministic and
tier-aware:

- **Tier 1** (field-level): Brief — identifies the field, notes whether
  iteration is needed, states the comparison pattern.
- **Tier 2** (pattern-level): Medium — describes the iteration strategy,
  set operations, helper functions, and per-element deny messages.
- **Tier 3** (composite): Detailed — breaks down multi-field logic, identifies
  needed built-ins (`time.parse_rfc3339_ns`, `startswith`), helper functions,
  and comprehensions.

Traces are also tailored to the output type:
- `rule_only`: Focuses on rule construction approach
- `test_only`: Focuses on positive/negative test design
- `rule_and_test`: Combines both
- `rule_from_test`: Analyzes test expectations to derive the rule
- `test_from_rule`: Analyzes rule behavior to derive test cases

### 4. Token-length audit

The script includes a `--audit` flag that runs the Qwen3-4B tokenizer over
every example and reports token statistics.

## Input

- `phase1_instructions/output/instructions.jsonl` — 60 canonical instructions
- `phase3_rules/output/tasks/` — 60 validated rule + test pairs (all passing)

## Output

- `phase4_dataset/output/rego_sft.jsonl` — final training dataset

## Instruction Variants

| Variant | Description | Example |
|---------|-------------|---------|
| **canonical** | Original clean instruction from Phase 1 | "Write a Rego deny rule that rejects..." |
| **terse** | Minimal, telegram-style | "deny if predicateType wrong" |
| **verbose** | Over-explained, redundant | "I need you to write a Rego policy rule..." |
| **poor_grammar** | Typos, missing articles, broken syntax | "write rego deny rule that reject attestation if..." |
| **reordered** | Constraint before context | "If the predicateType is wrong, reject. Write a rule." |
| **keyword_heavy** | Rego jargon throughout | "Create a partial set rule `deny contains msg if`..." |
| **vague** | Under-specified but answerable | "Write a rule to verify the SLSA predicate type." |

## Output Types

| Type | Count | Description |
|------|-------|-------------|
| `rule_only` | 420 | instruction → rule |
| `test_only` | 420 | instruction → tests |
| `rule_and_test` | 420 | instruction → rule + tests |
| `rule_from_test` | 60 | tests → rule (canonical only) |
| `test_from_rule` | 60 | rule → tests (canonical only) |

## Math

```
60 tasks × 7 variants × 3 output types  = 1,260
60 tasks × 1 canonical × 2 reversals    =   120
                                    Total: 1,380
```

## Results

- **1,380 training examples** generated
- **0 tasks skipped** (all 60 passed Phase 3)
- **1,380 unique user messages** (zero duplicates)
- **1,380/1,380 examples have `<think>` traces**
- **0 empty responses**

### Token audit (Qwen3-4B tokenizer)

```
Token counts per example:
  min:    265
  p25:    394
  median: 588
  p75:    664
  p95:    915
  max:    1126
  total:  782,258
  > 1024 tokens: 15 examples (1.1%)

Recommended max_seq_length: 2048 (covers p99=1038)

By tier:
  Tier 1: median=589, max=1104
  Tier 2: median=581, max=1051
  Tier 3: median=587, max=1126
```

### Breakdown by tier

| Tier | Examples |
|------|----------|
| Tier 1 (field-level) | 874 |
| Tier 2 (pattern-level) | 276 |
| Tier 3 (composite) | 230 |

### `<think>` trace lengths

```
min=127 chars, median=428 chars, max=691 chars
```

### File size

~3.4 MB

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
    output_dir="./rego-expert",
    max_seq_length=2048,         # covers p99 of our data
    per_device_train_batch_size=4,
    num_train_epochs=3,
    learning_rate=2e-5,
    bf16=True,                   # A100 optimization
)
```
