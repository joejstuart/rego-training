# AIAgent

A simple setup for running an AI agent using a specified model API and SSL certificate.

## Getting Started

Follow these steps to configure and run the agent.

---

### models.corp documentation

https://gitlab.cee.redhat.com/models-corp/user-documentation


### Set Up Environment Variables

Create a `.env` file in the project root and add the following:

```env
MODEL_API="https://granite-3-2-8b-instruct--apicast-production.apps.int.stc.ai.prod.us-east-1.aws.paas.redhat.com:443/v1"
MODEL_ID="/data/granite-3.2-8b-instruct"
USER_KEY="YOUR-USER_KEY"

JIRA_URL="https://issues.redhat.com"
JIRA_API_TOKEN="YOUR JIRA PAT"
```

### SSL Cert

```bash
echo | openssl s_client -connect granite-3-2-8b-instruct--apicast-production.apps.int.stc.ai.prod.us-east-1.aws.paas.redhat.com:443 | openssl x509 > /tmp/granite-3-2-8b.crt
export SSL_CERT_FILE=/tmp/granite-3-2-8b.crt
```

### Running the agent

```bash
uv run main.py
```

### Example Jira search

The `jira_search` tells the model to use the `search_jira` function.

```
jira-search project = EC AND assignee = jjstuart-rh AND status = 'In Progress'
```

Or more free-form

```
search Jira for all issues in project EC with assignee jjstuart-rh that are 'In Progress'
```

### Summarize Jira issues

```
jira-summarize project = EC AND assignee = jjstuart-rh AND status = 'In Progress'
```

### Help with Jira story creation

Give it details of what you want. The model will return a summary and acceptance criteria.

```
jira-format-ac I want to create a VSA after EC verifies the slsa provenance of an image. This should be configurable with parameters and the VSA should be stored in Rekor
```

---

## Rego Expert — Training a Rego Policy Model

A two-stage training pipeline to fine-tune **Qwen3-14B** into an expert at writing
Rego `deny` rules for SLSA provenance attestation verification.

### Quick Start (from scratch)

```bash
# ─── Prerequisites ───
pip install torch transformers trl peft datasets
brew install opa                             # or install from OPA releases
brew install styrainc/packages/regal         # optional, improves GRPO reward

# ─── Stage 1: SFT (Supervised Fine-Tuning) ───
cd sft/

# Build the data pipeline (each step reads from the previous)
python phase0_catalog/build_catalog.py       # Parse attestation → field catalog
python phase1_instructions/derive_instructions.py  # Catalog → instructions
python phase2_tests/generate_tests.py        # Instructions → Rego tests
python phase3_rules/generate_rules_local.py  # Tests → Rego rules (validates all 60)
python phase5_modifications/generate_modifications.py  # Modification examples
python phase4_dataset/assemble_dataset.py    # Assemble 2,132-example SFT dataset

# Train the SFT model (A100 GPU, ~20GB VRAM)
python train.py

# Test inference
python inference.py --model ./output/rego-expert-14b \
    --prompt "Write Rego policy code that checks task status"

cd ..

# ─── Stage 2: GRPO (Reinforcement Learning) ───

# Build the GRPO dataset (609 prompts)
python -m grpo.build_dataset

# Train GRPO on top of SFT
python -m grpo.train

# Test GRPO model (stacks SFT + GRPO LoRAs)
python sft/inference.py \
    --model grpo/output/rego-expert-grpo-14b \
    --sft-model sft/output/rego-expert-14b \
    --prompt "Write a deny rule that checks task status"
```

### Documentation

| Directory | Description |
|-----------|-------------|
| [`sft/`](sft/README.md) | SFT data pipeline and training — phases 0–5, dataset assembly, training script |
| [`sft/phase0_catalog/`](sft/phase0_catalog/README.md) | Phase 0: Parse attestation → field catalog |
| [`sft/phase1_instructions/`](sft/phase1_instructions/README.md) | Phase 1: Field catalog → natural language instructions |
| [`sft/phase2_tests/`](sft/phase2_tests/README.md) | Phase 2: Instructions → Rego test files |
| [`sft/phase3_rules/`](sft/phase3_rules/README.md) | Phase 3: Tests → Rego rules (validated with `opa test`) |
| [`sft/phase4_dataset/`](sft/phase4_dataset/README.md) | Phase 4: Assemble SFT dataset (2,132 examples) |
| [`sft/phase5_modifications/`](sft/phase5_modifications/README.md) | Phase 5: Rule modification examples |
| [`grpo/`](grpo/README.md) | GRPO training — reward functions, dataset builder, training script, logging |
