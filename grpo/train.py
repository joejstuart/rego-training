#!/usr/bin/env python3
"""GRPO training script — converts an SFT-trained Rego expert into a reasoning model.

This is Stage 2 of the training pipeline:
  1. SFT  (sft/train.py)        → teaches Rego syntax, deny patterns, schema grounding
  2. GRPO (this script)          → teaches the model to REASON through ambiguous prompts

Architecture (adapted from the Unsloth Qwen3-4B GRPO notebook):
  - Loads the SFT-trained model (LoRA or merged)
  - Reads a pre-built GRPO dataset (grpo/output/grpo_prompts.jsonl)
  - Uses 5 stacked reward functions scored by OPA / Regal evaluation
  - Runs GRPOTrainer from TRL with vLLM fast inference

Reward functions (see grpo/rewards.py for implementation):
  1. reward_format        — structural compliance (<think>, package, deny pattern)
  2. reward_opa_parse     — syntactic validity via `opa check`
  3. reward_opa_test      — functional correctness via `opa test`
  4. reward_schema_paths  — schema grounding (valid input.* references)
  5. reward_regal_lint    — idiomatic Rego style via `regal lint`

Prerequisites:
  - OPA binary on PATH:   brew install opa  /  go install github.com/open-policy-agent/opa@latest
  - Regal binary on PATH: brew install styrainc/packages/regal
  - Python packages:      pip install unsloth trl vllm datasets torch
  - SFT model:            run sft/train.py first
  - GRPO dataset:         run grpo/build_dataset.py first

Usage:
    # Build the dataset first (only needed once / when SFT data changes)
    python -m grpo.build_dataset

    # GRPO on the SFT-trained model
    python -m grpo.train

    # Point to a specific SFT checkpoint
    python -m grpo.train --sft-model ./sft/output/rego-expert

    # Adjust training
    python -m grpo.train --max-steps 200 --num-generations 8

    # Dry run (loads dataset, prints config, no training)
    python -m grpo.train --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
GRPO_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = GRPO_DIR.parent
SFT_ROOT = PROJECT_ROOT / "sft"
DATASET_PATH = GRPO_DIR / "output" / "grpo_prompts.jsonl"
DEFAULT_SFT_MODEL = str(SFT_ROOT / "output" / "rego-expert")
DEFAULT_OUTPUT_DIR = str(GRPO_DIR / "output" / "rego-expert-grpo")


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULTS = {
    "base_model": "Qwen/Qwen3-4B",
    "sft_model": DEFAULT_SFT_MODEL,
    "output_dir": DEFAULT_OUTPUT_DIR,
    "max_seq_length": 2048,
    "lora_rank": 32,
    "max_steps": 100,
    "num_generations": 4,
    "batch_size": 4,              # must be >= num_generations (GRPO compares N completions per prompt)
    "grad_accum": 1,
    "lr": 5e-6,
    "warmup_ratio": 0.1,
    "seed": 42,
}


# ===========================================================================
# Dataset loader
# ===========================================================================

def _load_grpo_dataset() -> list[dict]:
    """Load the pre-built GRPO dataset from grpo/output/grpo_prompts.jsonl."""
    if not DATASET_PATH.exists():
        print(f"ERROR: GRPO dataset not found at {DATASET_PATH}")
        print(f"       Run:  python -m grpo.build_dataset")
        return []

    records = []
    with open(DATASET_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


# ===========================================================================
# Args
# ===========================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="GRPO training for Rego expert (post-SFT)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument("--base-model", type=str, default=DEFAULTS["base_model"],
                    help="Base model name for tokenizer / architecture.")
    p.add_argument("--sft-model", type=str, default=DEFAULTS["sft_model"],
                    help="Path to SFT-trained model (LoRA adapter or merged).")
    p.add_argument("--output-dir", type=str, default=DEFAULTS["output_dir"],
                    help="Directory for GRPO checkpoints and final model.")
    p.add_argument("--dataset", type=str, default=str(DATASET_PATH),
                    help="Path to the pre-built GRPO dataset JSONL.")
    p.add_argument("--max-seq-length", type=int, default=DEFAULTS["max_seq_length"],
                    help="Maximum total sequence length (prompt + completion).")
    p.add_argument("--lora-rank", type=int, default=DEFAULTS["lora_rank"],
                    help="LoRA rank for GRPO training.")
    p.add_argument("--max-steps", type=int, default=DEFAULTS["max_steps"],
                    help="Maximum GRPO training steps.")
    p.add_argument("--num-generations", type=int, default=DEFAULTS["num_generations"],
                    help="Number of completions to generate per prompt.")
    p.add_argument("--batch-size", type=int, default=DEFAULTS["batch_size"],
                    help="Per-device batch size.")
    p.add_argument("--grad-accum", type=int, default=DEFAULTS["grad_accum"],
                    help="Gradient accumulation steps.")
    p.add_argument("--lr", type=float, default=DEFAULTS["lr"],
                    help="Learning rate.")
    p.add_argument("--warmup-ratio", type=float, default=DEFAULTS["warmup_ratio"],
                    help="Warmup ratio.")
    p.add_argument("--seed", type=int, default=DEFAULTS["seed"],
                    help="Random seed.")
    p.add_argument("--dry-run", action="store_true",
                    help="Build dataset and print config without training.")
    p.add_argument("--no-unsloth", action="store_true",
                    help="Use standard HF/TRL instead of Unsloth (slower, more VRAM).")

    return p.parse_args()


# ===========================================================================
# Main
# ===========================================================================

def main() -> None:
    args = parse_args()

    # ------------------------------------------------------------------
    # Verify OPA and Regal are available
    # ------------------------------------------------------------------
    if not shutil.which("opa"):
        print("ERROR: `opa` binary not found on PATH.")
        print("Install: brew install opa  OR  go install github.com/open-policy-agent/opa@latest")
        return

    if not shutil.which("regal"):
        print("WARNING: `regal` binary not found on PATH — reward_regal_lint will return 0.0")
        print("Install: brew install styrainc/packages/regal")

    # ------------------------------------------------------------------
    # Load pre-built GRPO dataset
    # ------------------------------------------------------------------
    dataset_path = Path(args.dataset)
    if dataset_path != DATASET_PATH and dataset_path.exists():
        # Custom dataset path
        records = []
        with open(dataset_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        grpo_records = records
    else:
        grpo_records = _load_grpo_dataset()

    if not grpo_records:
        return

    unique_tasks = len(set(r["task_id"] for r in grpo_records))
    print(f"GRPO dataset: {len(grpo_records)} prompts from {unique_tasks} tasks")

    # ------------------------------------------------------------------
    # Dry run — print dataset info and exit (no torch/GPU required)
    # ------------------------------------------------------------------
    if args.dry_run:
        from collections import Counter
        variant_counts = Counter(r.get("variant", "unknown") for r in grpo_records)

        print(f"\n{'='*60}")
        print(f"  GRPO Training Configuration (DRY RUN)")
        print(f"{'='*60}")
        print(f"  SFT model:        {args.sft_model}")
        print(f"  Output:           {args.output_dir}")
        print(f"  Dataset:          {dataset_path}")
        print(f"  LoRA rank:        {args.lora_rank}")
        print(f"  Max seq length:   {args.max_seq_length}")
        print(f"  Max steps:        {args.max_steps}")
        print(f"  Num generations:  {args.num_generations}")
        print(f"  Batch size:       {args.batch_size} × {args.grad_accum}")
        print(f"  Learning rate:    {args.lr}")
        print(f"  Dataset size:     {len(grpo_records)} prompts from {unique_tasks} tasks")
        print(f"  Reward functions: format, opa_parse, opa_test, schema_paths, regal_lint")
        print(f"  OPA available:    {bool(shutil.which('opa'))}")
        print(f"  Regal available:  {bool(shutil.which('regal'))}")
        print(f"{'='*60}")

        print(f"\n  Prompts by variant:")
        for v, c in sorted(variant_counts.items()):
            print(f"    {v:20s} {c:4d}")

        print(f"\n  Sample prompts:")
        for i in range(min(5, len(grpo_records))):
            user_msg = grpo_records[i]["prompt"][-1]["content"]
            tid = grpo_records[i]["task_id"]
            var = grpo_records[i].get("variant", "?")
            print(f"    [{i}] ({tid}/{var}) {user_msg[:80]}...")

        print(f"\n  [DRY RUN] — exiting without training.")
        print(f"  To train, remove --dry-run. Requires: torch, unsloth, trl, vllm, datasets\n")
        return

    # ------------------------------------------------------------------
    # Load model (requires torch + GPU libraries)
    # ------------------------------------------------------------------
    import torch

    if args.no_unsloth:
        print(f"\nLoading model with standard HF (no Unsloth)...")
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import LoraConfig, PeftModel, TaskType

        tokenizer = AutoTokenizer.from_pretrained(
            args.base_model, trust_remote_code=True,
        )
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        sft_path = Path(args.sft_model)
        is_lora = (sft_path / "adapter_config.json").exists()

        if is_lora:
            # SFT output is a LoRA adapter — load base model, apply adapter, merge
            print(f"  SFT model is a LoRA adapter — loading base model {args.base_model}...")
            base_model = AutoModelForCausalLM.from_pretrained(
                args.base_model,
                torch_dtype=torch.bfloat16,
                trust_remote_code=True,
            )
            print(f"  Applying SFT LoRA from {args.sft_model}...")
            model = PeftModel.from_pretrained(base_model, args.sft_model)
            print(f"  Merging SFT LoRA into base weights...")
            model = model.merge_and_unload()
        else:
            # SFT output is a full merged model
            print(f"  Loading merged SFT model from {args.sft_model}...")
            model = AutoModelForCausalLM.from_pretrained(
                args.sft_model,
                torch_dtype=torch.bfloat16,
                trust_remote_code=True,
            )

        # New LoRA adapter for GRPO training (on top of merged SFT weights)
        peft_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=args.lora_rank,
            lora_alpha=args.lora_rank * 2,
            lora_dropout=0.05,
            target_modules=[
                "q_proj", "k_proj", "v_proj", "o_proj",
                "gate_proj", "up_proj", "down_proj",
            ],
            bias="none",
        )
    else:
        print(f"\nLoading model with Unsloth (fast inference)...")
        from unsloth import FastLanguageModel

        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=args.sft_model,
            max_seq_length=args.max_seq_length,
            load_in_4bit=False,
            fast_inference=True,
            max_lora_rank=args.lora_rank,
            gpu_memory_utilization=0.9,
        )

        model = FastLanguageModel.get_peft_model(
            model,
            r=args.lora_rank,
            target_modules=[
                "q_proj", "k_proj", "v_proj", "o_proj",
                "gate_proj", "up_proj", "down_proj",
            ],
            lora_alpha=args.lora_rank * 2,
            use_gradient_checkpointing="unsloth",
            random_state=args.seed,
        )
        peft_config = None  # Unsloth handles it

    # ------------------------------------------------------------------
    # Convert records to HF Dataset
    # ------------------------------------------------------------------
    from datasets import Dataset
    import numpy as np

    dataset = Dataset.from_list(grpo_records)

    # Filter by prompt length (keep p90)
    tokenized = dataset.map(
        lambda x: {
            "tokens": tokenizer.apply_chat_template(
                x["prompt"], add_generation_prompt=True, tokenize=True,
            )
        },
        batched=True,
    )
    tokenized = tokenized.map(lambda x: {"L": len(x["tokens"])})
    maximum_length = int(np.quantile(tokenized["L"], 0.9))
    dataset = dataset.select(np.where(np.array(tokenized["L"]) <= maximum_length)[0])
    del tokenized

    max_prompt_length = maximum_length + 1
    max_completion_length = args.max_seq_length - max_prompt_length

    print(f"\n  Dataset after length filter: {len(dataset)} prompts")
    print(f"  Max prompt length (p90):     {maximum_length} tokens")
    print(f"  Max completion length:       {max_completion_length} tokens")

    # ------------------------------------------------------------------
    # Print config
    # ------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"  GRPO Training Configuration")
    print(f"{'='*60}")
    print(f"  SFT model:        {args.sft_model}")
    print(f"  SFT is LoRA:      {(Path(args.sft_model) / 'adapter_config.json').exists()}")
    print(f"  Output:           {args.output_dir}")
    print(f"  Dataset:          {dataset_path}")
    print(f"  LoRA rank:        {args.lora_rank}")
    print(f"  Max seq length:   {args.max_seq_length}")
    print(f"  Prompt length:    {max_prompt_length}")
    print(f"  Completion len:   {max_completion_length}")
    print(f"  Max steps:        {args.max_steps}")
    print(f"  Num generations:  {args.num_generations}")
    print(f"  Batch size:       {args.batch_size} × {args.grad_accum}")
    print(f"  Learning rate:    {args.lr}")
    print(f"  KL beta:          0.1")
    print(f"  Gen temperature:  0.7")
    print(f"  Save every:       {save_every} steps")
    print(f"  Dataset size:     {len(dataset)}")
    print(f"  Reward functions: format, opa_parse, opa_test, schema_paths, regal_lint")
    print(f"  OPA available:    {bool(shutil.which('opa'))}")
    print(f"  Regal available:  {bool(shutil.which('regal'))}")
    print(f"{'='*60}")

    # ------------------------------------------------------------------
    # Import reward functions
    # ------------------------------------------------------------------
    from grpo.rewards import ALL_REWARD_FUNCS

    # ------------------------------------------------------------------
    # Configure GRPO trainer
    # ------------------------------------------------------------------
    from trl import GRPOConfig, GRPOTrainer

    if not args.no_unsloth:
        from vllm import SamplingParams
        vllm_sampling_params = SamplingParams(
            min_p=0.1,
            top_p=1.0,
            top_k=-1,
            seed=args.seed,
            stop=[tokenizer.eos_token],
            include_stop_str_in_output=True,
        )
    else:
        vllm_sampling_params = None

    save_every = max(args.max_steps // 4, 10)  # checkpoint ~4 times during training

    training_args = GRPOConfig(
        output_dir=args.output_dir,

        # vLLM (only with Unsloth)
        **({"vllm_sampling_params": vllm_sampling_params} if vllm_sampling_params else {}),

        # Generation
        temperature=0.7,                       # lower → more coherent generations
        max_prompt_length=max_prompt_length,
        max_completion_length=max_completion_length,
        num_generations=args.num_generations,

        # KL penalty — prevents drift from the SFT policy
        beta=0.1,

        # Optimisation
        learning_rate=args.lr,
        weight_decay=0.001,
        warmup_ratio=args.warmup_ratio,
        lr_scheduler_type="linear",
        optim="adamw_8bit",
        bf16=True,

        # Batching
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,

        # Steps & logging
        max_steps=args.max_steps,
        save_steps=save_every,                 # intermediate checkpoints
        logging_steps=1,
        report_to="none",

        # Misc
        seed=args.seed,
    )

    # ------------------------------------------------------------------
    # Train
    # ------------------------------------------------------------------
    print("\nStarting GRPO training...")

    trainer_kwargs = {
        "model": model,
        "processing_class": tokenizer,
        "reward_funcs": ALL_REWARD_FUNCS,
        "args": training_args,
        "train_dataset": dataset,
    }

    if peft_config is not None:
        trainer_kwargs["peft_config"] = peft_config

    trainer = GRPOTrainer(**trainer_kwargs)
    trainer.train()

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------
    print(f"\nSaving GRPO model to {args.output_dir}...")
    if args.no_unsloth:
        trainer.save_model()
        tokenizer.save_pretrained(args.output_dir)
    else:
        model.save_lora(args.output_dir)

    # Save config for reproducibility
    config_path = Path(args.output_dir) / "grpo_training_args.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(vars(args), f, indent=2)

    print(f"  Config saved to {config_path}")
    print("\nDone! ✓")
    print(f"\n  Pipeline complete:")
    print(f"    1. SFT model:  {args.sft_model}")
    print(f"    2. GRPO model: {args.output_dir}")


if __name__ == "__main__":
    main()
