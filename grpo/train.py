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

─── How rewards affect model weights (the GRPO algorithm) ────────────────

  For each training step:

  1. SAMPLE:  Pick a prompt from the dataset.

  2. GENERATE:  Produce N completions (num_generations=4 by default) from the
     current policy (the model).

  3. SCORE:  Run every reward function on every completion. Each completion
     gets a scalar reward = sum of all 5 function scores (range -17 to +15).

  4. ADVANTAGE:  Compute a *group-relative advantage* for each completion:
       advantage_i = (reward_i - mean(rewards)) / std(rewards)
     Completions that scored above the group average get positive advantage;
     those below get negative.  If all N completions score the same,
     std ≈ 0 and there is NO learning signal for this step.

  5. POLICY GRADIENT:  For each token in each completion, compute:
       loss_token = -advantage * log π(token | context)
     Positive advantage → the gradient *increases* the probability of those
     tokens.  Negative advantage → the gradient *decreases* them.
     This is the standard REINFORCE-style policy-gradient update.

  6. KL PENALTY:  A small penalty (β=0.04) is added for each token that
     diverges from the *reference policy* (the frozen SFT model):
       kl_penalty = β * KL(π_current ‖ π_ref)
     This prevents the model from drifting too far from what SFT taught it.

  7. BACKPROP:  The combined loss (policy gradient + KL penalty) is
     back-propagated through the LoRA adapter weights only (the base model
     is frozen).  The optimizer (AdamW) updates the LoRA parameters.

  Net effect over many steps: the model learns to produce completions that
  score high on ALL five reward functions simultaneously, while staying
  close to the SFT baseline.  Unlike PPO, GRPO needs no separate critic
  network — the group of N completions *is* the baseline.

──────────────────────────────────────────────────────────────────────────

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
    "max_steps": 600,
    # num_generations: how many completions to generate per prompt.  GRPO
    # compares these N outputs against each other — the spread in their
    # rewards IS the learning signal.  More generations = richer signal but
    # more compute per step.
    "num_generations": 4,
    # batch_size must be >= num_generations because each "sample" in the
    # batch is one completion; a single prompt produces num_generations
    # samples that must all fit in the same batch.
    "batch_size": 4,
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
    p.add_argument("--log-every", type=int, default=5,
                    help="Print a console summary every N steps.")

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
    # We start from the SFT model (Stage 1) and add a NEW LoRA adapter on
    # top.  Only these new LoRA weights will be updated by GRPO — the base
    # model weights (including merged SFT knowledge) stay frozen.
    # This is what allows the policy gradient (step 5-7 in the docstring)
    # to update a small set of parameters while preserving everything SFT
    # already learned.
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
            # SFT output is a LoRA adapter — load base + SFT adapter, then
            # merge them into one set of weights.  This "bakes in" SFT
            # knowledge so GRPO can build on top of it.
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
            # SFT output is a full merged model — use it directly as our
            # frozen base.
            print(f"  Loading merged SFT model from {args.sft_model}...")
            model = AutoModelForCausalLM.from_pretrained(
                args.sft_model,
                torch_dtype=torch.bfloat16,
                trust_remote_code=True,
            )

        # A NEW LoRA adapter for GRPO training.  These are the ONLY weights
        # that the optimizer will update.  The merged SFT weights underneath
        # serve as both the "base model" and the "reference policy" for the
        # KL penalty — keeping GRPO's updates grounded in SFT behaviour.
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

        # Unsloth needs a FULL model, not a LoRA adapter.  If the SFT
        # output is a LoRA adapter we must merge it into the base model
        # first, save the merged result to disk, and point Unsloth at
        # that.  The merged model is cached so this only happens once.
        sft_path = Path(args.sft_model)
        is_sft_lora = (sft_path / "adapter_config.json").exists()

        if is_sft_lora:
            merged_sft_dir = Path(args.output_dir) / "_sft_merged"

            if (merged_sft_dir / "config.json").exists():
                print(f"  Using cached merged SFT model at {merged_sft_dir}")
            else:
                print(f"  SFT model is a LoRA adapter — merging into base model first...")
                from transformers import AutoModelForCausalLM, AutoTokenizer
                from peft import PeftModel

                print(f"    Loading base model {args.base_model}...")
                _base = AutoModelForCausalLM.from_pretrained(
                    args.base_model,
                    torch_dtype=torch.bfloat16,
                    trust_remote_code=True,
                )
                print(f"    Applying SFT LoRA from {args.sft_model}...")
                _base = PeftModel.from_pretrained(_base, args.sft_model)
                print(f"    Merging SFT LoRA into base weights...")
                _merged = _base.merge_and_unload()

                merged_sft_dir.mkdir(parents=True, exist_ok=True)
                _merged.save_pretrained(str(merged_sft_dir))

                _tok = AutoTokenizer.from_pretrained(
                    args.base_model, trust_remote_code=True,
                )
                _tok.save_pretrained(str(merged_sft_dir))

                del _base, _merged, _tok
                torch.cuda.empty_cache()
                print(f"    Merged SFT model saved to {merged_sft_dir}")

            unsloth_model_path = str(merged_sft_dir)
        else:
            # SFT output is already a full merged model — use directly
            unsloth_model_path = args.sft_model

        # Now load the full (merged) model with Unsloth.
        # fast_inference=True uses vLLM for generation (much faster), but
        # requires a compatible vLLM version.  Try it first, fall back to
        # Unsloth-only if vLLM is missing or has a version mismatch.
        _has_vllm = __import__("importlib").util.find_spec("vllm") is not None

        model = None
        if _has_vllm:
            try:
                print("  Trying Unsloth + vLLM (fast_inference=True)...")
                model, tokenizer = FastLanguageModel.from_pretrained(
                    model_name=unsloth_model_path,
                    max_seq_length=args.max_seq_length,
                    load_in_4bit=False,
                    fast_inference=True,
                    max_lora_rank=args.lora_rank,
                    gpu_memory_utilization=0.9,
                )
                print("  vLLM loaded successfully — fast generation enabled.")
            except (RuntimeError, ImportError, TypeError) as e:
                print(f"  WARNING: vLLM failed to initialise: {e}")
                print("  Falling back to Unsloth without vLLM (still faster than --no-unsloth).")
                print("  To fix: pip install 'unsloth[vllm]' or align vllm/unsloth versions.")
                model = None
                torch.cuda.empty_cache()

        if model is None:
            if not _has_vllm:
                print("  vLLM not installed — using Unsloth without fast inference.")
                print("  Install for ~2-3x faster generation: pip install vllm")
            model, tokenizer = FastLanguageModel.from_pretrained(
                model_name=unsloth_model_path,
                max_seq_length=args.max_seq_length,
                load_in_4bit=False,
                fast_inference=False,
            )

        # Add a fresh GRPO LoRA adapter on top of the merged model
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
    # Each record has: prompt, test_code, package_name, rule_code, task_id,
    # variant.  GRPOTrainer will forward the non-prompt columns (test_code,
    # package_name, etc.) as **kwargs to each reward function, so the reward
    # functions can use them for evaluation (e.g. reward_opa_test needs
    # test_code and package_name to run `opa test`).
    # ------------------------------------------------------------------
    from datasets import Dataset
    import numpy as np

    dataset = Dataset.from_list(grpo_records)

    # Drop prompts longer than p90 — very long prompts waste compute and
    # leave too little room for the completion (which must fit in
    # max_seq_length - max_prompt_length).
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

    save_every = max(args.max_steps // 4, 10)  # checkpoint ~4 times during training

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
    print(f"  KL beta:          0.10")
    print(f"  Gen temperature:  0.7")
    print(f"  Save every:       {save_every} steps")
    print(f"  Dataset size:     {len(dataset)}")
    print(f"  Reward functions: format, opa_parse, opa_test, schema_paths, regal_lint")
    print(f"  OPA available:    {bool(shutil.which('opa'))}")
    print(f"  Regal available:  {bool(shutil.which('regal'))}")
    print(f"{'='*60}")

    # ------------------------------------------------------------------
    # Import reward functions + wrap with logger
    # ------------------------------------------------------------------
    # ALL_REWARD_FUNCS is a list of 5 callables.  GRPOTrainer calls each
    # one on every completion, sums the scores, and uses the sum as the
    # reward for the policy gradient.  The wrap_reward_funcs() call adds
    # transparent logging without changing the scores.
    # ------------------------------------------------------------------
    from grpo.rewards import ALL_REWARD_FUNCS
    from grpo.logging_utils import StepLogger

    step_logger = StepLogger(
        log_dir=args.output_dir,
        console_every=args.log_every,
    )
    reward_funcs = step_logger.wrap_reward_funcs(ALL_REWARD_FUNCS)
    print(f"\n  Step logging enabled → {step_logger.log_file}")
    print(f"  Console summary every {args.log_every} steps")

    # ------------------------------------------------------------------
    # Configure GRPO trainer
    # ------------------------------------------------------------------
    from trl import GRPOConfig, GRPOTrainer

    # NOTE: We intentionally do NOT pass custom vllm_sampling_params.
    # Unsloth's GRPOTrainer manages vLLM generation internally and uses
    # max_completion_length from GRPOConfig to set the token limit.
    # Passing our own SamplingParams can cause a tensor size mismatch
    # between the completion and the completion_mask in compute_loss.
    vllm_sampling_params = None

    # ------------------------------------------------------------------
    # GRPOConfig controls both generation and the policy-gradient update.
    #
    # The training loop (inside GRPOTrainer.train()) works like this:
    #
    #   for step in range(max_steps):
    #       prompt = sample_one_prompt(dataset)
    #
    #       # ① GENERATE — produce N completions from the current policy
    #       completions = model.generate(prompt, n=num_generations,
    #                                    temperature=0.7)
    #
    #       # ② SCORE — call each reward function, sum their scores
    #       rewards = [sum(fn(c) for fn in reward_funcs) for c in completions]
    #
    #       # ③ ADVANTAGE — group-relative normalisation
    #       advantages = (rewards - mean(rewards)) / std(rewards)
    #       #   → completions better than the group average get positive
    #       #     advantage; worse ones get negative.
    #       #   → if all completions score the same, std≈0 → no gradient.
    #
    #       # ④ POLICY GRADIENT + KL — for each token t in completion i:
    #       #   loss += -advantage_i * log π(t|context)   (REINFORCE)
    #       #         + β * KL(π_current ‖ π_ref)          (stay near SFT)
    #
    #       # ⑤ BACKPROP — update LoRA weights via AdamW
    #       loss.backward()
    #       optimizer.step()
    #
    # The result: tokens that appear in high-reward completions become more
    # likely; tokens in low-reward completions become less likely.
    # ------------------------------------------------------------------
    training_args = GRPOConfig(
        output_dir=args.output_dir,

        # vLLM (only with Unsloth)
        # ── Generation parameters ──
        # temperature controls randomness in sampling.  0.7 is a balance:
        # high enough that the N completions are diverse (so their rewards
        # differ → learning signal exists), low enough to stay coherent.
        temperature=0.7,
        max_prompt_length=max_prompt_length,
        max_completion_length=max_completion_length,
        # N completions per prompt — these form the "group" that GRPO
        # compares.  The variance in their rewards drives learning.
        num_generations=args.num_generations,

        # ── KL penalty (β) ──
        # Penalises per-token divergence from the reference policy (the
        # frozen SFT model).  Higher β keeps the model closer to SFT,
        # preventing regression on prompts GRPO didn't train on enough.
        # 0.04 was too low — the model drifted and forgot correct SFT
        # behaviour on under-represented prompts.  0.10 is a safer
        # default that still allows improvement while preserving SFT
        # knowledge.
        beta=0.10,

        # ── Optimiser ──
        # AdamW updates the LoRA weights using the policy-gradient loss.
        learning_rate=args.lr,
        weight_decay=0.001,
        warmup_ratio=args.warmup_ratio,
        lr_scheduler_type="linear",
        optim="adamw_8bit",
        bf16=True,

        # ── Batching ──
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
    # GRPOTrainer ties everything together:
    #   - model:            the policy being optimised (SFT base + new LoRA)
    #   - reward_funcs:     the 5 scoring functions (format, parse, test,
    #                       schema, lint) — their outputs drive the gradient
    #   - train_dataset:    prompts + metadata; GRPOTrainer forwards extra
    #                       columns (test_code, package_name, …) as kwargs
    #                       to each reward function automatically
    #   - peft_config:      defines the LoRA adapter whose weights are
    #                       the only thing the optimiser updates
    #
    # trainer.train() runs the generate→score→advantage→backprop loop
    # described above for max_steps iterations.
    # ------------------------------------------------------------------
    print("\nStarting GRPO training...")

    trainer_kwargs = {
        "model": model,
        "processing_class": tokenizer,
        "reward_funcs": reward_funcs,
        "args": training_args,
        "train_dataset": dataset,
        "callbacks": [step_logger.make_callback()],
    }

    if peft_config is not None:
        trainer_kwargs["peft_config"] = peft_config

    trainer = GRPOTrainer(**trainer_kwargs)
    trainer.train()

    # ------------------------------------------------------------------
    # Save LoRA adapter
    # ------------------------------------------------------------------
    # After training, the LoRA weights encode "what GRPO learned on top of
    # SFT".  Saving just the adapter is small (~100 MB vs ~8 GB for the
    # full model) and lets us swap/stack adapters later.
    # ------------------------------------------------------------------
    print(f"\nSaving GRPO LoRA adapter to {args.output_dir}...")
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

    # ------------------------------------------------------------------
    # Save fully merged model (base + SFT + GRPO — ready for inference)
    # ------------------------------------------------------------------
    # Merging collapses base weights + LoRA deltas into a single set of
    # weights.  The result is a standalone model that incorporates
    # everything: original Qwen knowledge, SFT Rego training, AND the
    # GRPO reasoning improvements.  No adapter stacking needed at
    # inference time.
    # ------------------------------------------------------------------
    merged_dir = Path(args.output_dir) / "merged"
    print(f"\nSaving fully merged model to {merged_dir}...")
    try:
        merged_model = trainer.model.merge_and_unload()
        merged_model.save_pretrained(str(merged_dir))
        tokenizer.save_pretrained(str(merged_dir))
        print(f"  Merged model saved — use directly with:")
        print(f"    python sft/inference.py --model {merged_dir}")
    except Exception as e:
        print(f"  WARNING: Could not save merged model: {e}")
        print(f"  You can still use the LoRA adapter with:")
        print(f"    python sft/inference.py --model {args.output_dir} --sft-model {args.sft_model}")

    # ------------------------------------------------------------------
    # Training summary
    # ------------------------------------------------------------------
    step_logger.print_final_summary()

    print("Done! ✓")
    print(f"\n  Pipeline complete:")
    print(f"    1. SFT model:  {args.sft_model}")
    print(f"    2. GRPO LoRA:  {args.output_dir}")
    print(f"    3. Merged:     {merged_dir}")
    print(f"    4. Step log:   {step_logger.log_file}")
    print(f"\n  Inference:")
    print(f"    python sft/inference.py --model {merged_dir}")


if __name__ == "__main__":
    main()
