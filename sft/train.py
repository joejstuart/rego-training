#!/usr/bin/env python3
"""SFT training script for Qwen3-4B on SLSA provenance attestation Rego rules.

Trains using LoRA (default) or full fine-tuning on the dataset produced by
Phase 4 (phase4_dataset/output/rego_sft.jsonl).

Hardware target: single A100 80GB GPU.

Usage:
    # LoRA (default) — ~20GB VRAM, fast
    python train.py

    # Full fine-tuning — ~60GB VRAM, slower, but stronger
    python train.py --no-lora

    # Custom settings
    python train.py --epochs 5 --lr 1e-5 --batch-size 8

    # Resume from checkpoint
    python train.py --resume-from ./output/rego-expert/checkpoint-300

    # Dry run (no training, just prints config and dataset stats)
    python train.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch
from datasets import Dataset
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

# ---------------------------------------------------------------------------
# Defaults — tuned for Qwen3-4B on a single A100 80GB
# ---------------------------------------------------------------------------
DEFAULTS = {
    "model": "Qwen/Qwen3-4B",
    "dataset": str(Path(__file__).resolve().parent / "phase4_dataset" / "output" / "rego_sft.jsonl"),
    "output_dir": str(Path(__file__).resolve().parent / "output" / "rego-expert"),
    "max_seq_length": 2048,       # covers p99≈1853, p100≈1995 (includes schema in system prompt)
    "batch_size": 4,              # per-device
    "grad_accum": 4,              # effective batch size = 16
    "epochs": 3,                  # small dataset → multiple passes
    "lr": 2e-5,                   # standard SFT learning rate
    "lr_scheduler": "cosine",
    "warmup_ratio": 0.1,
    "weight_decay": 0.01,
    "max_grad_norm": 1.0,
    "eval_split": 0.05,           # 5% holdout for eval (~97 examples)
    "seed": 42,
    # LoRA defaults
    "lora_r": 16,
    "lora_alpha": 32,
    "lora_dropout": 0.05,
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SFT training for Rego expert (Qwen3-4B)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Model & data
    p.add_argument("--model", type=str, default=DEFAULTS["model"],
                    help="HuggingFace model name or local path.")
    p.add_argument("--dataset", type=str, default=DEFAULTS["dataset"],
                    help="Path to the JSONL dataset (messages format).")
    p.add_argument("--output-dir", type=str, default=DEFAULTS["output_dir"],
                    help="Directory for checkpoints and final model.")

    # Training hyperparams
    p.add_argument("--max-seq-length", type=int, default=DEFAULTS["max_seq_length"],
                    help="Maximum sequence length for training.")
    p.add_argument("--batch-size", type=int, default=DEFAULTS["batch_size"],
                    help="Per-device train batch size.")
    p.add_argument("--grad-accum", type=int, default=DEFAULTS["grad_accum"],
                    help="Gradient accumulation steps (effective batch = batch_size × grad_accum).")
    p.add_argument("--epochs", type=int, default=DEFAULTS["epochs"],
                    help="Number of training epochs.")
    p.add_argument("--lr", type=float, default=DEFAULTS["lr"],
                    help="Peak learning rate.")
    p.add_argument("--lr-scheduler", type=str, default=DEFAULTS["lr_scheduler"],
                    choices=["cosine", "linear", "constant", "constant_with_warmup"],
                    help="Learning rate scheduler type.")
    p.add_argument("--warmup-ratio", type=float, default=DEFAULTS["warmup_ratio"],
                    help="Fraction of total steps used for linear warmup.")
    p.add_argument("--weight-decay", type=float, default=DEFAULTS["weight_decay"],
                    help="AdamW weight decay.")
    p.add_argument("--max-grad-norm", type=float, default=DEFAULTS["max_grad_norm"],
                    help="Max gradient norm for clipping.")
    p.add_argument("--eval-split", type=float, default=DEFAULTS["eval_split"],
                    help="Fraction of data to hold out for evaluation (0 to disable).")
    p.add_argument("--seed", type=int, default=DEFAULTS["seed"],
                    help="Random seed.")

    # LoRA
    p.add_argument("--no-lora", action="store_true",
                    help="Disable LoRA and do full fine-tuning.")
    p.add_argument("--lora-r", type=int, default=DEFAULTS["lora_r"],
                    help="LoRA rank.")
    p.add_argument("--lora-alpha", type=int, default=DEFAULTS["lora_alpha"],
                    help="LoRA alpha (scaling factor).")
    p.add_argument("--lora-dropout", type=float, default=DEFAULTS["lora_dropout"],
                    help="LoRA dropout.")

    # Misc
    p.add_argument("--resume-from", type=str, default=None,
                    help="Resume training from a checkpoint directory.")
    p.add_argument("--dry-run", action="store_true",
                    help="Print config and dataset stats without training.")

    return p.parse_args()


def load_dataset(path: str, eval_split: float, seed: int) -> tuple[Dataset, Dataset | None]:
    """Load the JSONL dataset and optionally split into train/eval."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    ds = Dataset.from_list(records)

    if eval_split > 0 and len(ds) > 20:
        split = ds.train_test_split(test_size=eval_split, seed=seed)
        return split["train"], split["test"]

    return ds, None


def print_config(args: argparse.Namespace, train_ds: Dataset, eval_ds: Dataset | None) -> None:
    """Print training configuration summary."""
    effective_batch = args.batch_size * args.grad_accum
    steps_per_epoch = len(train_ds) // effective_batch
    total_steps = steps_per_epoch * args.epochs

    print("=" * 60)
    print("  SFT Training Configuration")
    print("=" * 60)
    print(f"  Model:            {args.model}")
    print(f"  Dataset:          {args.dataset}")
    print(f"  Output:           {args.output_dir}")
    print(f"  LoRA:             {'disabled' if args.no_lora else f'r={args.lora_r}, alpha={args.lora_alpha}'}")
    print(f"  Precision:        bf16")
    print()
    print(f"  Train examples:   {len(train_ds)}")
    print(f"  Eval examples:    {len(eval_ds) if eval_ds else 'none'}")
    print(f"  Max seq length:   {args.max_seq_length}")
    print(f"  Batch size:       {args.batch_size} × {args.grad_accum} = {effective_batch} effective")
    print(f"  Epochs:           {args.epochs}")
    print(f"  Steps/epoch:      ~{steps_per_epoch}")
    print(f"  Total steps:      ~{total_steps}")
    print(f"  Learning rate:    {args.lr}")
    print(f"  LR scheduler:     {args.lr_scheduler}")
    print(f"  Warmup:           {args.warmup_ratio:.0%} ({int(total_steps * args.warmup_ratio)} steps)")
    print(f"  Weight decay:     {args.weight_decay}")
    print(f"  Seed:             {args.seed}")
    print("=" * 60)


def main() -> None:
    args = parse_args()

    # ------------------------------------------------------------------
    # Load dataset
    # ------------------------------------------------------------------
    print(f"Loading dataset from {args.dataset}...")
    train_ds, eval_ds = load_dataset(args.dataset, args.eval_split, args.seed)
    print(f"  Train: {len(train_ds)} examples")
    if eval_ds:
        print(f"  Eval:  {len(eval_ds)} examples")

    # ------------------------------------------------------------------
    # Print config
    # ------------------------------------------------------------------
    print_config(args, train_ds, eval_ds)

    if args.dry_run:
        print("\n  [DRY RUN] — exiting without training.\n")
        return

    # ------------------------------------------------------------------
    # Load tokenizer
    # ------------------------------------------------------------------
    print("\nLoading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(
        args.model,
        trust_remote_code=True,
        model_max_length=args.max_seq_length,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # ------------------------------------------------------------------
    # Load model
    # ------------------------------------------------------------------
    print("Loading model...")
    model_kwargs = {
        "trust_remote_code": True,
        "dtype": torch.bfloat16,
        "attn_implementation": "sdpa",  # PyTorch native; use "flash_attention_2" if flash_attn is installed
    }

    model = AutoModelForCausalLM.from_pretrained(args.model, **model_kwargs)

    # ------------------------------------------------------------------
    # LoRA config (optional)
    # ------------------------------------------------------------------
    peft_config = None
    if not args.no_lora:
        from peft import LoraConfig, TaskType

        peft_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=args.lora_r,
            lora_alpha=args.lora_alpha,
            lora_dropout=args.lora_dropout,
            target_modules=[
                "q_proj", "k_proj", "v_proj", "o_proj",
                "gate_proj", "up_proj", "down_proj",
            ],
            bias="none",
        )
        trainable = args.lora_r * 2 * 7 * 36  # rough estimate for 4B model
        print(f"  LoRA enabled: r={args.lora_r}, ~{trainable / 1e6:.1f}M trainable params (estimate)")

    # ------------------------------------------------------------------
    # Training config
    # ------------------------------------------------------------------
    training_args = SFTConfig(
        output_dir=args.output_dir,
        overwrite_output_dir=True,

        # Batch & accumulation
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,

        # Epochs & scheduling
        num_train_epochs=args.epochs,
        learning_rate=args.lr,
        lr_scheduler_type=args.lr_scheduler,
        warmup_ratio=args.warmup_ratio,
        weight_decay=args.weight_decay,
        max_grad_norm=args.max_grad_norm,

        # Precision
        bf16=True,
        bf16_full_eval=True,

        # Logging
        logging_steps=10,
        logging_first_step=True,
        report_to="none",

        # Saving
        save_strategy="epoch",
        save_total_limit=3,

        # Eval
        eval_strategy="epoch" if eval_ds else "no",

        # Misc
        seed=args.seed,
        dataloader_pin_memory=True,
        dataloader_num_workers=4,
        gradient_checkpointing=not args.no_lora,  # save memory with LoRA
        gradient_checkpointing_kwargs={"use_reentrant": False} if not args.no_lora else None,

        # Remove unused columns (our dataset has metadata fields)
        remove_unused_columns=True,
    )

    # ------------------------------------------------------------------
    # Trainer
    # ------------------------------------------------------------------
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        processing_class=tokenizer,
        peft_config=peft_config,
    )

    # ------------------------------------------------------------------
    # Train
    # ------------------------------------------------------------------
    print("\nStarting training...")
    if args.resume_from:
        print(f"  Resuming from {args.resume_from}")
        trainer.train(resume_from_checkpoint=args.resume_from)
    else:
        trainer.train()

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------
    print(f"\nSaving final model to {args.output_dir}...")
    trainer.save_model()
    tokenizer.save_pretrained(args.output_dir)

    # Save training args for reproducibility
    args_path = Path(args.output_dir) / "training_args.json"
    with open(args_path, "w") as f:
        json.dump(vars(args), f, indent=2)
    print(f"  Training args saved to {args_path}")

    print("\nDone! ✓")
    if not args.no_lora:
        print(f"\n  To merge LoRA weights into the base model:")
        print(f"    python -c \"")
        print(f"      from peft import AutoPeftModelForCausalLM")
        print(f"      model = AutoPeftModelForCausalLM.from_pretrained('{args.output_dir}')")
        print(f"      merged = model.merge_and_unload()")
        print(f"      merged.save_pretrained('{args.output_dir}-merged')\"")


if __name__ == "__main__":
    main()
