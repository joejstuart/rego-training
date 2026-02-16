#!/usr/bin/env python3
"""SFT training script for Qwen3-4B-Thinking on SLSA provenance attestation Rego rules.

Trains using LoRA (default) or full fine-tuning on the dataset produced by
Phase 7 (phase7_distill_think/output/rego_sft_distilled.jsonl).

Hardware target: single GPU (A10 24GB with QLoRA, A100 80GB for full fine-tuning).

Usage:
    # LoRA + packing (default) — fast, ~16GB VRAM
    python train.py

    # Zero truncation — fit longest example (slower, more VRAM)
    python train.py --fit-all-context

    # Disable packing (preserves example boundaries, slower)
    python train.py --no-packing

    # LoRA without 4-bit quantization (higher VRAM)
    python train.py --no-4bit

    # Full fine-tuning — ~60GB VRAM, slower, but stronger
    python train.py --no-lora

    # Custom settings
    python train.py --epochs 5 --lr 1e-5 --batch-size 8

    # Resume from checkpoint
    python train.py --resume-from ./output/rego-expert-4b/checkpoint-300

    # Dry run (no training, just prints config and dataset stats)
    python train.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import torch
from datasets import Dataset
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

# ---------------------------------------------------------------------------
# Defaults — tuned for Qwen3-4B-Thinking on a single A10 24GB with QLoRA
# ---------------------------------------------------------------------------
DEFAULTS = {
    "model": "Qwen/Qwen3-4B-Thinking-2507",
    "dataset": str(Path(__file__).resolve().parent / "phase7_distill_think" / "output" / "rego_sft_distilled.jsonl"),
    "output_dir": str(Path(__file__).resolve().parent / "output" / "rego-expert-4b"),
    "max_seq_length": 4096,       # covers p95+ of examples; use --fit-all-context for zero truncation
    "batch_size": 2,              # per-device; safe for 4B + 4096 tokens + packing on ~24GB GPUs
    "grad_accum": 8,              # effective batch size = 16
    "epochs": 3,                  # small dataset → multiple passes
    "lr": 2e-5,                   # standard SFT learning rate
    "lr_scheduler": "cosine",
    "warmup_ratio": 0.1,
    "weight_decay": 0.01,
    "max_grad_norm": 1.0,
    "eval_split": 0.05,           # 5% holdout for eval (~122 examples)
    "packing": True,              # pack multiple examples per sequence (major GPU efficiency win)
    "seed": 42,
    # LoRA defaults
    "lora_r": 16,
    "lora_alpha": 32,
    "lora_dropout": 0.05,
    "use_4bit": True,             # QLoRA default keeps memory usage comfortable on 4B
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SFT training for Rego expert (Qwen3-4B-Thinking)",
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
    p.add_argument("--no-4bit", action="store_true",
                    help="Disable 4-bit QLoRA loading for LoRA runs (uses more VRAM).")
    p.add_argument("--lora-r", type=int, default=DEFAULTS["lora_r"],
                    help="LoRA rank.")
    p.add_argument("--lora-alpha", type=int, default=DEFAULTS["lora_alpha"],
                    help="LoRA alpha (scaling factor).")
    p.add_argument("--lora-dropout", type=float, default=DEFAULTS["lora_dropout"],
                    help="LoRA dropout.")

    # Packing
    p.add_argument("--packing", dest="packing", action="store_true",
                    help="Pack multiple examples per sequence (major GPU efficiency win, default).")
    p.add_argument("--no-packing", dest="packing", action="store_false",
                    help="Disable packing (preserves example boundaries, slower).")
    p.set_defaults(packing=DEFAULTS["packing"])

    # Misc
    p.add_argument("--resume-from", type=str, default=None,
                    help="Resume training from a checkpoint directory.")
    p.add_argument("--dry-run", action="store_true",
                    help="Print config and dataset stats without training.")
    p.add_argument("--fit-all-context", dest="fit_all_context", action="store_true",
                    help="Auto-increase max sequence length to avoid truncating any example.")
    p.add_argument("--no-fit-all-context", dest="fit_all_context", action="store_false",
                    help="Keep --max-seq-length fixed even if examples are longer (default with packing).")
    p.set_defaults(fit_all_context=False)

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


def _max_tokens_in_dataset(ds: Dataset | None, tokenizer: AutoTokenizer) -> int:
    """Return the maximum tokenized chat length in a dataset split."""
    if ds is None or len(ds) == 0:
        return 0

    max_tokens = 0
    for ex in ds:
        messages = ex.get("messages")
        if not messages:
            continue
        text = tokenizer.apply_chat_template(messages, tokenize=False)
        n_tokens = len(tokenizer.encode(text, add_special_tokens=False))
        if n_tokens > max_tokens:
            max_tokens = n_tokens
    return max_tokens


def print_config(args: argparse.Namespace, train_ds: Dataset, eval_ds: Dataset | None) -> None:
    """Print training configuration summary."""
    effective_batch = args.batch_size * args.grad_accum
    steps_per_epoch = len(train_ds) // effective_batch
    total_steps = steps_per_epoch * args.epochs

    use_4bit = (not args.no_lora) and (not args.no_4bit)
    print("=" * 60)
    print("  SFT Training Configuration")
    print("=" * 60)
    print(f"  Model:            {args.model}")
    print(f"  Dataset:          {args.dataset}")
    print(f"  Output:           {args.output_dir}")
    print(f"  LoRA:             {'disabled' if args.no_lora else f'r={args.lora_r}, alpha={args.lora_alpha}'}")
    print(f"  Quantization:     {'4-bit QLoRA' if use_4bit else 'none (bf16)'}")
    print(f"  Precision:        bf16")
    print(f"  Packing:          {'ON (dense sequences, major speedup)' if args.packing else 'OFF (padded sequences)'}")
    print()
    print(f"  Train examples:   {len(train_ds)}")
    print(f"  Eval examples:    {len(eval_ds) if eval_ds else 'none'}")
    print(f"  Max seq length:   {args.max_seq_length}")
    print(f"  Batch size:       {args.batch_size} × {args.grad_accum} = {effective_batch} effective")
    print(f"  Epochs:           {args.epochs}")
    if not args.packing:
        print(f"  Steps/epoch:      ~{steps_per_epoch}")
        print(f"  Total steps:      ~{total_steps}")
    else:
        print(f"  Steps/epoch:      (determined after packing)")
        print(f"  Total steps:      (determined after packing)")
    print(f"  Learning rate:    {args.lr}")
    print(f"  LR scheduler:     {args.lr_scheduler}")
    if not args.packing:
        print(f"  Warmup:           {args.warmup_ratio:.0%} ({int(total_steps * args.warmup_ratio)} steps)")
    else:
        print(f"  Warmup:           {args.warmup_ratio:.0%}")
    print(f"  Weight decay:     {args.weight_decay}")
    print(f"  Seed:             {args.seed}")
    print("=" * 60)


def _detect_cuda() -> bool:
    """Robust CUDA detection that handles containerised environments.

    In OpenShift / Kubernetes pods the NVML management library often fails
    (``Can't initialize NVML``) even when the GPU *is* available via the
    CUDA runtime.  ``torch.cuda.is_available()`` may return ``False`` in
    that situation.  We try harder by calling into the CUDA runtime
    directly.
    """
    # Fast path: standard PyTorch check.
    if torch.cuda.is_available():
        return True

    # NVML may have failed — try the CUDA runtime directly.
    try:
        count = torch.cuda.device_count()     # calls cudaGetDeviceCount
        if count > 0:
            # Force-initialise so later calls work.
            torch.cuda.init()
            return True
    except Exception:
        pass

    # Last resort: check for /dev/nvidia* devices.
    import glob
    if glob.glob("/dev/nvidia[0-9]*"):
        print("  WARNING: GPU devices found in /dev but torch.cuda failed.")
        print("           Ensure NVIDIA container runtime is configured.")

    return False


def main() -> None:
    # Helps reduce CUDA memory fragmentation on long-running training jobs.
    # Mitigate CUDA memory fragmentation (renamed in PyTorch ≥2.9).
    os.environ.setdefault("PYTORCH_ALLOC_CONF", "expandable_segments:True")

    args = parse_args()
    use_4bit = (not args.no_lora) and (not args.no_4bit)

    # ------------------------------------------------------------------
    # GPU diagnostics
    # ------------------------------------------------------------------
    cuda_available = _detect_cuda()
    if cuda_available:
        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem = torch.cuda.get_device_properties(0).total_memory / 1e9
        print(f"  GPU detected: {gpu_name} ({gpu_mem:.1f} GB)")
    else:
        print("  ⚠ WARNING: No CUDA GPU detected — training will run on CPU (very slow).")
        print("    If you have a GPU, check:")
        print("      1. nvidia-smi works inside this container")
        print("      2. NVIDIA_VISIBLE_DEVICES / CUDA_VISIBLE_DEVICES are set")
        print("      3. The container has the NVIDIA runtime configured")

    bf16_ok = cuda_available and torch.cuda.is_bf16_supported()
    compute_dtype = torch.bfloat16 if bf16_ok else torch.float16

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
    if not bf16_ok:
        if cuda_available:
            print("  NOTE: bf16 not supported on this GPU; falling back to fp16.")
        else:
            print("  NOTE: No GPU detected; using fp16 on CPU.")

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

    # Auto-detect Flash Attention 2 — requires both the package AND a CUDA GPU.
    attn_impl = "sdpa"
    if cuda_available:
        try:
            import flash_attn  # noqa: F401
            attn_impl = "flash_attention_2"
            print("  Flash Attention 2 detected — using for faster attention (~30% speedup).")
        except ImportError:
            print("  Flash Attention 2 not found — using SDPA. Install flash-attn for ~30% speedup.")
    else:
        print("  Using eager attention (no GPU).")
        attn_impl = "eager"

    model_kwargs = {
        "trust_remote_code": True,
        "attn_implementation": attn_impl,
        "device_map": "auto",           # let accelerate place layers on available devices
        "low_cpu_mem_usage": True,       # stream weights to avoid 2× memory spike
    }
    if use_4bit:
        model_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=compute_dtype,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )
    else:
        model_kwargs["torch_dtype"] = compute_dtype

    model = AutoModelForCausalLM.from_pretrained(args.model, **model_kwargs)

    runtime_max_seq_length = args.max_seq_length
    if args.fit_all_context:
        print("Scanning token lengths to fit all context...")
        train_max = _max_tokens_in_dataset(train_ds, tokenizer)
        eval_max = _max_tokens_in_dataset(eval_ds, tokenizer)
        observed_max = max(train_max, eval_max)
        model_ctx = int(getattr(model.config, "max_position_embeddings", observed_max))

        if observed_max > runtime_max_seq_length:
            if observed_max > model_ctx:
                print(
                    f"  WARNING: observed max length ({observed_max}) exceeds model context ({model_ctx}); "
                    "clipping to model limit."
                )
            runtime_max_seq_length = min(observed_max, model_ctx)
            tokenizer.model_max_length = runtime_max_seq_length
            print(f"  Increased max sequence length to {runtime_max_seq_length} to avoid truncation.")

            # Without packing, longer context increases activation memory. Keep
            # the run stable by reducing micro-batch and preserving effective
            # batch via grad_accum. With packing, sequences are already dense so
            # the memory impact is smaller — skip the auto-adjustment.
            if not args.packing and args.batch_size > 1:
                old_batch = args.batch_size
                old_accum = args.grad_accum
                args.batch_size = 1
                args.grad_accum = old_accum * old_batch
                print(
                    f"  Auto-adjusted batch for memory: {old_batch} x {old_accum} -> "
                    f"{args.batch_size} x {args.grad_accum} (effective batch preserved)."
                )
    args.max_seq_length = runtime_max_seq_length
    if args.fit_all_context:
        print(f"  Runtime max seq length: {args.max_seq_length}")

    # ------------------------------------------------------------------
    # LoRA config (optional)
    # ------------------------------------------------------------------
    peft_config = None
    if not args.no_lora:
        from peft import LoraConfig, TaskType, prepare_model_for_kbit_training

        if use_4bit:
            model = prepare_model_for_kbit_training(model)

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
        trainable = args.lora_r * 2 * 7 * 36  # rough estimate; adapter params scale with architecture depth
        print(f"  LoRA enabled: r={args.lora_r}, ~{trainable / 1e6:.1f}M trainable params (estimate)")

    # ------------------------------------------------------------------
    # Training config
    # ------------------------------------------------------------------
    sft_kwargs = {}
    if args.packing:
        sft_kwargs["packing"] = True
        sft_kwargs["eval_packing"] = False  # keep eval clean / comparable across runs
        eval_strat = "epoch" if eval_ds else "no"
        print(f"  Packing enabled: sequences packed to {args.max_seq_length} tokens (dense, no padding waste).")
    else:
        eval_strat = "epoch" if eval_ds else "no"

    training_args = SFTConfig(
        output_dir=args.output_dir,
        overwrite_output_dir=True,

        # SFT-specific: sequence length (controls truncation and packing block size)
        max_length=args.max_seq_length,

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
        bf16=bf16_ok,
        bf16_full_eval=bf16_ok,
        fp16=not bf16_ok,
        fp16_full_eval=not bf16_ok,

        # Logging
        logging_steps=10,
        logging_first_step=True,
        report_to="none",

        # Saving
        save_strategy="epoch",
        save_total_limit=3,

        # Eval
        eval_strategy=eval_strat,

        # Misc
        seed=args.seed,
        dataloader_pin_memory=cuda_available,
        dataloader_num_workers=4,
        gradient_checkpointing=not args.no_lora,  # save memory with LoRA
        gradient_checkpointing_kwargs={"use_reentrant": False} if not args.no_lora else None,
        optim="paged_adamw_8bit" if use_4bit else "adamw_torch",

        # Remove unused columns (our dataset has metadata fields)
        remove_unused_columns=True,

        **sft_kwargs,
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
