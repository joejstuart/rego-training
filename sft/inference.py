#!/usr/bin/env python3
"""Run inference with the fine-tuned Rego expert model.

Supports LoRA adapters (default from train.py) and merged models.

Usage:
    # Interactive chat
    python inference.py --model ./output/rego-expert

    # Single prompt
    python inference.py --model ./output/rego-expert \
        --prompt "Write a Rego deny rule that rejects if predicateType is wrong"

    # From a file
    python inference.py --model ./output/rego-expert --prompt-file prompt.txt

    # Use the base model (no fine-tuning) for comparison
    python inference.py --model Qwen/Qwen3-4B

    # Disable thinking (faster, no <think> block)
    python inference.py --model ./output/rego-expert --no-think

    # Adjust generation params
    python inference.py --model ./output/rego-expert --max-tokens 1024 --temperature 0.3
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# ---------------------------------------------------------------------------
# System prompt (same as training)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """\
You are an expert in the Rego policy language (Open Policy Agent). \
You specialize in writing deny rules for verifying SLSA provenance attestations.

Conventions you always follow:
- Use `import rego.v1` (Rego v1 syntax).
- Use `deny contains msg if { ... }` (partial set rules). Rules fire when something is WRONG.
- Use `some x in collection` to iterate (Rego v1 iteration, not indexing).
- Use `sprintf` to produce human-readable deny messages.
- The attestation document is accessed via `input`.
- Tests use `count(<pkg>.deny) == 0` for positive cases and `count(<pkg>.deny) > 0` for negative cases.\
"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run inference with the fine-tuned Rego expert",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument("--model", type=str, required=True,
                    help="Model path: LoRA adapter dir, merged model dir, or HF model name.")
    p.add_argument("--base-model", type=str, default="Qwen/Qwen3-4B",
                    help="Base model (only needed if --model points to a LoRA adapter).")

    # Input
    p.add_argument("--prompt", type=str, default=None,
                    help="Single prompt to run. If omitted, starts interactive mode.")
    p.add_argument("--prompt-file", type=str, default=None,
                    help="Read prompt from a file.")

    # Generation
    p.add_argument("--max-tokens", type=int, default=2048,
                    help="Maximum new tokens to generate.")
    p.add_argument("--temperature", type=float, default=0.6,
                    help="Sampling temperature (0 = greedy).")
    p.add_argument("--top-p", type=float, default=0.95,
                    help="Nucleus sampling top-p.")
    p.add_argument("--top-k", type=int, default=20,
                    help="Top-k sampling.")
    p.add_argument("--no-think", action="store_true",
                    help="Disable thinking mode (suppress <think> block).")
    p.add_argument("--show-think", action="store_true",
                    help="Show the <think> reasoning block in output (hidden by default).")

    # System
    p.add_argument("--system-prompt", type=str, default=SYSTEM_PROMPT,
                    help="Override the system prompt.")
    p.add_argument("--no-system-prompt", action="store_true",
                    help="Omit the system prompt entirely.")

    return p.parse_args()


def load_model(args: argparse.Namespace):
    """Load model and tokenizer, handling LoRA adapters automatically."""
    model_path = Path(args.model)

    # Detect if this is a LoRA adapter (has adapter_config.json)
    is_lora = (model_path / "adapter_config.json").exists()

    print(f"Loading tokenizer from {args.model}...")
    tokenizer = AutoTokenizer.from_pretrained(
        args.model if not is_lora else args.base_model,
        trust_remote_code=True,
    )

    if is_lora:
        print(f"Detected LoRA adapter at {args.model}")
        print(f"Loading base model {args.base_model}...")
        from peft import AutoPeftModelForCausalLM
        model = AutoPeftModelForCausalLM.from_pretrained(
            args.model,
            torch_dtype=torch.bfloat16,
            device_map="auto",
            trust_remote_code=True,
        )
        print(f"  LoRA adapter loaded and applied.")
    else:
        print(f"Loading model from {args.model}...")
        model = AutoModelForCausalLM.from_pretrained(
            args.model,
            torch_dtype=torch.bfloat16,
            device_map="auto",
            trust_remote_code=True,
        )

    model.eval()
    print(f"  Device: {model.device}")
    print(f"  Parameters: {sum(p.numel() for p in model.parameters()) / 1e9:.1f}B")

    return model, tokenizer


def generate(
    model,
    tokenizer,
    prompt: str,
    args: argparse.Namespace,
) -> str:
    """Generate a response for a single prompt."""
    # Build messages
    messages = []
    if not args.no_system_prompt:
        messages.append({"role": "system", "content": args.system_prompt})
    messages.append({"role": "user", "content": prompt})

    # Apply chat template
    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
        enable_thinking=not args.no_think,
    )

    inputs = tokenizer(text, return_tensors="pt").to(model.device)

    # Generate
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=args.max_tokens,
            temperature=args.temperature if args.temperature > 0 else None,
            top_p=args.top_p if args.temperature > 0 else None,
            top_k=args.top_k if args.temperature > 0 else None,
            do_sample=args.temperature > 0,
        )

    # Decode only the new tokens
    new_tokens = outputs[0][inputs["input_ids"].shape[1]:]
    response = tokenizer.decode(new_tokens, skip_special_tokens=True)

    return response


def format_response(response: str, show_think: bool) -> str:
    """Optionally strip the <think> block from the response."""
    if not show_think and "<think>" in response:
        # Strip the think block
        parts = response.split("</think>")
        if len(parts) > 1:
            return parts[-1].strip()
        # If no closing tag, the whole response is thinking — show it anyway
        return response

    return response


def run_interactive(model, tokenizer, args: argparse.Namespace) -> None:
    """Interactive chat loop."""
    print("\n" + "=" * 60)
    print("  Rego Expert — Interactive Mode")
    print("  Type your prompt and press Enter.")
    print("  Type 'quit' or Ctrl+D to exit.")
    print("=" * 60 + "\n")

    while True:
        try:
            prompt = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not prompt:
            continue
        if prompt.lower() in ("quit", "exit", "q"):
            print("Bye!")
            break

        response = generate(model, tokenizer, prompt, args)
        formatted = format_response(response, args.show_think)
        print(f"\nAssistant:\n{formatted}\n")


def main() -> None:
    args = parse_args()

    model, tokenizer = load_model(args)

    # Determine the prompt
    prompt = args.prompt
    if args.prompt_file:
        prompt = Path(args.prompt_file).read_text().strip()

    if prompt:
        # Single-shot mode
        response = generate(model, tokenizer, prompt, args)
        formatted = format_response(response, args.show_think)
        print(formatted)
    else:
        # Interactive mode
        run_interactive(model, tokenizer, args)


if __name__ == "__main__":
    main()
