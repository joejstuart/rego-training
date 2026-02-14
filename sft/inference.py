#!/usr/bin/env python3
"""Run inference with the fine-tuned Rego expert model.

Supports LoRA adapters (default from train.py) and merged models.

Usage:
    # Interactive chat
    python inference.py --model ./output/rego-expert-4b

    # Single prompt
    python inference.py --model ./output/rego-expert-4b \
        --prompt "Write Rego policy code to validate predicateType"

    # From a file
    python inference.py --model ./output/rego-expert-4b --prompt-file prompt.txt

    # Use the base model (no fine-tuning) for comparison
    python inference.py --model Qwen/Qwen3-4B

    # Disable thinking (faster, no <think> block)
    python inference.py --model ./output/rego-expert-4b --no-think

    # Adjust generation params
    python inference.py --model ./output/rego-expert-4b --max-tokens 1024 --temperature 0.3
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# ---------------------------------------------------------------------------
# System prompt — must match what SFT / GRPO training used (includes schema)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """\
You are an expert in the Rego policy language (Open Policy Agent). \
You specialize in writing Rego policy code for verifying SLSA provenance attestations.

Conventions you always follow:
- Use `import rego.v1` (Rego v1 syntax).
- Depending on the request, produce either:
  - a deny policy rule (for policy decisions), or
  - a standalone helper function/rule (for reusable logic).
- Use `some x in collection` to iterate (Rego v1 iteration, not indexing).
- Use `sprintf` for user-facing messages when generating deny rules.
- The attestation document is accessed via `input`.
- For deny-rule tests: use `count(<pkg>.deny) == 0` (positive) and `count(<pkg>.deny) > 0` (negative).
- For helper-method tests: assert the helper's expected boolean/value result directly.

SLSA attestation schema (field → JSON path):
- _type: ._type
- predicateType: .predicateType
- subject[*].name: .subject[*].name
- subject[*].digest.sha256: .subject[*].digest.sha256
- buildType: .predicate.buildType
- builder.id: .predicate.builder.id
- materials: .predicate.materials (array)
- materials[*].uri: .predicate.materials[*].uri
- materials[*].digest.sha256: .predicate.materials[*].digest.sha256
- materials[*].digest.sha1: .predicate.materials[*].digest.sha1
- invocation.parameters.git-url: .predicate.invocation.parameters.git-url
- invocation.parameters.revision: .predicate.invocation.parameters.revision
- invocation.parameters.output-image: .predicate.invocation.parameters.output-image
- invocation.parameters.hermetic: .predicate.invocation.parameters.hermetic
- invocation.parameters.rebuild: .predicate.invocation.parameters.rebuild
- invocation.parameters.skip-checks: .predicate.invocation.parameters.skip-checks
- metadata.buildStartedOn: .predicate.metadata.buildStartedOn
- metadata.buildFinishedOn: .predicate.metadata.buildFinishedOn
- metadata.reproducible: .predicate.metadata.reproducible
- tasks[*].name: .predicate.buildConfig.tasks[*].name
- tasks[*].status: .predicate.buildConfig.tasks[*].status
- tasks[*].startedOn: .predicate.buildConfig.tasks[*].startedOn
- tasks[*].finishedOn: .predicate.buildConfig.tasks[*].finishedOn
- tasks[*].serviceAccountName: .predicate.buildConfig.tasks[*].serviceAccountName
- tasks[*].ref.resolver: .predicate.buildConfig.tasks[*].ref.resolver
- tasks[*].ref.params[*].name: .predicate.buildConfig.tasks[*].ref.params[*].name
- tasks[*].ref.params[*].value: .predicate.buildConfig.tasks[*].ref.params[*].value
- tasks[*].steps: .predicate.buildConfig.tasks[*].steps (array)
- tasks[*].steps[*].entryPoint: .predicate.buildConfig.tasks[*].steps[*].entryPoint
- tasks[*].steps[*].environment.container: .predicate.buildConfig.tasks[*].steps[*].environment.container
- tasks[*].steps[*].environment.image: .predicate.buildConfig.tasks[*].steps[*].environment.image
- tasks[*].results[*].name: .predicate.buildConfig.tasks[*].results[*].name
- tasks[*].results[*].type: .predicate.buildConfig.tasks[*].results[*].type
- tasks[*].results[*].value: .predicate.buildConfig.tasks[*].results[*].value
- tasks[*].invocation.parameters.HERMETIC: .predicate.buildConfig.tasks[*].invocation.parameters.HERMETIC
- tasks[*].invocation.parameters.TLSVERIFY: .predicate.buildConfig.tasks[*].invocation.parameters.TLSVERIFY
- tasks[*].invocation.parameters.COMMIT_SHA: .predicate.buildConfig.tasks[*].invocation.parameters.COMMIT_SHA
- tasks[*].invocation.parameters.DOCKERFILE: .predicate.buildConfig.tasks[*].invocation.parameters.DOCKERFILE
- tasks[*].invocation.parameters.IMAGE: .predicate.buildConfig.tasks[*].invocation.parameters.IMAGE\
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
    p.add_argument("--sft-model", type=str, default=None,
                    help="SFT LoRA adapter to merge before applying --model LoRA. "
                         "Required when --model is a GRPO adapter (trained on top of SFT).")

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
        from peft import PeftModel
        model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            torch_dtype=torch.bfloat16,
            device_map="auto",
            trust_remote_code=True,
        )

        # If an SFT adapter is specified, merge it first (needed for GRPO adapters
        # which were trained on top of the SFT-merged weights, not the raw base)
        if args.sft_model:
            sft_path = Path(args.sft_model)
            if (sft_path / "adapter_config.json").exists():
                print(f"  Merging SFT LoRA from {args.sft_model}...")
                model = PeftModel.from_pretrained(model, args.sft_model)
                model = model.merge_and_unload()
                print(f"  SFT LoRA merged into base weights.")
            else:
                print(f"  WARNING: --sft-model {args.sft_model} has no adapter_config.json, skipping.")

        print(f"  Applying LoRA adapter from {args.model}...")
        model = PeftModel.from_pretrained(model, args.model)
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
