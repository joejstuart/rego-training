#!/usr/bin/env python3
"""
Phase 3: Generate Rego Rules via LLM and Validate with OPA.

For each (instruction, test) pair from Phases 1 and 2, this script:
  1. Sends the instruction + test to an OpenAI-compatible LLM API
  2. Extracts the Rego rule from the response
  3. Writes the rule + test to a task directory
  4. Validates with ``opa check`` (syntax) and ``opa test`` (functional)
  5. On failure, retries with error feedback (up to --max-retries)
  6. Records results in result.json

Works with any OpenAI-compatible API: Ollama, Granite, OpenAI, vLLM, etc.

Configuration (CLI flags with env var fallbacks):
    --api-url   / MODEL_API   — API base URL (e.g. http://localhost:11434/v1)
    --model     / MODEL_ID    — Model name (e.g. qwen3-coder:30b)
    --api-key   / USER_KEY    — API key (use "ollama" for local Ollama)

Usage:
    cd sft/

    # Using env vars (from .env):
    python phase3_rules/generate_rules.py

    # Using CLI flags:
    python phase3_rules/generate_rules.py \\
        --api-url http://localhost:11434/v1 \\
        --model qwen3-coder:30b \\
        --api-key ollama

    # Process only specific tasks:
    python phase3_rules/generate_rules.py --tasks predicate_type_check type_check

    # Resume from where you left off (skip already-passing tasks):
    python phase3_rules/generate_rules.py --skip-passing
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


# ─── Constants ────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = textwrap.dedent("""\
    You are a Rego policy expert. You write concise, correct Rego rules for
    verifying SLSA provenance attestations.

    CRITICAL RULES — follow these exactly:

    1. Always use Rego v1 syntax:
       - Start with: package <package_name>
       - Then:       import rego.v1

    2. Use the deny set pattern:
       deny contains msg if {
           <conditions>
           msg := "<human-readable violation message>"
       }

    3. Use modern Rego v1 constructs:
       - ``some x in collection`` for iteration
       - ``every x in collection { ... }`` for universal checks
       - ``if`` keyword in rule heads
       - ``contains`` keyword for partial set rules
       - ``in`` keyword for membership checks

    4. Access input data via ``input.<path>``:
       - input.predicateType
       - input.predicate.buildConfig.tasks
       - input.subject[i].digest.sha256

    5. For iterating arrays, use:
       some task in input.predicate.buildConfig.tasks
       NOT: input.predicate.buildConfig.tasks[i]

    6. For checking string prefixes, use:
       startswith(value, "prefix")

    7. For timestamp comparison, use:
       time.parse_rfc3339_ns(ts1) > time.parse_rfc3339_ns(ts2)

    8. Output ONLY the .rego file contents. No markdown fencing, no
       explanation, no commentary. Just the raw Rego code.

    9. The package name MUST match exactly what is specified in the prompt.
""")


# ─── LLM API ─────────────────────────────────────────────────────────────────

def _call_llm(
    api_url: str,
    model: str,
    api_key: str,
    system: str,
    user: str,
    temperature: float = 0.3,
    max_tokens: int = 2048,
) -> str:
    """Call an OpenAI-compatible chat completions endpoint."""
    url = f"{api_url.rstrip('/')}/chat/completions"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"LLM API returned {e.code}: {error_body}"
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Could not connect to LLM API at {url}: {e.reason}"
        ) from e


# ─── Rego extraction ─────────────────────────────────────────────────────────

def _extract_rego(raw: str) -> str:
    """
    Extract Rego code from LLM response.

    Handles:
      - Raw Rego (no fencing)
      - Markdown fenced blocks (```rego ... ``` or ``` ... ```)
      - Leading/trailing commentary
    """
    # Try to extract from markdown fence
    fence_match = re.search(
        r"```(?:rego)?\s*\n(.*?)```",
        raw,
        re.DOTALL,
    )
    if fence_match:
        return fence_match.group(1).strip() + "\n"

    # Look for the package declaration and take everything from there
    pkg_match = re.search(r"^(package\s+\S+.*)", raw, re.MULTILINE | re.DOTALL)
    if pkg_match:
        return pkg_match.group(1).strip() + "\n"

    # Last resort: return as-is
    return raw.strip() + "\n"


# ─── OPA validation ──────────────────────────────────────────────────────────

def _run_opa_check(task_dir: Path) -> tuple[bool, str]:
    """Run ``opa check .`` in the task directory. Returns (passed, output)."""
    try:
        result = subprocess.run(
            ["opa", "check", "."],
            cwd=str(task_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except FileNotFoundError:
        return False, "ERROR: opa not found in PATH"
    except subprocess.TimeoutExpired:
        return False, "ERROR: opa check timed out"


def _run_opa_test(task_dir: Path) -> tuple[bool, str]:
    """Run ``opa test . -v`` in the task directory. Returns (passed, output)."""
    try:
        result = subprocess.run(
            ["opa", "test", ".", "-v"],
            cwd=str(task_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        passed = result.returncode == 0 and "FAIL" not in output
        return passed, output
    except FileNotFoundError:
        return False, "ERROR: opa not found in PATH"
    except subprocess.TimeoutExpired:
        return False, "ERROR: opa test timed out"


# ─── Prompt construction ─────────────────────────────────────────────────────

def _build_user_prompt(inst: dict, test_content: str) -> str:
    """Build the initial user prompt for the LLM."""
    return textwrap.dedent(f"""\
        Write a Rego rule file for this task.

        **Package name:** {inst["package_name"]}

        **Instruction:** {inst["instruction"]}

        **The tests below must pass.** Your rule must make both the positive
        and negative tests succeed:

        ```rego
        {test_content.strip()}
        ```

        Remember:
        - package {inst["package_name"]}
        - import rego.v1
        - deny contains msg if {{ ... }}
        - Output ONLY the .rego file. No markdown, no explanation.
    """)


def _build_retry_prompt(
    inst: dict,
    test_content: str,
    previous_rule: str,
    error_output: str,
    attempt: int,
) -> str:
    """Build a retry prompt with error feedback."""
    return textwrap.dedent(f"""\
        Your previous attempt (attempt {attempt}) for package
        ``{inst["package_name"]}`` failed validation.

        **Instruction:** {inst["instruction"]}

        **Tests that must pass:**
        ```rego
        {test_content.strip()}
        ```

        **Your previous rule:**
        ```rego
        {previous_rule.strip()}
        ```

        **Error output:**
        ```
        {error_output.strip()}
        ```

        Fix the rule. Output ONLY the corrected .rego file contents.
        No markdown fencing, no explanation.
    """)


# ─── Per-task pipeline ───────────────────────────────────────────────────────

def _process_task(
    inst: dict,
    test_content: str,
    task_dir: Path,
    api_url: str,
    model: str,
    api_key: str,
    max_retries: int,
    delay: float,
) -> dict:
    """
    Generate, validate, and (if needed) retry a Rego rule for one task.

    Returns a result dict for result.json.
    """
    pkg = inst["package_name"]
    task_id = inst["id"]
    rule_file = task_dir / f"{pkg}.rego"
    test_file = task_dir / f"{pkg}_test.rego"

    # Write the test file into the task directory
    test_file.write_text(test_content, encoding="utf-8")

    result = {
        "task_id": task_id,
        "tier": inst["tier"],
        "package_name": pkg,
        "attempts": 0,
        "opa_check": "not_run",
        "opa_test": "not_run",
        "test_output": "",
        "errors": [],
        "status": "pending",
    }

    user_prompt = _build_user_prompt(inst, test_content)
    previous_rule = ""
    error_output = ""

    for attempt in range(1, max_retries + 1):
        result["attempts"] = attempt

        # Construct the prompt
        if attempt == 1:
            prompt = user_prompt
        else:
            prompt = _build_retry_prompt(
                inst, test_content, previous_rule, error_output, attempt
            )

        # Call the LLM
        try:
            raw_response = _call_llm(
                api_url, model, api_key,
                system=SYSTEM_PROMPT,
                user=prompt,
            )
        except RuntimeError as e:
            result["errors"].append(f"LLM API error (attempt {attempt}): {e}")
            result["status"] = "api_error"
            if delay > 0:
                time.sleep(delay)
            continue

        # Extract and write the rule
        rego_code = _extract_rego(raw_response)
        rule_file.write_text(rego_code, encoding="utf-8")
        previous_rule = rego_code

        # Validate syntax
        check_ok, check_output = _run_opa_check(task_dir)
        result["opa_check"] = "pass" if check_ok else "fail"

        if not check_ok:
            error_output = f"opa check failed:\n{check_output}"
            result["errors"].append(f"Attempt {attempt}: {error_output}")
            if delay > 0:
                time.sleep(delay)
            continue

        # Validate tests
        test_ok, test_output = _run_opa_test(task_dir)
        result["opa_test"] = "pass" if test_ok else "fail"
        result["test_output"] = test_output

        if test_ok:
            result["status"] = "pass"
            return result

        error_output = f"opa test failed:\n{test_output}"
        result["errors"].append(f"Attempt {attempt}: {error_output}")
        if delay > 0:
            time.sleep(delay)

    # Exhausted retries
    if result["status"] == "pending":
        result["status"] = "fail"

    return result


# ─── Main ─────────────────────────────────────────────────────────────────────

def _load_instructions(path: str) -> list[dict]:
    """Load the JSONL instructions file."""
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def generate_rules(
    instructions_path: str,
    tests_dir: str,
    output_dir: str,
    api_url: str,
    model: str,
    api_key: str,
    max_retries: int = 3,
    delay: float = 1.0,
    task_filter: list[str] | None = None,
    skip_passing: bool = False,
) -> list[dict]:
    """Run the full Phase 3 pipeline."""
    instructions = _load_instructions(instructions_path)
    tests_root = Path(tests_dir)
    out_root = Path(output_dir)

    results: list[dict] = []
    stats = {"pass": 0, "fail": 0, "api_error": 0, "skipped": 0}

    if task_filter:
        filter_set = set(task_filter)
        instructions = [i for i in instructions if i["id"] in filter_set]

    total = len(instructions)
    print(f"Phase 3: Generating Rego rules via LLM")
    print(f"  API:    {api_url}")
    print(f"  Model:  {model}")
    print(f"  Tasks:  {total}")
    print(f"  Retries: {max_retries}")
    print()

    for idx, inst in enumerate(instructions, 1):
        task_id = inst["id"]
        pkg = inst["package_name"]

        # Find the test file from Phase 2
        test_file = tests_root / "tasks" / task_id / f"{pkg}_test.rego"
        if not test_file.exists():
            print(f"  [{idx}/{total}] {task_id}: SKIP (no test file)")
            stats["skipped"] += 1
            continue

        test_content = test_file.read_text(encoding="utf-8")

        # Set up output directory
        task_dir = out_root / "tasks" / task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        # Skip if already passing and --skip-passing
        result_file = task_dir / "result.json"
        if skip_passing and result_file.exists():
            try:
                existing = json.loads(result_file.read_text(encoding="utf-8"))
                if existing.get("status") == "pass":
                    print(f"  [{idx}/{total}] {task_id}: SKIP (already passing)")
                    results.append(existing)
                    stats["pass"] += 1
                    continue
            except (json.JSONDecodeError, KeyError):
                pass  # Re-process if result.json is corrupt

        # Process the task
        print(f"  [{idx}/{total}] {task_id} (tier {inst['tier']})...", end=" ", flush=True)

        result = _process_task(
            inst=inst,
            test_content=test_content,
            task_dir=task_dir,
            api_url=api_url,
            model=model,
            api_key=api_key,
            max_retries=max_retries,
            delay=delay,
        )

        # Write result.json
        result_file.write_text(
            json.dumps(result, indent=2) + "\n",
            encoding="utf-8",
        )
        results.append(result)

        status = result["status"]
        attempts = result["attempts"]
        stats[status] = stats.get(status, 0) + 1

        if status == "pass":
            print(f"PASS (attempt {attempts})")
        else:
            print(f"FAIL ({status}, {attempts} attempts)")

    # Summary
    print()
    print("=" * 60)
    print(f"Phase 3 Results")
    print(f"  Total:     {total}")
    print(f"  Passed:    {stats['pass']}")
    print(f"  Failed:    {stats['fail']}")
    print(f"  API Error: {stats['api_error']}")
    print(f"  Skipped:   {stats['skipped']}")
    print(f"  Pass rate: {stats['pass']}/{total - stats['skipped']} "
          f"({100 * stats['pass'] / max(1, total - stats['skipped']):.0f}%)")
    print("=" * 60)

    # Write summary
    summary_file = out_root / "summary.json"
    summary_file.write_text(
        json.dumps({
            "total": total,
            "stats": stats,
            "model": model,
            "api_url": api_url,
            "max_retries": max_retries,
        }, indent=2) + "\n",
        encoding="utf-8",
    )

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Phase 3: Generate Rego rules via LLM and validate with OPA.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Use env vars from .env:
              python phase3_rules/generate_rules.py

              # Use Ollama locally:
              python phase3_rules/generate_rules.py \\
                  --api-url http://localhost:11434/v1 \\
                  --model qwen3-coder:30b \\
                  --api-key ollama

              # Process specific tasks only:
              python phase3_rules/generate_rules.py \\
                  --tasks predicate_type_check type_check

              # Resume, skipping already-passing tasks:
              python phase3_rules/generate_rules.py --skip-passing
        """),
    )
    parser.add_argument(
        "--instructions", type=str,
        default="phase1_instructions/output/instructions.jsonl",
        help="Path to instructions JSONL (default: phase1_instructions/output/instructions.jsonl).",
    )
    parser.add_argument(
        "--tests", type=str,
        default="phase2_tests/output",
        help="Phase 2 test output directory (default: phase2_tests/output).",
    )
    parser.add_argument(
        "--output", type=str,
        default="phase3_rules/output",
        help="Output directory (default: phase3_rules/output).",
    )
    parser.add_argument(
        "--api-url", type=str,
        default=os.environ.get("MODEL_API", "http://localhost:11434/v1"),
        help="OpenAI-compatible API base URL (default: $MODEL_API or http://localhost:11434/v1).",
    )
    parser.add_argument(
        "--model", type=str,
        default=os.environ.get("MODEL_ID", "qwen3-coder:30b"),
        help="Model name (default: $MODEL_ID or qwen3-coder:30b).",
    )
    parser.add_argument(
        "--api-key", type=str,
        default=os.environ.get("USER_KEY", "ollama"),
        help="API key (default: $USER_KEY or 'ollama').",
    )
    parser.add_argument(
        "--max-retries", type=int, default=3,
        help="Max attempts per task (default: 3).",
    )
    parser.add_argument(
        "--delay", type=float, default=1.0,
        help="Delay in seconds between retries and between tasks (default: 1.0).",
    )
    parser.add_argument(
        "--tasks", nargs="*", default=None,
        help="Only process these task IDs (space-separated). Default: all.",
    )
    parser.add_argument(
        "--skip-passing", action="store_true",
        help="Skip tasks that already have a passing result.json.",
    )
    args = parser.parse_args()

    # Try to load .env if python-dotenv is available
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
        # Re-resolve defaults from env if not explicitly set on CLI
        if args.api_url == "http://localhost:11434/v1" and os.environ.get("MODEL_API"):
            args.api_url = os.environ["MODEL_API"]
        if args.model == "qwen3-coder:30b" and os.environ.get("MODEL_ID"):
            args.model = os.environ["MODEL_ID"]
        if args.api_key == "ollama" and os.environ.get("USER_KEY"):
            args.api_key = os.environ["USER_KEY"]
    except ImportError:
        pass  # dotenv is optional

    generate_rules(
        instructions_path=args.instructions,
        tests_dir=args.tests,
        output_dir=args.output,
        api_url=args.api_url,
        model=args.model,
        api_key=args.api_key,
        max_retries=args.max_retries,
        delay=args.delay,
        task_filter=args.tasks,
        skip_passing=args.skip_passing,
    )


if __name__ == "__main__":
    main()
