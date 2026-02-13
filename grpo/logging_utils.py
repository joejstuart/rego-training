#!/usr/bin/env python3
"""Structured logging for GRPO training — captures per-step completions and rewards.

Produces two outputs:
  1. **JSONL log** (`step_log.jsonl`) — one JSON object per training step with
     prompts, all N completions, per-function reward scores, and training metrics.
     Easy to load into pandas for analysis.
  2. **Console summaries** — human-readable snapshots every N steps showing
     best/worst completions, reward breakdowns, and which prompts are hardest.

Usage (integrated via grpo/train.py):
    python -m grpo.train --log-every 5

Analysis:
    # Quick look
    python -c "
    import json, pandas as pd
    rows = [json.loads(l) for l in open('grpo/output/rego-expert-grpo-8b/step_log.jsonl')]
    df = pd.json_normalize(rows)
    print(df[['step','task_id','variant','reward_mean','had_learning_signal']].to_string())
    "
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_think_and_code(response: str) -> tuple[str, str]:
    """Split a model response into its <think> trace and code portions."""
    think = ""
    code = response

    m = re.search(r"<think>(.*?)</think>", response, re.DOTALL)
    if m:
        think = m.group(1).strip()
        code = response[m.end():].strip()

    return think, code


def _get_response_text(completion: Any) -> str:
    """Extract plain text from a completion in various TRL formats.

    TRL may pass completions as:
      - ``[{"role": "assistant", "content": "..."}]``  (list of message dicts)
      - ``"raw text"``                                  (plain string)
    """
    if isinstance(completion, str):
        return completion
    if isinstance(completion, list) and len(completion) > 0:
        if isinstance(completion[0], dict):
            return completion[0].get("content", "")
    return str(completion)


def _extract_prompt_text(prompts: Any, idx: int) -> str:
    """Extract a human-readable prompt string from various formats.

    TRL may pass prompts as:
      - list of message-lists: ``[[{"role": "user", "content": "..."}], ...]``
      - list of strings: ``["...", ...]``
    """
    if prompts is None:
        return ""
    if idx >= len(prompts):
        return ""

    p = prompts[idx]
    if isinstance(p, list):
        # List of message dicts — find the user message
        for msg in reversed(p):
            if isinstance(msg, dict) and msg.get("role") == "user":
                return msg["content"]
        return str(p)[:200]
    return str(p)[:200]


# ===========================================================================
# StepLogger
# ===========================================================================

class StepLogger:
    """Wraps GRPO reward functions to capture completions and scores per step.

    Parameters
    ----------
    log_dir : str
        Directory where ``step_log.jsonl`` is written (usually the GRPO output dir).
    console_every : int
        Print a human-readable console summary every N steps.
    """

    def __init__(self, log_dir: str, console_every: int = 10):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "step_log.jsonl"
        self.console_every = console_every

        # Accumulates data across reward-function calls within a single step
        self._buffer: dict[str, Any] = {}
        self._steps_logged = 0

    # ------------------------------------------------------------------
    # Reward function wrapping
    # ------------------------------------------------------------------

    def wrap_reward_funcs(self, reward_funcs: list) -> list:
        """Return wrapped versions of each reward function that log their I/O."""
        return [self._make_wrapper(fn) for fn in reward_funcs]

    def _make_wrapper(self, fn):
        logger = self
        original_name = fn.__name__

        def wrapper(completions, **kwargs):
            scores = fn(completions, **kwargs)

            # First reward-func call in a step captures shared data
            if "completions_raw" not in logger._buffer:
                logger._buffer["completions_raw"] = completions
                # TRL may or may not pass prompts — capture if present
                logger._buffer["prompts"] = kwargs.get("prompts")
                # Dataset columns forwarded by GRPOTrainer
                logger._buffer["task_ids"] = kwargs.get("task_id", [])
                logger._buffer["variants"] = kwargs.get("variant", [])
                logger._buffer["package_names"] = kwargs.get("package_name", [])

            # Accumulate scores per reward function
            if "rewards" not in logger._buffer:
                logger._buffer["rewards"] = {}
            logger._buffer["rewards"][original_name] = [float(s) for s in scores]

            return scores

        wrapper.__name__ = original_name
        return wrapper

    # ------------------------------------------------------------------
    # Flush (called by the TrainerCallback after each logged step)
    # ------------------------------------------------------------------

    def flush(self, step: int, metrics: Optional[dict] = None) -> None:
        """Write the buffered step data to the JSONL log and optionally print."""
        if "completions_raw" not in self._buffer:
            return

        completions_raw = self._buffer["completions_raw"]
        prompts = self._buffer.get("prompts")
        task_ids = self._buffer.get("task_ids", [])
        variants = self._buffer.get("variants", [])
        rewards_by_func = self._buffer.get("rewards", {})

        n = len(completions_raw)

        # --- Per-completion detail ---
        completions_log = []
        totals: list[float] = []

        for i in range(n):
            response = _get_response_text(completions_raw[i])
            think, code = _extract_think_and_code(response)

            per_func: dict[str, float] = {}
            total = 0.0
            for fname, scores in rewards_by_func.items():
                s = scores[i] if i < len(scores) else 0.0
                per_func[fname] = round(s, 2)
                total += s

            totals.append(round(total, 2))
            completions_log.append({
                "code": code[:600],
                "think": think[:400] if think else "",
                "rewards": per_func,
                "total_reward": round(total, 2),
            })

        # --- Aggregate stats ---
        best_idx = totals.index(max(totals)) if totals else 0
        worst_idx = totals.index(min(totals)) if totals else 0
        reward_mean = sum(totals) / len(totals) if totals else 0.0
        reward_std = (
            (sum((t - reward_mean) ** 2 for t in totals) / len(totals)) ** 0.5
            if len(totals) > 1 else 0.0
        )
        has_signal = reward_std > 0.01  # tiny float tolerance

        # --- Identify prompt ---
        prompt_text = _extract_prompt_text(prompts, 0) if prompts else ""
        task_id = (
            task_ids[0] if isinstance(task_ids, list) and task_ids
            else str(task_ids) if task_ids else ""
        )
        variant = (
            variants[0] if isinstance(variants, list) and variants
            else str(variants) if variants else ""
        )

        # --- Build log record ---
        record = {
            "step": step,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "task_id": task_id,
            "variant": variant,
            "prompt": prompt_text[:300],
            "num_completions": n,
            "completions": completions_log,
            "best_idx": best_idx,
            "worst_idx": worst_idx,
            "reward_mean": round(reward_mean, 2),
            "reward_std": round(reward_std, 2),
            "had_learning_signal": has_signal,
        }
        if metrics:
            record["metrics"] = {
                k: round(v, 6) if isinstance(v, float) else v
                for k, v in metrics.items()
                if k in (
                    "loss", "grad_norm", "learning_rate", "reward",
                    "reward_std", "kl", "entropy",
                )
            }

        # --- Write JSONL ---
        with open(self.log_file, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")

        # --- Console summary ---
        self._steps_logged += 1
        if (self._steps_logged % self.console_every == 0) or step <= 3:
            self._print_step_summary(step, record)

        # Clear buffer for next step
        self._buffer = {}

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    def _print_step_summary(self, step: int, record: dict) -> None:
        rmean = record["reward_mean"]
        rstd = record["reward_std"]
        signal = "LEARNING" if record["had_learning_signal"] else "no signal"
        tid = record.get("task_id") or "?"
        var = record.get("variant") or "?"

        print(f"\n{'─' * 72}")
        print(f"  Step {step:>4d} │ {tid}/{var} │ reward {rmean:.1f}±{rstd:.1f} │ {signal}")

        # Best completion rewards
        best = record["completions"][record["best_idx"]]
        parts = " │ ".join(
            f"{k.replace('reward_', ''):>10s}: {v:+.1f}"
            for k, v in best["rewards"].items()
        )
        print(f"  Best  [{best['total_reward']:+.1f}]  {parts}")

        if record["had_learning_signal"]:
            worst = record["completions"][record["worst_idx"]]
            parts_w = " │ ".join(
                f"{k.replace('reward_', ''):>10s}: {v:+.1f}"
                for k, v in worst["rewards"].items()
            )
            print(f"  Worst [{worst['total_reward']:+.1f}]  {parts_w}")

        # Code preview (first 100 chars, one line)
        code_preview = best["code"].replace("\n", " ↵ ")[:120]
        print(f"  Code: {code_preview}")

        # Prompt preview
        if record.get("prompt"):
            print(f"  Prompt: {record['prompt'][:100]}")

        print(f"{'─' * 72}")

    # ------------------------------------------------------------------
    # End-of-training summary
    # ------------------------------------------------------------------

    def print_final_summary(self) -> None:
        """Read the log file and print aggregate statistics."""
        if not self.log_file.exists():
            print("  (no log file found)")
            return

        records = []
        with open(self.log_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

        if not records:
            print("  (log file is empty)")
            return

        total = len(records)
        with_signal = sum(1 for r in records if r.get("had_learning_signal"))
        avg_reward = sum(r["reward_mean"] for r in records) / total

        # Per-variant stats
        variant_stats: dict[str, list[float]] = defaultdict(list)
        for r in records:
            variant_stats[r.get("variant") or "?"].append(r["reward_mean"])

        # Hardest prompts (lowest reward)
        hard = sorted(records, key=lambda r: r["reward_mean"])[:5]

        # Reward function breakdown
        func_totals: dict[str, list[float]] = defaultdict(list)
        for r in records:
            for comp in r.get("completions", []):
                for fname, score in comp.get("rewards", {}).items():
                    func_totals[fname].append(score)

        print(f"\n{'=' * 72}")
        print(f"  GRPO Training Log Summary")
        print(f"{'=' * 72}")
        print(f"  Steps logged:          {total}")
        print(f"  Steps with signal:     {with_signal} ({100 * with_signal / total:.0f}%)")
        print(f"  Steps without signal:  {total - with_signal} ({100 * (total - with_signal) / total:.0f}%)")
        print(f"  Avg reward:            {avg_reward:.2f} / 15.0")

        print(f"\n  Reward by function (mean across all completions):")
        for fname, scores in sorted(func_totals.items()):
            avg = sum(scores) / len(scores)
            print(f"    {fname:30s}  avg={avg:+.2f}")

        print(f"\n  Reward by variant:")
        for v, scores in sorted(variant_stats.items()):
            avg = sum(scores) / len(scores)
            pct_signal = sum(1 for s in scores if s < 15.0) / len(scores) * 100
            print(f"    {v:25s}  avg={avg:.2f}  n={len(scores):3d}  imperfect={pct_signal:.0f}%")

        print(f"\n  Hardest prompts (lowest reward):")
        for r in hard:
            tid = r.get("task_id", "?")
            var = r.get("variant", "?")
            print(f"    step {r['step']:>4d} │ {tid}/{var:20s} │ reward: {r['reward_mean']:.1f}")

        print(f"\n  Log file: {self.log_file}")
        print(f"{'=' * 72}\n")

    # ------------------------------------------------------------------
    # TrainerCallback factory
    # ------------------------------------------------------------------

    def make_callback(self):
        """Return a TrainerCallback that flushes the log after each logged step."""
        logger = self
        from transformers import TrainerCallback

        class _StepLogCallback(TrainerCallback):
            def on_log(self, args, state, control, logs=None, **kwargs):
                logger.flush(state.global_step, logs)

        return _StepLogCallback()
