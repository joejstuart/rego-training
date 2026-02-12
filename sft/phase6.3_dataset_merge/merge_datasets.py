#!/usr/bin/env python3
"""Phase 6.3: merge phase4 and phase6.2 datasets into a single JSONL."""

from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SFT_ROOT = SCRIPT_DIR.parent
BASE_DATASET = SFT_ROOT / "phase4_dataset" / "output" / "rego_sft.jsonl"
ADDON_DATASET = SFT_ROOT / "phase6.2_candidate_dataset" / "output" / "policy_candidates_sft.jsonl"
OUTPUT_DIR = SCRIPT_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "rego_sft_merged.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main() -> None:
    if not BASE_DATASET.exists():
        raise FileNotFoundError(f"Missing base dataset: {BASE_DATASET}")
    if not ADDON_DATASET.exists():
        raise FileNotFoundError(f"Missing addon dataset: {ADDON_DATASET}")

    base = _load_jsonl(BASE_DATASET)
    addon = _load_jsonl(ADDON_DATASET)

    for rec in base:
        rec.setdefault("source", "phase4")
        rec.setdefault("task_type", "deny_rule")

    merged = base + addon
    random.seed(42)
    random.shuffle(merged)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        for rec in merged:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"Base:   {len(base)}")
    print(f"Addon:  {len(addon)}")
    print(f"Merged: {len(merged)}")
    print(f"Output: {OUTPUT_FILE}")
    print("By source:", dict(Counter(r.get("source", "unknown") for r in merged)))
    print("By task_type:", dict(Counter(r.get("task_type", "unknown") for r in merged)))


if __name__ == "__main__":
    main()
