#!/usr/bin/env bash
# ============================================================================
# setup_training_env.sh — Reproduce the GRPO training environment with Unsloth
# ============================================================================
#
# Prerequisites:
#   - NVIDIA GPU with CUDA 12.x (tested on A10 / sm_86)
#   - Python 3.12
#   - nvcc available at /usr/local/cuda/bin/nvcc
#   - ninja build system (installed via pip below)
#   - opa and regal binaries on PATH (for reward functions)
#
# Usage:
#   cd rego-training
#   bash grpo/setup_training_env.sh
#
# After setup, run training with:
#   source sft/venv/bin/activate
#   python -m grpo.train
#
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$REPO_ROOT/sft/venv"

echo "============================================================"
echo "  GRPO Training Environment Setup"
echo "============================================================"
echo "  Repo root:  $REPO_ROOT"
echo "  Venv:       $VENV_DIR"
echo ""

# ------------------------------------------------------------------
# Step 1: Create or activate venv
# ------------------------------------------------------------------
if [ ! -d "$VENV_DIR" ]; then
    echo "[1/6] Creating Python venv at $VENV_DIR ..."
    python3.12 -m venv "$VENV_DIR"
else
    echo "[1/6] Venv already exists at $VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
echo "  Python: $(python --version) at $(which python)"

# ------------------------------------------------------------------
# Step 2: Upgrade pip and install build tools
# ------------------------------------------------------------------
echo ""
echo "[2/6] Upgrading pip and installing build tools ..."
pip install --upgrade pip
pip install wheel setuptools==80.10.2 ninja==1.13.0

# ------------------------------------------------------------------
# Step 3: Install pinned requirements
# ------------------------------------------------------------------
echo ""
echo "[3/6] Installing pinned requirements ..."
pip install -r "$SCRIPT_DIR/requirements.txt"

# ------------------------------------------------------------------
# Step 4: Fix curand.h for flashinfer JIT compilation
# ------------------------------------------------------------------
# flashinfer needs curand.h for JIT-compiling CUDA kernels at first run.
# The nvidia-curand-cu12 pip package ships the header, but nvcc looks in
# /usr/local/cuda/include/ which may not have it (e.g. runtime-only CUDA
# images on OpenShift). We add the pip package's include dir to CPATH.
# ------------------------------------------------------------------
echo ""
echo "[4/6] Configuring curand.h for flashinfer JIT ..."

CURAND_INCLUDE="$VENV_DIR/lib/python3.12/site-packages/nvidia/curand/include"
if [ -f "$CURAND_INCLUDE/curand.h" ]; then
    # Try to symlink into the system CUDA include dir
    if [ -w "/usr/local/cuda/include/" ]; then
        ln -sf "$CURAND_INCLUDE/curand.h" /usr/local/cuda/include/curand.h
        echo "  Symlinked curand.h → /usr/local/cuda/include/curand.h"
    else
        echo "  Cannot write to /usr/local/cuda/include/ (no root access)"
        echo "  Setting CPATH instead ..."
        export CPATH="$CURAND_INCLUDE:${CPATH:-}"
        echo "  CPATH=$CPATH"

        # Persist for future shells
        ACTIVATE_SCRIPT="$VENV_DIR/bin/activate"
        if ! grep -q "CPATH.*nvidia/curand" "$ACTIVATE_SCRIPT" 2>/dev/null; then
            echo "" >> "$ACTIVATE_SCRIPT"
            echo "# flashinfer JIT needs curand.h from pip-installed nvidia-curand-cu12" >> "$ACTIVATE_SCRIPT"
            echo "export CPATH=\"$CURAND_INCLUDE:\${CPATH:-}\"" >> "$ACTIVATE_SCRIPT"
            echo "  Added CPATH export to $ACTIVATE_SCRIPT"
        fi
    fi
else
    echo "  WARNING: curand.h not found at $CURAND_INCLUDE"
    echo "  flashinfer JIT compilation may fail. Install nvidia-curand-cu12."
fi

# ------------------------------------------------------------------
# Step 5: Clear stale flashinfer JIT cache
# ------------------------------------------------------------------
echo ""
echo "[5/6] Clearing stale flashinfer JIT cache ..."
CACHE_DIR="$REPO_ROOT/unsloth_compiled_cache/.cache/flashinfer"
if [ -d "$CACHE_DIR" ]; then
    rm -rf "$CACHE_DIR"
    echo "  Removed $CACHE_DIR"
else
    echo "  No stale cache found"
fi

# ------------------------------------------------------------------
# Step 6: Verify installation
# ------------------------------------------------------------------
echo ""
echo "[6/6] Verifying installation ..."
echo ""

python -c "
import sys

errors = []

# Core packages
try:
    import torch
    print(f'  torch:          {torch.__version__}')
    print(f'  CUDA available: {torch.cuda.is_available()}')
    if torch.cuda.is_available():
        print(f'  GPU:            {torch.cuda.get_device_name(0)}')
        print(f'  CUDA version:   {torch.version.cuda}')
except Exception as e:
    errors.append(f'torch: {e}')

try:
    import unsloth
    print(f'  unsloth:        {unsloth.__version__}')
except Exception as e:
    errors.append(f'unsloth: {e}')

try:
    import vllm
    print(f'  vllm:           {vllm.__version__}')
except Exception as e:
    errors.append(f'vllm: {e}')

try:
    import trl
    print(f'  trl:            {trl.__version__}')
except Exception as e:
    errors.append(f'trl: {e}')

try:
    import transformers
    print(f'  transformers:   {transformers.__version__}')
except Exception as e:
    errors.append(f'transformers: {e}')

try:
    import peft
    print(f'  peft:           {peft.__version__}')
except Exception as e:
    errors.append(f'peft: {e}')

try:
    import datasets
    print(f'  datasets:       {datasets.__version__}')
except Exception as e:
    errors.append(f'datasets: {e}')

try:
    import flashinfer
    print(f'  flashinfer:     {flashinfer.__version__}')
except Exception as e:
    errors.append(f'flashinfer: {e}')

# Check curand.h
import os, pathlib
curand_paths = [
    pathlib.Path('/usr/local/cuda/include/curand.h'),
    pathlib.Path(os.environ.get('CPATH', '').split(':')[0]) / 'curand.h' if os.environ.get('CPATH') else None,
]
curand_found = any(p and p.exists() for p in curand_paths)
print(f'  curand.h found: {curand_found}')

if errors:
    print()
    print('  ERRORS:')
    for e in errors:
        print(f'    ✗ {e}')
    sys.exit(1)
else:
    print()
    print('  ✓ All packages verified successfully')
"

echo ""
echo "============================================================"
echo "  Setup complete!"
echo ""
echo "  To start training:"
echo "    source $VENV_DIR/bin/activate"
echo "    python -m grpo.train \\"
echo "        --max-steps 600 \\"
echo "        --lr 5e-6 \\"
echo "        --lora-rank 32 \\"
echo "        --log-every 5"
echo "============================================================"
