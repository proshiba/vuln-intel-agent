#!/usr/bin/env bash

set -euo pipefail

echo "Configuring Python development environment..."

sudo mkdir -p /home/vscode/.codex
sudo chown -R vscode:vscode /home/vscode/.codex
sudo mkdir -p .venv
sudo chown -R vscode:vscode .venv

if [ ! -x ".venv/bin/python" ]; then
    python -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip setuptools wheel

if [ -f "pyproject.toml" ]; then
    .venv/bin/pip install --editable ".[dev,ai]"
elif [ -f "requirements.txt" ]; then
    .venv/bin/pip install --requirement requirements.txt
fi

echo
echo "Versions:"
python --version
node --version
npm --version
codex --version
