#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/backend"

# Create venv on first run
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
  ./.venv/bin/pip install --quiet --upgrade pip
  ./.venv/bin/pip install --quiet -r requirements.txt
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"

echo "VulnScan console → http://${HOST}:${PORT}"
exec ./.venv/bin/uvicorn app:app --host "$HOST" --port "$PORT"
