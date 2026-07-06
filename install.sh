#!/usr/bin/env bash
# attestinfer installer (Linux/macOS). Zero required dependencies.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
echo "==> Using $($PY --version)"
$PY -m pip install --upgrade pip >/dev/null

if [ "${1:-}" = "--fast" ]; then
  echo "==> Installing with optional PyNaCl cross-check"
  $PY -m pip install -e ".[fast]"
else
  echo "==> Installing (pure-Python, no third-party deps)"
  $PY -m pip install -e .
fi

echo "==> Verifying"
$PY -c "import attestinfer; print('attestinfer', attestinfer.__version__, 'installed OK')"
$PY examples/demo.py >/dev/null && echo "==> Demo passed"
echo "Done. Try:  attestinfer --help"
