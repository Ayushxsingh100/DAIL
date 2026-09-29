#!/usr/bin/env bash
# Local bootstrap command (P0 deliverable, Doc 15 Section 7.2).
# Deliberately uses only the Python 3.12 standard library: this must succeed
# on a fresh clone with no network access and no secrets (P0 exit criteria).
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "== Checking Python version =="
"$PYTHON_BIN" --version
REQUIRED_MAJOR_MINOR="3.12"
ACTUAL="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [ "$ACTUAL" != "$REQUIRED_MAJOR_MINOR" ]; then
  echo "WARNING: expected Python ${REQUIRED_MAJOR_MINOR}.x, found ${ACTUAL}. Continuing, but pin mismatch should be fixed."
fi

echo "== Creating local data directory =="
mkdir -p .local

echo "== Initializing local sqlite storage =="
"$PYTHON_BIN" -c "
from core.domain.storage import LocalStorage
from evidence.store import EvidenceStore
storage = LocalStorage('.local/dail.db')
storage.initialize_schema()
EvidenceStore('.local/dail.db').initialize_schema()
print('Domain + evidence schema initialized at .local/dail.db')
"

echo "== Running domain unit tests (stdlib only, no secrets/network) =="
"$PYTHON_BIN" -m unittest discover -s tests -p "test_*.py" -v

echo ""
echo "Bootstrap complete. Fresh clone -> tests passing, per P0 exit criteria."
echo "Once you have network access, run: pip install -e \".[dev]\" for the full toolchain."
