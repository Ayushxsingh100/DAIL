#!/usr/bin/env bash
# Local bootstrap command (Doc 15 §7.2, Doc 14 §12): thin wrapper around
# scripts/dev.py bootstrap, which uses only the Python 3.12 standard library.
# On Windows use WSL or Git Bash, or run: python scripts/dev.py bootstrap
set -euo pipefail

cd "$(dirname "$0")/.."

exec "${PYTHON_BIN:-python3}" scripts/dev.py bootstrap "$@"
