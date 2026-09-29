# requirements/

`dev.lock` is the hash-locked dev toolchain (ADR-002). It is generated from the
exact pins in the `dev` extra of `pyproject.toml` and committed to the
repository. CI installs it with `--require-hashes`; it is never edited by hand.

Generate or refresh it with Python 3.12, from the repository root:

```bash
python3.12 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
python -m pip install "pip-tools>=7.4"
pip-compile --extra=dev --generate-hashes --output-file=requirements/dev.lock pyproject.toml
python -m pip install --require-hashes -r requirements/dev.lock
python -m pip install --no-deps -e .
pip-audit --require-hashes -r requirements/dev.lock
```

Commit the regenerated `dev.lock` together with the `pyproject.toml` change
that caused it, and run the full test suite and `python scripts/dev.py lint`
after every update (Doc 14 §39).

Later-phase dependency groups (`graph`, `verification`, `llm`, `aws`) are not
locked here yet; each is re-verified and locked when its phase starts.
