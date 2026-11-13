"""The experiment harness (P8a; Doc 13; C-196 to C-207).

It runs TerraPreserve target scenarios through DAIL under the four conditions of C-198 (A Stateless,
B Stateful Full, C DAIL, C' DAIL without identity evidence) and stores what happened. It never
bypasses the deterministic verification and promotion path (Doc 13 "Safety principle"): every
transition is one ``EvaluationOrchestrator.evaluate`` call, and only the Promotion Controller moves
a trial's Trusted State.

Modules: ``loader`` (TerraPreserve read-only, hashes verified, execution fields only),
``definition`` (Experiment, Trial, conditions, lifecycle), ``conditions`` (what each condition
passes to DAIL), ``trial`` (one attempt of one trial), ``records`` (what is stored per transition),
``artifacts`` (write-once files), ``runner`` (plan, run, resume), ``__main__`` (the command line).

Blinding: trial execution never reads oracle labels; ``tests/contract/test_experiment_blinding.py``
parses every module here. Scoring against labels, metrics and reports are P8b. The test split is
never read before P10 (the loader refuses it).

Not part of ``core``: nothing in ``core`` or ``evidence`` imports this package (rule R3).
"""
