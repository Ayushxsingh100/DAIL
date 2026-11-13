"""Scoring (P8b): the only part of the repository that reads TerraPreserve label fields.

``labels`` reads the dev labels (oracle truth per step, the oracle's affected invariants, the
mutation records, the scenario class) from the frozen TerraPreserve files, with the same hash checks
as ``experiments.loader``; ``truth`` turns them into the truth of one transition (metrics-draft-1);
``identity`` holds the identity truth table of C-213. Trial execution never imports this package
(``tests/contract/test_experiment_blinding.py``, check (b)), and no module outside it names a label
field (check (a)). The test split is refused.
"""
