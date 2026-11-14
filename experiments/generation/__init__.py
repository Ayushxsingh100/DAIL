"""LLM candidates for the experiment (P10a; C-218 to C-221).

``task`` (what generation is given: S0 only, the fixed task, the scope of decision 5), ``models``
(pins, digest check, budget), ``parent`` (S0 through the baseline flow, configuration only),
``run`` (generate and freeze), ``replay`` (rebuild, check, evaluate under A, B, C and C'),
``export`` (configuration-only candidates for the oracle). No module here reads a label, a
description, an intent or a later step (``tests/contract/test_experiment_blinding.py``).
"""
