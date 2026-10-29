"""Promotion: the only component allowed to advance Trusted State.

Owning spec sections: Doc 09 §17-41 (conflicting evidence, preconditions,
decision matrix, commit transaction, carry-forward, idempotency, concurrency).
Built in: P6a (policy, decide(), decision completeness, applying a decision to the
candidate) and P6b (commit transaction, carry-forward, concurrency).

P6a is the decision half: ``decide`` is a pure function of its arguments that returns PROMOTE,
REJECT, RETRY or ESCALATE with every blocking reason; ``lifecycle.candidate_after`` applies the
decision to the candidate; ``policy`` builds the DAIL and Stateful-Full policies. Nothing here
commits anything or calls ``TrustedState.promote`` (P6b does).

Import restrictions (tests/contract/test_architecture_boundaries.py): standard library and
``core.domain.*`` only (R18, C-157). In particular it never imports ``core.verification``: it
consumes the reports as domain objects, and it never runs or repairs verification (Doc 02 §15).
"""
