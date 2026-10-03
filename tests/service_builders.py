"""Fixtures for tests that go through ``EvidenceService`` (P2-fix). Not a test module.

``ServiceCase`` is a ``RepoCase`` (schema-5 database, ``uow()``, ``count()``, ``tamper()``) with
trusted state v0 and two ANALYZING candidates c1 and c2 already stored, an ``EvidenceService`` and
a correlation context. ``put`` and ``put_for`` write evidence through the service, each in its own
unit of work.
"""

from __future__ import annotations

from typing import Any

from core.domain.evidence import EvidenceContext, EvidenceEvent, EvidenceKind
from evidence.ids import CorrelationContext
from evidence.service import EvidenceService
from tests.evidence_builders import prov
from tests.persistence_builders import SAFE, SAFE_OTHER, RepoCase

K = EvidenceKind


class ServiceCase(RepoCase):
    seed_bound = False
    hide_seeded_evidence = True

    def setUp(self) -> None:
        super().setUp()
        self.svc = EvidenceService()
        self.ctx = CorrelationContext.new()
        self.attempt_ctx = self.ctx.with_attempt()
        self.v0 = self.seed()
        self.c1 = self.store_stages(self.v0, SAFE, n=1, sequence=1, upto=3)[3]
        self.c2 = self.store_stages(self.v0, SAFE_OTHER, n=2, sequence=2, upto=3)[3]
        self.v0_ctx = EvidenceContext.state(self.v0.state_id)
        self.c1_ctx = EvidenceContext.candidate(self.c1.candidate_id)
        self.c2_ctx = EvidenceContext.candidate(self.c2.candidate_id)

    def put(self, payload: Any = None, **overrides: Any) -> EvidenceEvent:
        """VERIFICATION evidence about v0 (with its state hash), written through the service."""
        fields: dict[str, Any] = {
            "kind": K.VERIFICATION,
            "event_name": "verification_completed",
            "payload": {"result": "PASS"} if payload is None else payload,
            "ctx": self.ctx,
            "provenance": prov(),
            "state_id": self.v0.state_id,
            "state_hash": self.v0.state_hash,
        }
        fields.update(overrides)
        with self.uow() as u:
            return self.svc.record(u, **fields).record

    def put_for(self, candidate: Any, payload: Any = None, **overrides: Any) -> EvidenceEvent:
        """VERIFICATION evidence about a candidate: its attempt, parent and state hash (C-55)."""
        fields: dict[str, Any] = {
            "ctx": self.attempt_ctx,
            "state_id": None,
            "state_hash": candidate.state_hash,
            "candidate_id": candidate.candidate_id,
            "parent_state_id": candidate.parent_state_id,
        }
        fields.update(overrides)
        return self.put(payload, **fields)

    def impact_for(self, candidate: Any, payload: Any = None) -> EvidenceEvent:
        """IMPACT evidence for a candidate, the reference an invalidation for it must carry."""
        return self.put_for(
            candidate,
            {"affected": ["INV-SEC-001"]} if payload is None else payload,
            kind=K.IMPACT,
            event_name="impact_completed",
        )
