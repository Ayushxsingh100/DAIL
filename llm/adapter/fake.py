"""The fake provider: scripted replies and failures, no network (Doc 01 FR-LLM-006; C-71, C-182).

``FakeProvider(script)`` answers each call with the next item of ``script``: a ``ProviderReply`` is
returned, a ``ProviderError`` is raised. Every call is kept in ``calls`` so a test can read the
prompt that would have been sent. Running out of script is a test error (``RuntimeError``), never a
reply. CI and the default test run use this provider only.
"""

from __future__ import annotations

from collections.abc import Iterable

from llm.adapter.provider import ProviderCall, ProviderError, ProviderReply


class FakeProvider:
    name = "fake"

    def __init__(self, script: Iterable[ProviderReply | ProviderError]) -> None:
        self._script = list(script)
        self.calls: list[ProviderCall] = []

    def generate(self, call: ProviderCall) -> ProviderReply:
        self.calls.append(call)
        if not self._script:
            raise RuntimeError("FakeProvider: the script is exhausted")
        item = self._script.pop(0)
        if isinstance(item, ProviderError):
            raise item
        return item
