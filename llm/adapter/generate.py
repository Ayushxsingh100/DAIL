"""``Generator.generate``: one repair generation, with its retries (Doc 10 §17-§18, §20-§24,
§31-§34; Doc 14 §37; ADR-006).

§31, as built in P7a: validate config; estimate budget; build versioned prompt; record request
metadata; call provider; record raw response safely; parse structured response; return the
normalized result. "Validate patch" is limited to the parser checks of §22 here; the full §13
pipeline, and turning a patch into a Candidate State, are P7b.

* **Emergency switch (Doc 14 §37).** ``generation_enabled`` is the reviewed
  ``llm.generation_enabled`` value. Off, ``generate`` returns DISABLED: no budget, no prompt,
  no provider call, no record.
* **Config (§16).** The provider name, the prompt version and the response schema version must
  match what is built here; otherwise ``ValueError`` before anything else.
* **Budget (§18).** If priorities 1-2 cannot fit, the result is CONTEXT_INSUFFICIENT and no provider
  is called. The deterministic context would not change on a retry (``prompt_adjustment_policy`` is
  ``none``), so CONTEXT_INSUFFICIENT is not retried even when the policy lists it.
* **Retries (§23).** Up to ``max_attempts``; another attempt only for a failure class in the
  policy's ``retry_on``. Every attempt has its own request and response record; the parent state,
  the context, the prompt and the constraints are the same object for every attempt.
* **Records (§20, §21, §32-§34).** The request holds hashes and the full configuration, not the
  prompt text. The raw reply is stored redacted; ``response_hash`` is the SHA-256 of the reply text
  as received; a PATCH carries its ``patch_hash``. An optional ``StructuredLogger`` gets one event
  per request and per response with hashes and classes only.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

from core.domain.hashing import sha256_text
from core.domain.ids import new_uuid
from core.domain.redaction import Redactor
from evidence.ids import CorrelationContext
from evidence.models import LogLevel
from evidence.structured_log import StructuredLogger
from llm.adapter.budget import BudgetOutcome, apply_budget
from llm.adapter.context import LLMContext
from llm.adapter.provider import LLMProvider, ProviderCall, ProviderError, ProviderReply
from llm.prompts.templates import PROMPT_VERSION, Prompt, render
from llm.schemas.records import (
    Attempt,
    BudgetConfig,
    FailureClass,
    GenerationResult,
    GenerationStatus,
    LLMConfig,
    LLMRequest,
    LLMResponse,
    RetryPolicy,
)
from llm.schemas.repair_response import RESPONSE_JSON_SCHEMA, RESPONSE_SCHEMA_VERSION
from llm.validation.parser import PARSER_VERSION, parse_response
from llm.validation.patch import VALIDATOR_VERSION as PATCH_VALIDATOR_VERSION
from llm.validation.patch import PatchValidator

# Without a patch validator only the parser checks (§22) run, as in P7a.
VALIDATOR_VERSION = PARSER_VERSION
_COMPONENT = "llm.generate"


class Generator:
    def __init__(
        self,
        *,
        provider: LLMProvider,
        config: LLMConfig,
        retry_policy: RetryPolicy,
        budget: BudgetConfig,
        generation_enabled: bool,
        clock: Callable[[], datetime],
        ids: Callable[[], str] = new_uuid,
        sleep: Callable[[float], None] = time.sleep,
        logger: StructuredLogger | None = None,
        ctx: CorrelationContext | None = None,
        validator: PatchValidator | None = None,
    ) -> None:
        if not isinstance(generation_enabled, bool):
            raise ValueError("generation_enabled must be the boolean llm.generation_enabled")
        if (logger is None) != (ctx is None):
            raise ValueError("a logger needs a correlation context and the other way round")
        self.provider = provider
        self.config = config
        self.retry_policy = retry_policy
        self.budget = budget
        self.generation_enabled = generation_enabled
        self.clock = clock
        self.ids = ids
        self.sleep = sleep
        self.logger = logger
        self.ctx = ctx
        self.validator = validator
        self._redactor = Redactor()
        self._builds: dict[str, object] = {}

    # --- §31 ------------------------------------------------------------------------------------

    def _validate_config(self) -> None:
        problems = []
        if self.config.provider != self.provider.name:
            problems.append(f"provider {self.config.provider!r} is not {self.provider.name!r}")
        if self.config.prompt_version != PROMPT_VERSION:
            problems.append(
                f"prompt_version {self.config.prompt_version!r} is not {PROMPT_VERSION}"
            )
        if self.config.response_schema_version != RESPONSE_SCHEMA_VERSION:
            problems.append("response_schema_version is not " + RESPONSE_SCHEMA_VERSION)
        if self.config.retry_policy_id != self.retry_policy.policy_id:
            problems.append("retry_policy_id does not name the retry policy in use")
        if problems:
            raise ValueError("LLM configuration refused: " + "; ".join(problems))

    def generate(self, context: LLMContext) -> GenerationResult:
        if not self.generation_enabled:
            return self._result(GenerationStatus.DISABLED, None, (), context, None, None, ())
        self._validate_config()
        if self.validator is not None:
            self.validator.check_context(context)
        budget = apply_budget(context, self.budget)
        if budget.insufficient:
            return self._result(
                GenerationStatus.CONTEXT_INSUFFICIENT,
                FailureClass.CONTEXT_INSUFFICIENT,
                (),
                budget.context,
                None,
                budget,
                (),
                detail="priorities 1-2 do not fit the budget (§18)",
            )
        prompt = render(budget.context)
        attempts: list[Attempt] = []
        failure: FailureClass | None = None
        patch: str | None = None
        for number in range(1, self.retry_policy.max_attempts + 1):
            if number > 1 and self.retry_policy.backoff_seconds:
                self.sleep(self.retry_policy.backoff_seconds)
            attempt = self._attempt(number, budget.context, prompt)
            attempts.append(attempt)
            failure = attempt.response.failure_class
            if failure is None:
                patch = attempt.response.extracted_patch
                break
            if failure not in self.retry_policy.retry_on or failure is (
                FailureClass.CONTEXT_INSUFFICIENT
            ):
                break
        status = GenerationStatus.PATCH if failure is None else GenerationStatus.FAILED
        build = None
        if failure is None and attempts and attempts[-1].response.patch_id is not None:
            build = self._builds.get(attempts[-1].response.response_id)
        return self._result(
            status,
            failure,
            tuple(attempts),
            budget.context,
            prompt,
            budget,
            (),
            patch=patch,
            build=build,
        )

    # --- one attempt ----------------------------------------------------------------------------

    def _attempt(self, number: int, context: LLMContext, prompt: Prompt) -> Attempt:
        request = LLMRequest(
            request_id=self.ids(),
            attempt_id=self.ids(),
            attempt_number=number,
            parent_state_id=context.parent_state_id,
            trusted_state_hash=context.trusted_state_hash,
            context_version=context.context_version,
            context_hash=context.context_hash,
            prompt_hash=prompt.prompt_hash,
            prompt_version=prompt.prompt_version,
            template_hash=prompt.template_hash,
            model_config=self.config.to_dict(),
            created_at=self.clock(),
        )
        self._log("llm.request", "STARTED", request.request_id, {"attempt": number})
        call = ProviderCall(
            request=request,
            system=prompt.system,
            task=prompt.task,
            response_schema=RESPONSE_JSON_SCHEMA,
            config=self.config,
        )
        try:
            reply: ProviderReply | None = self.provider.generate(call)
            error: ProviderError | None = None
        except ProviderError as raised:
            reply, error = None, raised
        except Exception as raised:  # noqa: BLE001 - a provider bug is a failure, never a reply
            reply, error = None, ProviderError(FailureClass.TRANSIENT_ERROR, type(raised).__name__)
        response = self._response(request, reply, error)
        self._log(
            "llm.response",
            "FAILED" if response.failure_class else "SUCCEEDED",
            request.request_id,
            {
                "attempt": number,
                "failure_class": response.to_dict()["failure_class"],
                "response_hash": response.response_hash,
                "parsed_status": response.parsed_status,
            },
        )
        return Attempt(request, response)

    def _response(
        self,
        request: LLMRequest,
        reply: ProviderReply | None,
        error: ProviderError | None,
    ) -> LLMResponse:
        if reply is None:
            assert error is not None
            return LLMResponse(
                response_id=self.ids(),
                request_id=request.request_id,
                raw_response=None,
                parsed_status=None,
                extracted_patch=None,
                response_hash=None,
                patch_hash=None,
                parse_errors=(self._redactor.redact(str(error)).payload,),
                failure_class=error.failure_class,
                latency_ms=None,
                token_usage={},
                parser_version=PARSER_VERSION,
                created_at=self.clock(),
            )
        outcome = parse_response(reply.text)
        parsed = outcome.response
        failure = outcome.failure_class
        patch = None
        validation = None
        response_id = self.ids()
        if parsed is not None and failure is None and self.validator is not None:
            validation = self.validator.validate(
                parsed, request_id=request.request_id, patch_id=self.ids()
            )
            failure = validation.failure_class
            if validation.build is not None:
                self._builds[response_id] = validation.build
        if parsed is not None and failure is None:
            patch = self._redactor.redact(parsed.patch).payload
        return LLMResponse(
            response_id=response_id,
            request_id=request.request_id,
            raw_response=self._redactor.redact(reply.text).payload,
            parsed_status=None if parsed is None else parsed.status.value,
            extracted_patch=patch,
            response_hash=sha256_text(reply.text),
            patch_hash=None if patch is None else sha256_text(patch),
            parse_errors=tuple(self._redactor.redact(list(outcome.errors)).payload),
            failure_class=failure,
            latency_ms=reply.latency_ms,
            token_usage=dict(reply.token_usage),
            parser_version=outcome.parser_version,
            created_at=self.clock(),
            confidence=None if parsed is None else parsed.confidence,
            validator_version=None if validation is None else validation.validator_version,
            validation_errors=(
                ()
                if validation is None
                else tuple(self._redactor.redact(list(validation.errors)).payload)
            ),
            patch_id=(
                None if validation is None or validation.build is None else validation.patch_id
            ),
            candidate_tree_hash=(
                None
                if validation is None or validation.build is None
                else validation.build.tree_hash
            ),
        )

    # --- results and logs -----------------------------------------------------------------------

    def _result(
        self,
        status: GenerationStatus,
        failure: FailureClass | None,
        attempts: tuple[Attempt, ...],
        context: LLMContext,
        prompt: Prompt | None,
        budget: BudgetOutcome | None,
        omitted: tuple[str, ...],
        *,
        patch: str | None = None,
        detail: str = "",
        build: object = None,
    ) -> GenerationResult:
        return GenerationResult(
            status=status,
            failure_class=failure,
            patch=patch,
            attempts=attempts,
            config=self.config,
            context_version=context.context_version,
            context_hash=context.context_hash,
            prompt_version=PROMPT_VERSION,
            prompt_hash=None if prompt is None else prompt.prompt_hash,
            budget={} if budget is None else budget.to_dict(),
            omitted=omitted if budget is None else budget.omitted,
            parser_version=PARSER_VERSION,
            validator_version=(
                VALIDATOR_VERSION if self.validator is None else PATCH_VALIDATOR_VERSION
            ),
            detail=detail,
            build=build,
        )

    def _log(self, event: str, status: str, request_id: str, metadata: dict[str, object]) -> None:
        if self.logger is None or self.ctx is None:
            return
        self.logger.log(
            LogLevel.INFO,
            component=_COMPONENT,
            event_name=event,
            ctx=self.ctx,
            status=status,
            metadata={
                "request_id": request_id,
                "provider": self.config.provider,
                "model_name": self.config.model_name,
                **metadata,
            },
        )
