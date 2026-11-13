"""Model pins for candidate generation (P10a Section 3.3 "Model configuration"; C-182, C-218).

"Model configuration: pinned per model by tag and digest, ``temperature``, ``seed``, ``top_p``,
``max_output_tokens``, ``timeout``, and ``num_ctx`` if the model needs it. The run refuses a model
whose installed digest is not the pinned one."

A ``ModelPin`` also records what the pilot reports of the model (quantization, size, licence and
where the licence was checked). Pins live in the reviewed file ``experiments/config/models.toml``;
``load_pins`` reads it (standard library ``tomllib``). ``check_installed`` compares the local
server's facts with the pin before any generation; ``OllamaProvider(expected_digest=...)`` checks
the digest again before its first call (C-182).

The generation settings that are not per model are fixed here, for every model: the retry policy
(``RETRY_POLICY``: two attempts, another one only after TRANSIENT_ERROR or INVALID_OUTPUT; with
temperature 0 and a fixed seed a NO_SOLUTION would come back unchanged) and the budget (the model's
context window ``num_ctx`` with ``max_output_tokens`` reserved for the reply and a safety margin, so
an oversized prompt is CONTEXT_INSUFFICIENT before any call instead of being cut by the server).
The seed of repetition ``k`` is ``seed + k - 1`` (``seed_for``), so repetitions differ only by seed.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

from llm.prompts.templates import PROMPT_VERSION
from llm.schemas.records import BudgetConfig, FailureClass, LLMConfig, RetryPolicy
from llm.schemas.repair_response import RESPONSE_SCHEMA_VERSION

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
MODELS_FILE: Final = REPO_ROOT / "experiments" / "config" / "models.toml"
RETRY_POLICY: Final = RetryPolicy(
    policy_id="p10a-retry-2",
    max_attempts=2,
    retry_on=(FailureClass.TRANSIENT_ERROR, FailureClass.INVALID_OUTPUT),
    backoff_seconds=0.0,
    prompt_adjustment_policy="none",
)
SAFETY_MARGIN: Final = 256


class ModelRefused(Exception):
    """The installed model is not the pinned one (or is not installed): nothing was generated."""


@dataclass(frozen=True)
class ModelPin:
    key: str  # a file-system-safe name for the records
    tag: str
    digest: str
    quantization: str
    size: str
    licence: str
    licence_source: str
    temperature: float
    top_p: float
    seed: int
    max_output_tokens: int
    timeout_seconds: float
    num_ctx: int | None = None

    def __post_init__(self) -> None:
        if not self.key or any(c in self.key for c in '\\/:*?"<>| '):
            raise ValueError(f"model key {self.key!r} must be a plain file name")
        if len(self.digest) != 64 or any(c not in "0123456789abcdef" for c in self.digest):
            raise ValueError(f"{self.key}: the digest must be 64 lowercase hex characters")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def seed_for(pin: ModelPin, k: int) -> int:
    return pin.seed + k - 1


def llm_config(pin: ModelPin, provider_name: str, k: int = 1) -> LLMConfig:
    return LLMConfig(
        provider=provider_name,
        model_name=pin.tag,
        model_version=pin.digest,
        temperature=pin.temperature,
        top_p=pin.top_p,
        seed=seed_for(pin, k),
        max_output_tokens=pin.max_output_tokens,
        timeout_seconds=pin.timeout_seconds,
        retry_policy_id=RETRY_POLICY.policy_id,
        prompt_version=PROMPT_VERSION,
        response_schema_version=RESPONSE_SCHEMA_VERSION,
        num_ctx=pin.num_ctx,
    )


def budget_for(pin: ModelPin) -> BudgetConfig:
    if pin.num_ctx is None:
        # the budget must know the window the server will use; DAIL does not assume a default
        raise ValueError(f"{pin.key}: an experiment pin sets num_ctx")
    return BudgetConfig(
        max_context_tokens=pin.num_ctx,
        reserved_output_tokens=pin.max_output_tokens,
        safety_margin=SAFETY_MARGIN,
    )


def check_installed(pin: ModelPin, facts: Mapping[str, Any]) -> None:
    """Refuse unless the local server's model is the pinned tag and digest."""
    if facts.get("name") != pin.tag:
        raise ModelRefused(f"{pin.tag} is not installed (the server named {facts.get('name')!r})")
    if facts.get("digest") != pin.digest:
        raise ModelRefused(
            f"{pin.tag}: the installed digest {facts.get('digest')} is not the pinned "
            f"{pin.digest} (C-182)"
        )


def load_pins(path: Path = MODELS_FILE) -> dict[str, ModelPin]:
    """The pins of the reviewed file, by key."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    pins: dict[str, ModelPin] = {}
    for key, values in (data.get("model") or {}).items():
        pins[key] = ModelPin(key=key, **values)
    return pins
