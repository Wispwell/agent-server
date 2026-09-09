"""OpenRouter client, via the OpenAI SDK. M3.

OpenRouter is OpenAI-compatible and ships no SDK of its own, so this wraps the
OpenAI client pointed at OpenRouter's base URL.

The model is a `vendor/model` slug from configuration, never hardcoded.
Swapping it must not require a code change — and because it is configuration,
the evaluations can sweep it, which turns "does containment hold with a weaker
or stronger planner" into a config loop rather than a rewrite.

**Structured output is best-effort.** Support varies by model *and* by the
provider OpenRouter routes to, so non-conforming output is a normal case rather
than an exceptional one.

**Model output is never repaired to make it parse.** No stripping of code
fences, no extracting the first {...}, no retrying with "please return valid
JSON". Silently fixing it up is how an injected instruction gets laundered into
a valid-looking action: the text that failed to parse is the text an attacker
influenced, and coaxing it into shape is doing the attacker's work. A malformed
response returns `parsed=None` and the caller refuses it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Completion", "OpenRouterClient", "ProviderError"]


class ProviderError(Exception):
    reason = "provider_error"


@dataclass
class Completion:
    text: str
    parsed: dict[str, Any] | None = None
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    #: Set when a schema was requested and the response did not conform. The
    #: raw text is kept for the ledger; it is never repaired.
    malformed: str = ""

    @property
    def ok(self) -> bool:
        return self.parsed is not None if self.malformed or self.parsed else bool(self.text)


class OpenRouterClient:
    def __init__(self, config, *, client=None):
        self.config = config
        self._client = client

    def _ensure(self):
        if self._client is not None:
            return self._client
        key = self.config.api_key
        if not key:
            raise ProviderError(
                f"no API key: set ${self.config.api_key_env}. The model is not "
                f"reachable, so nothing can be planned."
            )
        from openai import OpenAI

        self._client = OpenAI(base_url=self.config.base_url, api_key=key,
                              timeout=self.config.timeout)
        return self._client

    def complete(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        schema: Mapping[str, Any] | None = None,
        model: str | None = None,
    ) -> Completion:
        """One completion. Raises only on transport failure; a model that
        answers badly is a value, because the caller has to handle that case
        anyway and raising would tempt it into a retry loop."""
        target = model or self.config.model
        if not target:
            raise ProviderError("no model configured; set provider.model in config.yaml")

        kwargs: dict[str, Any] = {
            "model": target,
            "messages": list(messages),
            "max_tokens": self.config.max_output_tokens,
        }
        headers = {}
        if self.config.referer:
            headers["HTTP-Referer"] = self.config.referer
        if self.config.title:
            headers["X-Title"] = self.config.title
        if headers:
            kwargs["extra_headers"] = headers

        if schema is not None and self.config.structured_output:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "turn", "strict": True, "schema": dict(schema)},
            }

        try:
            response = self._ensure().chat.completions.create(**kwargs)
        except ProviderError:
            raise
        except Exception as exc:  # noqa: BLE001 — SDK raises a wide family
            raise ProviderError(f"{type(exc).__name__}: {exc}") from None

        choice = response.choices[0] if response.choices else None
        text = (getattr(choice.message, "content", "") if choice else "") or ""
        usage = {}
        if getattr(response, "usage", None):
            usage = {
                "prompt": response.usage.prompt_tokens or 0,
                "completion": response.usage.completion_tokens or 0,
            }

        if schema is None:
            return Completion(text=text, model=getattr(response, "model", target), usage=usage)

        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return Completion(text=text, parsed=None, malformed="not JSON",
                              model=getattr(response, "model", target), usage=usage)
        if not isinstance(parsed, dict):
            return Completion(text=text, parsed=None, malformed="not an object",
                              model=getattr(response, "model", target), usage=usage)
        return Completion(text=text, parsed=parsed,
                          model=getattr(response, "model", target), usage=usage)
