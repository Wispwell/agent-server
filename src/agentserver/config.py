"""Configuration. Read once, at startup.

What belongs here is *configuration*: the trust anchor, the capability
vocabulary, where the roots are, and the thresholds. What does not belong here
is anything authored — a subagent is a program, not a setting, and it lives in
its own artifact and is compiled into the database.

Rules this loader keeps, each of which has a failure it prevents:

  * **`safe_load`, never `load`.** The full loader constructs arbitrary Python
    objects, which turns a config file into a code-execution path.
  * **Unknown keys are an error.** A misspelled threshold silently taking its
    default is how a rate limit of 2 ships as 20, and thresholds are exactly
    where a silent default is worst.
  * **No partial configuration.** Anything malformed and the process refuses to
    start. A containment server that boots on defaults because a key was
    typo'd is worse than one that does not boot.
  * **Paths resolve relative to this file, not the working directory.**
    Otherwise starting the server from elsewhere silently changes which root
    agents are confined to — a containment bug that would present as a path
    bug.
  * **Read once, passed explicitly.** No global, no hot reload: the trust
    anchor is fixed for the life of the process, and components take their
    configuration in their constructors so tests can build one inline.

Secrets are never in the file. It names an environment variable; operator keys
in it are public halves. So it is meant to be committed and reviewed, which is
what you want of a trust anchor.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .containment.admission import AdmissionConfig
from .policy import Policy, PolicyError
from .supervisor.budgets import Budget

__all__ = ["Config", "ConfigError", "ProviderConfig", "find_config"]

ENV_VAR = "AGENT_SERVER_CONFIG"
DEFAULT_NAME = "config.yaml"

_TOP_LEVEL = {"operators", "capabilities", "roots", "servers", "admission",
              "budget", "provider", "storage"}
_PROVIDER = {"base_url", "api_key_env", "model", "max_output_tokens",
             "structured_output", "timeout", "referer", "title"}
_STORAGE = {"database", "ledger", "keys"}


class ConfigError(Exception):
    """The configuration is unusable. Never recoverable at runtime."""


def _reject_unknown(section: str, raw: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError(
            f"{section}: unknown keys {sorted(unknown)}; allowed {sorted(allowed)}"
        )


@dataclass(frozen=True)
class ProviderConfig:
    base_url: str = "https://openrouter.ai/api/v1"
    api_key_env: str = "OPENROUTER_API_KEY"
    model: str = ""
    max_output_tokens: int = 8000
    structured_output: bool = True
    timeout: int = 120
    referer: str = ""
    title: str = "agent-server"

    @property
    def api_key(self) -> str | None:
        """Read at use, not at load — the process may be started before the
        environment is populated, and a missing key should fail the call that
        needs it rather than the whole server."""
        return os.environ.get(self.api_key_env)

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> ProviderConfig:
        raw = dict(raw or {})
        _reject_unknown("provider", raw, _PROVIDER)
        return cls(**raw)


@dataclass(frozen=True)
class Config:
    policy: Policy
    admission: AdmissionConfig
    budget: Budget
    provider: ProviderConfig
    database: Path
    ledger: Path
    keys: Path
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    source: Path | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, base: Path | None = None) -> Config:
        if not isinstance(raw, dict):
            raise ConfigError("configuration must be a mapping")
        _reject_unknown("config", raw, _TOP_LEVEL)

        try:
            policy = Policy.from_dict(raw, base=base)
        except (PolicyError, ValueError) as exc:
            # narrow deliberately: a malformed trust root is a ConfigError, but
            # a bug in this module should still surface as the bug it is
            raise ConfigError(str(exc)) from None

        admission_raw = dict(raw.get("admission") or {})
        _reject_unknown("admission", admission_raw, set(AdmissionConfig.__dataclass_fields__))
        budget_raw = dict(raw.get("budget") or {})
        _reject_unknown("budget", budget_raw,
                        {f for f in Budget.__dataclass_fields__ if f.startswith("max_")})

        storage = dict(raw.get("storage") or {})
        _reject_unknown("storage", storage, _STORAGE)

        def path_for(key: str, default: str) -> Path:
            value = Path(str(storage.get(key, default))).expanduser()
            if not value.is_absolute() and base is not None:
                value = (base / value).resolve()
            return value

        return cls(
            policy=policy,
            admission=AdmissionConfig.from_dict(admission_raw),
            budget=Budget.from_dict(budget_raw),
            provider=ProviderConfig.from_dict(raw.get("provider")),
            database=path_for("database", "data/state.db"),
            ledger=path_for("ledger", "data/ledger.jsonl"),
            keys=path_for("keys", "data/keys"),
            servers={k: dict(v or {}) for k, v in (raw.get("servers") or {}).items()},
            source=base / DEFAULT_NAME if base else None,
            raw=raw,
        )

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> Config:
        resolved = Path(path) if path is not None else find_config()
        if resolved is None or not resolved.exists():
            raise ConfigError(
                f"no configuration found. Looked for --config, ${ENV_VAR}, "
                f"and ./{DEFAULT_NAME}"
            )
        try:
            raw = yaml.safe_load(resolved.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{resolved}: {exc}") from None
        config = cls.from_dict(raw, base=resolved.parent)
        return replace_source(config, resolved)


def replace_source(config: Config, source: Path) -> Config:
    return Config(
        policy=config.policy, admission=config.admission, budget=config.budget,
        provider=config.provider, database=config.database, ledger=config.ledger,
        keys=config.keys, servers=config.servers, source=source, raw=config.raw,
    )


def find_config() -> Path | None:
    """Environment, then the working directory. No search up the tree — an
    implicit parent config is how you end up confining agents to a root you did
    not mean to."""
    from_env = os.environ.get(ENV_VAR)
    if from_env:
        return Path(from_env).expanduser()
    candidate = Path.cwd() / DEFAULT_NAME
    return candidate if candidate.exists() else None
