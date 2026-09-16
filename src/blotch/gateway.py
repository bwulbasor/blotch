"""The privacy gateway: make the external service completely replaceable (plan §12).

A :class:`Gateway` wraps the whole round trip -

    sanitize -> leak-scan -> provider(sanitized) -> restore + response-check

around a *provider*: any callable ``str -> str``. The gateway neither knows nor
cares whether the provider is ChatGPT, Claude, a local model, a translation API,
or a test echo. Sensitive data and the vault never reach the provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .leakscan import LeakReport
from .pipeline import sanitize
from .policy import Policy
from .rehydrate import RestoreResult, restore
from .vault import Vault

#: A provider is anything that maps sanitised text to a response.
Provider = Callable[[str], str]


class LeakBlocked(RuntimeError):
    """Raised when the outbound leak scan blocks and the caller didn't override."""

    def __init__(self, report: LeakReport) -> None:
        super().__init__(report.summary())
        self.report = report


@dataclass
class GatewayResult:
    original: str
    sanitized: str
    response: str
    restored: str
    vault: Vault
    leak_report: LeakReport
    restore_result: RestoreResult

    @property
    def response_had_anomalies(self) -> bool:
        return self.restore_result.has_anomalies


def echo_provider(text: str) -> str:
    """A provider that returns the sanitised text unchanged.

    Useful for tests and for validating round-trip fidelity end-to-end without a
    real model in the loop.
    """

    return text


class Gateway:
    def __init__(self, policy: Policy, provider: Provider = echo_provider, *,
                 use_ner: bool = True, use_spacy: bool = True) -> None:
        self.policy = policy
        self.provider = provider
        self.use_ner = use_ner
        self.use_spacy = use_spacy

    def run(self, text: str, *, block_on_leak: bool = True) -> GatewayResult:
        result = sanitize(text, self.policy, use_ner=self.use_ner,
                          use_spacy=self.use_spacy, run_leak_scan=True)
        report = result.leak_report
        assert report is not None
        if block_on_leak and report.blocked:
            raise LeakBlocked(report)

        response = self.provider(result.sanitized_text)
        restored = restore(response, result.vault)
        return GatewayResult(
            original=text,
            sanitized=result.sanitized_text,
            response=response,
            restored=restored.text,
            vault=result.vault,
            leak_report=report,
            restore_result=restored,
        )
