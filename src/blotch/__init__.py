"""blotch - a local privacy gateway for documents.

A reversible pseudonymisation layer between sensitive information and an external
AI/service. Sensitive data and the token->original mapping never leave the local
trust boundary; only opaque, reversible tokens are transmitted.

Typical use::

    from blotch import sanitize, restore, get_policy

    result = sanitize(text, get_policy("personal"))
    # send result.sanitized_text to an external model, get a reply, then:
    final = restore(reply, result.vault)
"""

from __future__ import annotations

from .gateway import Gateway, GatewayResult, LeakBlocked, echo_provider
from .leakscan import LeakReport, scan
from .pipeline import SanitizeResult, preview, sanitize
from .policy import Action, Policy, get_policy
from .rehydrate import RestoreResult, restore, validate_response
from .reidrisk import ReidRisk, RiskLevel, assess as assess_reid_risk
from .spans import EntityType, Span
from .vault import Vault

__version__ = "0.1.0"

__all__ = [
    "sanitize", "restore", "preview", "scan", "validate_response",
    "get_policy", "Policy", "Action", "Vault", "EntityType", "Span",
    "SanitizeResult", "RestoreResult", "LeakReport",
    "Gateway", "GatewayResult", "LeakBlocked", "echo_provider",
    "ReidRisk", "RiskLevel", "assess_reid_risk", "__version__",
]
