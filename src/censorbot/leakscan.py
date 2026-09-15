"""The outbound privacy firewall (plan §9).

An independent second pass over text that is about to leave the device. It is a
*blocking* control, not a warning: if high-confidence sensitive material remains,
the caller must not transmit. Every block is inspectable and can be overridden by
the caller with an explicit, audited decision (plan §4) - a block is never a dead
end, but it is never silent either.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .detectors import deterministic
from .spans import Span
from .tokens import TOKEN_RE
from .vault import Vault

# Detector confidence at or above which a *remaining* entity blocks transmission.
BLOCK_THRESHOLD = 0.85


@dataclass
class LeakReport:
    clean: bool
    residual_spans: list[Span] = field(default_factory=list)
    leaked_values: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return not self.clean

    def summary(self) -> str:
        if self.clean:
            return "clean: no residual sensitive material detected"
        parts = []
        if self.leaked_values:
            parts.append(f"{len(self.leaked_values)} known original value(s) still present")
        if self.residual_spans:
            parts.append(f"{len(self.residual_spans)} high-confidence entity/entities remain")
        return "BLOCKED: " + "; ".join(parts)


def _isword(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _present_as_token(value: str, text: str) -> bool:
    """Whole-word, case-sensitive: does ``value`` still appear as its own token?

    Uses C-level ``str.find`` (fast, no per-value regex) then verifies word
    boundaries only on word-char edges - so emails/IBANs wrapped in punctuation
    match, but "Count" inside "Country" or "EU" inside "Europe" does not (which
    would otherwise make the scanner block almost every real document).
    """

    vlead = _isword(value[:1])
    vtrail = _isword(value[-1:])
    start = 0
    n = len(text)
    while True:
        i = text.find(value, start)
        if i < 0:
            return False
        j = i + len(value)
        left_ok = (not vlead) or i == 0 or not _isword(text[i - 1])
        right_ok = (not vtrail) or j >= n or not _isword(text[j])
        if left_ok and right_ok:
            return True
        start = i + 1


def scan(sanitized_text: str, vault: Vault | None = None,
         threshold: float = BLOCK_THRESHOLD) -> LeakReport:
    """Scan text destined for an external service. Returns a :class:`LeakReport`.

    Two checks:

    1. **Known-value check** - no original value from the vault may appear as a
       substring (defends against a detector that tokenised one occurrence but
       missed another).
    2. **Fresh-detection check** - re-run deterministic detectors; any residual
       high-confidence span (that is not itself a token) blocks.
    """

    leaked_values: list[str] = []
    if vault is not None:
        # A single character is never a meaningful leak signal (initials, stray
        # letters) and would fire everywhere. Search all values in combined,
        # chunked alternation passes rather than one full-text scan per value
        # (which was O(values x text) - slow on large documents).
        for value in {v for v in vault.values() if len(v) >= 2}:
            if _present_as_token(value, sanitized_text):
                leaked_values.append(value)

    residual: list[Span] = []
    token_spans = [(m.start(), m.end()) for m in TOKEN_RE.finditer(sanitized_text)]
    for span in deterministic.detect(sanitized_text):
        if span.confidence < threshold:
            continue
        if any(ts <= span.start and span.end <= te for ts, te in token_spans):
            continue  # inside a token, not a leak
        residual.append(span)

    clean = not leaked_values and not residual
    return LeakReport(clean=clean, residual_spans=residual, leaked_values=leaked_values)
