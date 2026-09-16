"""Benchmark the engine on the metrics that matter for a privacy gateway (plan §16).

The primary target is **not** speed. For a privacy gateway a missed entity is a
leak; a false positive is only an annoyance. So we measure, over a labelled set:

* **recall**  - of the gold sensitive items, how many were removed from output.
* **leak_rate** - of the gold sensitive items, how many still appear verbatim
  (this is the number you actually care about; target 0).
* **round_trip_fidelity** - can every tokenised value be restored exactly.
* **scan_block_rate** - how often the outbound scanner would block.

Fixtures are ``(text, must_remove)`` pairs where ``must_remove`` is the set of
substrings that MUST NOT survive into the sanitised output.
"""

from __future__ import annotations

from dataclasses import dataclass

from .pipeline import sanitize
from .policy import Policy, get_policy
from .rehydrate import restore

# (text, must_remove) - substrings that must not survive sanitisation.
FIXTURES: list[tuple[str, list[str]]] = [
    (
        "Alejandro Martinez was admitted to Vienna General Hospital on 14 March "
        "2026. His patient number is 48392017.",
        ["Alejandro Martinez", "48392017"],
    ),
    (
        "Contact Maria Gomez at maria.gomez@example.com or +43 660 1234567.",
        ["Maria Gomez", "maria.gomez@example.com", "+43 660 1234567"],
    ),
    (
        "Transfer to IBAN GB82 WEST 1234 5698 7654 32, card 4111 1111 1111 1111.",
        ["GB82 WEST 1234 5698 7654 32", "4111 1111 1111 1111"],
    ),
    (
        "Case AZ 17 C 391/26: the defendant, Mr. Thomas Weber, resides in Graz.",
        ["Thomas Weber"],
    ),
    (
        "Server 192.168.10.5 logged user john.doe@corp.example on 2026-01-09.",
        ["192.168.10.5", "john.doe@corp.example"],
    ),
]


@dataclass
class BenchmarkResult:
    n: int
    total_gold: int
    caught: int
    leaked: int
    round_trip_ok: int
    scan_blocked: int
    leaked_items: list[str]

    @property
    def recall(self) -> float:
        return self.caught / self.total_gold if self.total_gold else 1.0

    @property
    def leak_rate(self) -> float:
        return self.leaked / self.total_gold if self.total_gold else 0.0

    @property
    def round_trip_fidelity(self) -> float:
        return self.round_trip_ok / self.n if self.n else 1.0

    def report(self) -> str:
        return (
            f"fixtures={self.n}  gold_items={self.total_gold}\n"
            f"recall               {self.recall:6.1%}  ({self.caught}/{self.total_gold})\n"
            f"leak_rate            {self.leak_rate:6.1%}  ({self.leaked}/{self.total_gold})"
            + (f"  LEAKED: {self.leaked_items}" if self.leaked_items else "") + "\n"
            f"round_trip_fidelity  {self.round_trip_fidelity:6.1%}  "
            f"({self.round_trip_ok}/{self.n})\n"
            f"scan_block_rate      {self.scan_blocked}/{self.n}"
        )


def run_benchmark(policy: Policy | None = None, *, use_spacy: bool = False,
                  fixtures: list[tuple[str, list[str]]] | None = None) -> BenchmarkResult:
    policy = policy or get_policy("maximum")
    fixtures = fixtures or FIXTURES
    total_gold = caught = leaked = round_trip_ok = scan_blocked = 0
    leaked_items: list[str] = []

    for text, must_remove in fixtures:
        result = sanitize(text, policy, use_spacy=use_spacy)
        out = result.sanitized_text
        for item in must_remove:
            total_gold += 1
            if item in out:
                leaked += 1
                leaked_items.append(item)
            else:
                caught += 1
        # round trip: restoring the sanitised text must reproduce the original
        if restore(out, result.vault).text == text:
            round_trip_ok += 1
        if result.leak_report and result.leak_report.blocked:
            scan_blocked += 1

    return BenchmarkResult(
        n=len(fixtures), total_gold=total_gold, caught=caught, leaked=leaked,
        round_trip_ok=round_trip_ok, scan_blocked=scan_blocked,
        leaked_items=leaked_items,
    )
