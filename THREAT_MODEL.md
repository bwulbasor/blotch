# censorbot threat model

This document states what censorbot protects, against whom, and — just as
importantly — what it does **not** protect. A privacy tool that overstates its
guarantees is worse than none, because people rely on it.

## The core guarantee

> Sensitive information and the token→original mapping never leave the user's
> local trust boundary. Only opaque, reversible tokens are transmitted to an
> external service.

Everything else follows from, or qualifies, that sentence.

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Original document | Local disk / memory only | Never transmitted |
| Token→original mapping (vault) | Local disk / memory only | AES-256-GCM at rest (scrypt-derived key), session-scoped |
| Encryption passphrase / key | Provided by the user at runtime | Never stored by censorbot |
| Sanitised document | Sent to the external provider | Contains only tokens + non-sensitive text |

## Primary adversary: the external service

The model/API/service the sanitised document is sent to (ChatGPT, Claude, a
translation API, a company endpoint, …) is treated as **untrusted**.

- It only ever receives the pseudonymised text. It cannot see names, IDs, contact
  details, or any value that a detector caught.
- It cannot request the mapping — the mapping is never part of any request.
- Its **response is also untrusted**: rehydration resolves only tokens the vault
  issued; invented, dropped, or malformed tokens are flagged and never guessed
  (`rehydrate.py`).

Defence in depth before anything is sent: an independent **leak scanner**
(`leakscan.py`) re-checks the outbound text and *blocks* (not warns) if any
known original value or high-confidence identifier remains. Overriding the block
is an explicit, recorded action (`--force`).

## Secondary adversary: someone with the sanitised output

If the sanitised document leaks, it still should not identify anyone.

- Direct identifiers the detectors catch are gone.
- **Residual re-identification risk** from quasi-identifiers ("the 47-year-old CEO
  who survived the 2024 crash") is real and is surfaced as an **advisory**
  (`reidrisk.py`, `censorbot risk`) — it is **not** a guarantee of anonymity. True
  k-anonymity requires a population model censorbot does not have.

## The vault at rest

- Encrypted with AES-256-GCM; the key is derived from a user passphrase via scrypt
  (n=2¹⁵). A fresh random salt and nonce are used per write (no nonce reuse).
- Session-scoped by default so unrelated documents can't be correlated through a
  shared, permanent `PERSON_001 = …` mapping.
- censorbot refuses to write an unencrypted vault unless the user explicitly opts
  in (`--allow-plaintext`).
- **Out of scope:** an attacker with the passphrase, or with live memory access to
  the process while a vault is loaded. Vault security reduces to passphrase
  strength and host security.

## What censorbot does NOT protect against

- **Detection misses.** Detection is best-effort. The dependency-free heuristic
  NER is recall-first but not perfect; the leak scanner is a backstop, not a
  proof. Evaluate on your own documents (`evaluation/`) before relying on it.
- **Quasi-identifier re-identification** (see above) — advisory only.
- **A compromised host** — malware, a keylogger, or memory scraping on the user's
  own machine defeats any local tool.
- **The daemon on a public interface.** `censorbot serve` binds to 127.0.0.1 and
  returns the vault in its response; it must not be exposed off-loopback.
- **Side channels in the sanitised text** — document structure, writing style, or
  rare non-entity facts can still carry information.

## Trust boundary diagram

```
        ┌───────────────── local trust boundary ─────────────────┐
        │  original ─▶ detect ─▶ tokenise ─▶ leak-scan ──────────┐│
        │      ▲                     │                            ││
        │   vault (encrypted) ◀──────┘                    sanitised text
        │      │                                                  ││
        │   rehydrate ◀── validate response ◀───────────────────┐││
        └──────┼────────────────────────────────────────────────┼┘
               │                                                 ▼
               └───────────── final result          external service (untrusted)
```

Report security issues by opening an issue on the repository.
