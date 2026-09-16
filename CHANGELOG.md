# Changelog

All notable changes to this project are documented here. The format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **Core pipeline**: local detection → conservative entity resolution →
  reversible opaque tokenisation (`[[TYPE_NNN]]`) → outbound leak scan.
- **Detectors**: deterministic layer (email, URL, IP, phone, dates, SSN, plus
  checksum-validated IBAN mod-97 and card Luhn) and an NER layer (spaCy when
  installed, else a high-recall heuristic fallback).
- **Encrypted token vault** at rest (AES-256-GCM + scrypt), session-scoped.
- **Rehydration** that resolves only vault-issued tokens and flags invented /
  dropped / malformed tokens in an untrusted response.
- **Provider-agnostic `Gateway`** and dependency-free provider adapters
  (`HttpProvider`, `openai_chat_provider`).
- **Local HTTP daemon** (`blotch serve`, loopback-only, stdlib only).
- **Regenerated document output** (TXT/DOCX/PDF) verified on read-back —
  regenerate-don't-edit, so no un-sanitised layer can survive.
- **Visual review preview** (`blotch review` → standalone HTML).
- **Re-identification-risk advisory** (`blotch risk`) for residual
  quasi-identifiers.
- **Custom policies** via `--policy-file` / `policy_from_dict`.
- **Benchmark harness** (`blotch benchmark`) and CI gating on leak rate.

### spaCy NER + a guaranteed no-leak sweep
- spaCy NER is now **unioned** with the heuristic (not substituted): the
  heuristic stays a recall safety net for common-word / non-Latin names spaCy
  misses, while spaCy adds correctly-typed ORG/LOCATION and natural-context names
  (~760 extra real-name catches on the eval corpus). CI runs a spaCy job.
- Fixed a latent **non-deterministic leak**: hash-randomised set iteration made
  propagation order vary, so a shared surface (e.g. a surname spaCy types as ORG
  in one place and PERSON in another) could leak at a sentence start in some runs.
  Sanitisation is now deterministic, and a **guaranteed final sweep** removes any
  residual whole-word vault value — "no known value leaks" is now a guarantee,
  not best-effort. Verified leak-clean across hash seeds and the whole corpus
  under both the heuristic and the spaCy union.

### Evaluation & hardening
- Added an `evaluation/` subsystem: a synthetic labelled-document generator with
  a hard-case bank, a ground-truth evaluator (precision / coverage-recall /
  type-accuracy), a public-source corpus fetcher (gitignored), and a wild runner.
- Real-document testing (public-domain literature, public-figure Wikipedia)
  surfaced and fixed: court case-number detection; Unicode/non-Latin uppercase
  name detection (`str.isupper()` instead of an ASCII class); a colon wrongly
  treated as a sentence boundary; a resolver bug that split one surname into
  dozens of entities; leak-scanner substring false positives; single-letter
  "entities". Added **occurrence propagation** so a surface known sensitive is
  caught at every whole-word position (fixes sentence-initial leaks).
- Synthetic eval and the leak benchmark both gate CI.

### Detection coverage
- Added **postal-address detection**: English street addresses (number + name +
  street type), German/Austrian compound streets ("Hauptstraße 12"), and UK
  postcodes. Conservative patterns keep precision.
- Added **MAC addresses**, **geo-coordinates**, **crypto wallets** (ETH/BTC),
  **passport / driver-licence** numbers, and a **place-name gazetteer** for
  LOCATION typing. 18 entity types total.
- Heuristic NER: trims document-structure / currency words to cut prose
  over-redaction (precision 88% → 100% on the synthetic set); keeps European
  **name particles** ("van", "de", "von") within a name run.
- Phone detector ignores ISBNs and year ranges.

### Performance
- Fixed the O(n²) paths (overlap resolution, resolver name matching, leak-scan,
  edit application). Throughput ~40k → ~360k chars/sec on the real corpus;
  multi-MB documents scale linearly (5 MB ≈ 17s).

### CLI
- `inspect --json`, `batch` (directory sanitisation), and `verify` (audit a
  document for residual PII, optionally against its vault).

### Correctness
- Occurrence propagation now covers REDACT as well as TOKENIZE.
- Review page escapes embedded text (`<`) so undetected content can't break out
  of the script block.

### Notes
- Byte-exact round-trip holds when a token's occurrences share a surface form;
  co-referent mentions with differing surfaces restore to one canonical value.
- The re-id advisory is a flag, not a guarantee; quasi-identifier k-anonymity is
  out of scope for this MVP.
