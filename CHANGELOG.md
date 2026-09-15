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
- **Local HTTP daemon** (`censorbot serve`, loopback-only, stdlib only).
- **Regenerated document output** (TXT/DOCX/PDF) verified on read-back —
  regenerate-don't-edit, so no un-sanitised layer can survive.
- **Visual review preview** (`censorbot review` → standalone HTML).
- **Re-identification-risk advisory** (`censorbot risk`) for residual
  quasi-identifiers.
- **Custom policies** via `--policy-file` / `policy_from_dict`.
- **Benchmark harness** (`censorbot benchmark`) and CI gating on leak rate.

### Notes
- Byte-exact round-trip holds when a token's occurrences share a surface form;
  co-referent mentions with differing surfaces restore to one canonical value.
- The re-id advisory is a flag, not a guarantee; quasi-identifier k-anonymity is
  out of scope for this MVP.
