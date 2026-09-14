# censorbot

**A local privacy gateway for documents.** censorbot puts a reversible
pseudonymisation layer between your sensitive information and an external
AI/service. The identifying data — and the token→original mapping that reverses
it — **never leave your machine**. Only opaque, reversible tokens are transmitted.

```
Original → local extraction → local detection → local pseudonymisation
         → EXTERNAL PROCESSING → local re-identification → final result
```

```text
Alejandro Martinez was admitted to Vienna General Hospital on 14 March 2026.
His patient number is 48392017. Reach him at a.martinez@example.com.
```

becomes (this is all that leaves the device):

```text
[[PERSON_001]] was admitted to [[ORGANIZATION_001]] on [[DATE_001]].
His patient number is [[PATIENT_ID_001]]. Reach him at [[EMAIL_001]].
```

The local vault keeps `PERSON_001 → Alejandro Martinez`, … and rehydrates the
model's reply afterward. The external provider never sees the mapping.

> Status: **alpha (0.1)**. The core invention — detect → tokenise → verify →
> rehydrate, entirely local — is implemented and tested. See the roadmap.

---

## Why this design (and where the original plan was wrong)

This project began from a detailed architecture note. Most of it holds up; a few
points were corrected during the build because they don't survive contact with
implementation:

1. **Regenerate, don't edit.** In-place PDF redaction is a notorious leak source
   (hidden text layers, annotations, form fields, metadata, embedded files, OCR
   layers). censorbot extracts text and **regenerates a clean document from the
   sanitised text** — regeneration structurally cannot carry forward a layer it
   never copied.
2. **Opaque tokens only, for now.** Synthetic ("Alejandro→Daniel Weber") and
   format-preserving substitutions quietly break the two things that matter
   most: your own leak scanner can't tell a fake name from a real one, fakes can
   collide with a *different* real entity, and reversal depends on the model
   echoing the value back byte-exact. The strategy interface is pluggable, but
   the MVP ships reversible opaque tokens exclusively.
3. **Validate where you can.** Deterministic detectors are locale-bound, so we
   validate what is structurally validatable — IBAN mod-97, card Luhn — to keep
   precision high there, and treat the rest as high-recall candidates surfaced
   for review.
4. **Blocking scanner, audited override.** The outbound leak scanner *blocks*
   rather than warns — but every block is inspectable and overridable with an
   explicit `--force` that records the residual material, so it's never a dead
   end (which would just train users to bypass it).
5. **Rehydrate only issued tokens.** The return trip is untrusted. An invented
   `[[PERSON_842]]` is left verbatim and flagged, never guessed.
6. **Conservative entity resolution.** Over-merging two people, or splitting one
   across tokens, both corrupt meaning and rehydration. We link only on
   high-confidence evidence; distinct entities always get distinct tokens, so
   relationship graphs survive (`A owes B, B owes C` stays intact).
7. **Quasi-identifier re-identification is real but not solved here.** Removing a
   name while leaving "the 47-year-old CEO who survived the 2024 accident" is a
   leak. That layer is on the roadmap as an honest *risk flag*, not a guarantee.

## Token format

Plain ASCII `[[TYPE_NNN]]` (e.g. `[[PERSON_001]]`, `[[PATIENT_ID_017]]`):

- **Survives round-trips.** Unicode brackets get normalised/stripped by some
  model tokenizers; double square brackets survive LLMs, DOCX, PDF, JSON, email.
- **Readable + sequential.** Aids the review UI, keeps relationships legible, and
  makes "the model invented a token we never issued" trivial to detect.
- **Guessability is not a leak.** The mapping lives only in the local vault and
  only issued tokens rehydrate, so a random suffix would buy no real security.

## Install

```bash
pip install -e .                 # core (pure stdlib, zero required deps)
pip install -e '.[crypto]'       # encrypted vault at rest (AES-256-GCM)
pip install -e '.[ner]'          # spaCy NER (better PERSON/ORG/LOC recall)
pip install -e '.[docs]'         # PDF + DOCX ingestion
pip install -e '.[all,dev]'      # everything + pytest
```

The core runs with **no third-party dependencies**. Encryption, spaCy, and
PDF/DOCX are optional extras that degrade gracefully when absent.

## CLI

```bash
# See what would be detected, and with what confidence
censorbot inspect note.txt --policy medical

# Pseudonymise; write sanitised text + an encrypted vault
censorbot sanitize note.txt --out safe.txt --vault note.cbv \
    --policy medical --passphrase "…"

# ... send safe.txt to any model, save its reply to reply.txt ...

# Rehydrate the reply locally
censorbot restore reply.txt --vault note.cbv --passphrase "…"
```

`sanitize` refuses to write if the leak scan isn't clean (override with
`--force`, which records the residual material).

## Library

```python
from censorbot import sanitize, restore, get_policy

result = sanitize(text, get_policy("personal"))
assert result.leak_report.clean
reply = external_model(result.sanitized_text)   # only tokens leave the device
final = restore(reply, result.vault)
print(final.text)
if final.has_anomalies:
    print("model tampered with tokens:", final.summary())
```

## Privacy policies

Modes, not dozens of switches: `maximum`, `personal`, `medical`, `legal`. Each
maps entity types to an action (`tokenize` / `redact` / `keep`).

## Architecture

```
ingest → detect (Layer A regex+checksum, Layer B NER) → resolve overlaps
       → resolve entities → apply policy → tokenise → leak-scan ─┐
                                                                  ▼
                           vault (local, encrypted)      sanitised text ──▶ external
                                    ▲                                          │
              restore (issued tokens only) ◀── validate response ◀── reply ◀──┘
```

## Detected categories (MVP)

Person · Email · Phone · Address · Date/DOB · Organization · Location · IBAN
(mod-97) · Credit card (Luhn) · IP · URL · Government ID · Patient ID · Case/
reference ID · Account ID.

## Roadmap

- [x] Local ingestion + deterministic detection (checksum-validated)
- [x] Heuristic/spaCy NER + conservative entity resolution
- [x] Encrypted token vault + reversible tokenisation
- [x] Sanitised export + outbound leak scan
- [x] Round-trip rehydration with response validation
- [ ] Regenerated sanitised **PDF/DOCX** output (currently text out)
- [ ] Visual review/preview UI
- [ ] Benchmark suite (recall, leak rate, semantic preservation, round-trip)
- [ ] Domain entity packs; synthetic/generalised strategies
- [ ] Re-identification-risk (quasi-identifier) flagging
- [ ] `POST /sanitize|/restore|/inspect` local daemon + provider adapters

## Design principle (non-negotiable)

The original sensitive data, the mappings, the encryption keys, and the detection
process require **no cloud at all**. Sensitive information never leaves the user's
trust boundary.

## License

Apache-2.0. See [LICENSE](LICENSE).
