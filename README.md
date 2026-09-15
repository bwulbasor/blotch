# censorbot

[![CI](https://github.com/bwulbasor/censorbot/actions/workflows/ci.yml/badge.svg)](https://github.com/bwulbasor/censorbot/actions/workflows/ci.yml)

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
7. **Quasi-identifier re-identification is real but not fully solvable here.**
   Removing a name while leaving "the 47-year-old CEO who survived the 2024
   accident" is still a leak. censorbot ships this as an honest **advisory**
   (`censorbot risk`, [reidrisk.py](src/censorbot/reidrisk.py)) that flags
   residual quasi-identifiers and a qualitative level — never a claim of safety.

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
pip install -e '.[ner]' && python -m spacy download en_core_web_sm   # spaCy NER
pip install -e '.[docs]'         # PDF + DOCX ingestion and regenerated output
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

# Run the local gateway daemon (loopback only, zero deps)
censorbot serve --port 8723

# Benchmark detection / leak-rate / round-trip on the built-in fixtures
censorbot benchmark --policy maximum

# Generate the visual review preview (masked, click to inspect each entity)
censorbot review examples/discharge_summary.txt --out review.html --policy medical

# Advisory: residual re-identification risk after names/IDs are removed
censorbot risk examples/discharge_summary.txt --policy medical

# Sanitise a whole directory tree (one encrypted vault per file)
censorbot batch ./docs --outdir ./safe --vaultdir ./vaults \
    --policy legal --passphrase "…"

# Audit a document for residual PII (optionally against its vault)
censorbot verify ./safe/report.txt --vault ./vaults/report.cbv --passphrase "…"

# Batch with consistent pseudonyms across a related set (same person → same token)
censorbot batch ./case-files --outdir ./safe --vaultdir ./vaults \
    --shared-vault --policy legal --passphrase "…"
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

## Provider-agnostic gateway

The external service is completely replaceable — a provider is any callable
`str -> str`:

```python
from censorbot import Gateway, get_policy

def my_model(sanitized: str) -> str:
    return call_chatgpt_or_claude_or_local(sanitized)   # only tokens go out

gw = Gateway(get_policy("legal"), my_model)
res = gw.run(open("brief.txt").read())   # blocks if the outbound scan isn't clean
print(res.restored)                       # rehydrated locally
if res.response_had_anomalies:
    print("provider tampered with tokens:", res.restore_result.summary())
```

## Local daemon

`censorbot serve` runs a stdlib-only HTTP gateway on `127.0.0.1` with a
self-service **web UI** at `/` (paste a document, pick a policy, get the
sanitized text) plus a JSON API:

```
GET  /                                web UI
POST /inspect   {"text","policy"}   -> detected entities
POST /sanitize  {"text","policy"}   -> {sanitized, vault, leak}
POST /restore   {"text","vault"}    -> {restored, invented, dropped}
GET  /policies   GET /health
```

Or run it in a container (publish to loopback only — it returns vault material):

```bash
docker build -t censorbot . && docker run --rm -p 127.0.0.1:8723:8723 censorbot
```

The vault travels in the `/sanitize` response and back to `/restore`; the server
is stateless and loopback-bound, so the mapping never leaves the machine.

## Privacy policies

Modes, not dozens of switches: `maximum`, `personal`, `medical`, `legal`. Each
maps entity types to an action (`tokenize` / `redact` / `keep`). For fine-grained
control, pass a custom policy JSON with `--policy-file`:

```json
{ "name": "names-and-ids", "default": "keep",
  "actions": { "PERSON": "tokenize", "IBAN": "tokenize", "GOV_ID": "redact" } }
```

Unknown entity types are rejected (a typo must not silently leak a category), and
the outbound leak scanner still blocks if a custom policy leaves a high-confidence
identifier behind.

## Provider adapters

`censorbot.providers` ships dependency-free adapters so the gateway can talk to
any JSON/HTTP service — only the sanitised text is ever sent:

```python
from censorbot import Gateway, get_policy
from censorbot.providers import openai_chat_provider

provider = openai_chat_provider(
    "https://api.openai.com/v1/chat/completions", api_key=KEY, model="gpt-4o-mini")
result = Gateway(get_policy("legal"), provider).run(text)
```

`HttpProvider(url, build_payload=…, response_path="choices.0.message.content")`
covers any other endpoint (local llama.cpp/vLLM/Ollama shims, company APIs).

## Round-trip fidelity & coreference

Every token rehydrates to a value that actually appeared in the source. When one
entity is mentioned several ways ("Alejandro Martinez" … "Mr. Martinez"), all
mentions share **one** token (this is what lets a model keep the relationship
graph, plan §11) and therefore all restore to the single canonical surface (the
longest one seen). That's a deliberate trade of exact per-mention surface fidelity
for coreference. On the built-in benchmark, byte-exact round-trip is 100%.

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

Person · Email · Phone · Address (street + UK postcode) · Date/DOB ·
Organization · Location (gazetteer) · IBAN (mod-97) · Credit card (Luhn) · IP ·
MAC · Geo-coordinates · Crypto wallet (ETH/BTC) · URL · Government ID (incl.
passport / licence) · Patient ID · Case/reference ID · Account ID.

## Evaluation

### Real-world benchmark (Text Anonymization Benchmark)

The honest measure is on **real documents with gold human annotations**, not our
own synthetic data. `benchmarks/tab_eval.py` runs censorbot against
[TAB](https://github.com/NorskRegnesentral/text-anonymization-benchmark) — 1,268
real European Court of Human Rights judgments, each span labelled DIRECT / QUASI.
The headline metric is **DIRECT recall** (a missed direct identifier is a leak):

| Split | DIRECT recall | PERSON | CODE (case refs) | QUASI recall | precision |
|------|---------------|--------|------------------|--------------|-----------|
| test | **100%** (374/374) | 100% | 100% | 82% | **94%** |
| dev  | **100%** (391/391) | 100% | 100% | 84% | 93% |

Precision started at **65%** — the capitalisation heuristic flagged capitalised
common nouns in legal text (`Court`, `Government`, `Convention`) and headings as
names. A data-driven stoplist and requiring organisations to have a real
distinguishing word (not just `The`/`European` + `Court`) cut over-redaction from
35% to 6% **with no loss of DIRECT recall (still 100%) or name recall**.

A second benchmark, [AI4Privacy pii-masking](https://huggingface.co/datasets/ai4privacy/pii-masking-200k),
covers the contact/financial PII that legal text lacks. On 2,000 English rows,
recall on the types censorbot targets is **93.5% (heuristic) / 93.9% (spaCy
union)** — the heuristic nearly matches spaCy, which matters because spaCy needs
Python ≤ 3.13. The deterministic detectors are near-perfect:

| Detector | recall | | Detector | recall |
|---|---|---|---|---|
| EMAIL / PHONE | 100% | | CREDIT_CARD | 100% |
| IPv4 / IPv6 | 100% | | IBAN | 100% |
| URL / MAC | 100% | | Ethereum | 100% |
| FIRSTNAME | 99% | | LASTNAME | 99% |
| STREET / CITY / STATE | 100% | | SSN / Bitcoin | 97% |

The remaining gap is context-free bare numbers (a lone building number or ZIP,
`MM/YY` dates) — catching those means redacting every short number, so they're
left out by design (the street/city/state around them are already caught).

**Over-redaction / precision** was worked the same data-driven way. The
capitalisation heuristic flagged common capitalised words as names
(`Convention`, `Your`, `Could`, `IP`, `Bitcoin`). Analysing exactly what each
benchmark flagged that its human/gold labels did not, and adding those
non-name words, raised precision **65% → 94% on TAB** and **72% → 84% on
AI4Privacy — with no loss of recall** (DIRECT still 100%, names still 99%).

Getting here was the point of the exercise: the first TAB run scored only **62%**
DIRECT recall — all case/application numbers (`36110/97`) were missed — and
AI4Privacy exposed that Luhn-gated card detection missed 84% of card-shaped
numbers. Both are fixed. Quasi-identifiers (bare years, durations, demographics,
quantities) are partially caught by design; exhaustively redacting them destroys
utility, so they are surfaced by the re-id-risk advisory instead. Reproduce:

```bash
mkdir -p benchmarks/data && curl -Lo benchmarks/data/echr_test.json \
  https://raw.githubusercontent.com/NorskRegnesentral/text-anonymization-benchmark/master/echr_test.json
python -m benchmarks.tab_eval --split test
```

### Synthetic + wild

The `evaluation/` subsystem measures the engine on hard inputs:

```bash
python -m evaluation.evaluate      # synthetic docs WITH ground truth → precision/recall
python -m evaluation.fetch_corpus  # download public-domain / public-record docs
python -m evaluation.run_wild      # run over real docs: throughput, crashes, leak-scan
```

### spaCy NER (optional, recommended for natural-language documents)

Install the `ner` extra + the `en_core_web_sm` model, then pass `use_spacy=True`
(the CLI does by default; `--no-spacy` forces the heuristic). spaCy is **unioned
with** the built-in heuristic, never substituted for it: on its own spaCy misses
the cases most dangerous for a privacy tool — common-word names ("May",
"Summer") and non-Latin names ("Łukasz Škoda") — so the heuristic stays as a
recall safety net while spaCy adds correctly-typed ORG/LOCATION and names caught
in natural context (on the eval corpus it adds ~760 real-name catches the
heuristic missed). Trade-off: spaCy runs ~15× slower (~20K vs ~300K chars/sec).
Requires Python ≤ 3.13 today (no 3.14 wheels yet); the engine falls back to the
heuristic automatically when spaCy is absent.

* **Synthetic set** (`synth.py`) generates labelled documents with a hard-case
  bank — names that are common words, Unicode/apostrophe/hyphen names,
  international phones, multi-country checksum-valid IBANs, ambiguous numbers,
  court case numbers, and coreference. Current result (heuristic NER): **100%
  coverage recall, 0% leak, 100% precision, 100% type-accuracy** across 17 entity
  types (gates CI).
* **Wild corpus** (`fetch_corpus.py`, gitignored) pulls public-domain literature
  and public-figure/reference Wikipedia articles. On ~890K chars: **0 crashes,
  leak-scan clean on every document**, ~40K chars/sec (heuristic path).

Building this corpus drove out four real bugs — court case numbers, non-Latin
uppercase names, a colon mis-read as a sentence boundary, and a resolver bug that
split one surname into dozens of entities and leaked it at sentence starts. Each
is now a committed regression test.

## Roadmap

- [x] Local ingestion + deterministic detection (checksum-validated)
- [x] Heuristic/spaCy NER + conservative entity resolution
- [x] Encrypted token vault + reversible tokenisation
- [x] Sanitised export + outbound leak scan
- [x] Round-trip rehydration with response validation
- [x] Benchmark harness (recall, leak rate, round-trip, scan-block rate)
- [x] Provider-agnostic `Gateway` (the external service is fully replaceable)
- [x] `POST /sanitize|/restore|/inspect` local daemon (loopback, zero deps)
- [x] Regenerated sanitised **TXT/DOCX/PDF** output, verified on read-back
- [x] Visual review/preview UI (`censorbot review` → standalone HTML)
- [x] Re-identification-risk (quasi-identifier) advisory (`censorbot risk`)
- [x] CI (tests + leak benchmark gate on every push)
- [ ] Layout/appearance-preserving output (same verification bar)
- [ ] Semantic-preservation metric (needs a real model in the loop)
- [ ] Domain entity packs; synthetic/generalised strategies

## Threat model

What censorbot protects, against whom, and what it explicitly does **not**
guarantee, is documented in [THREAT_MODEL.md](THREAT_MODEL.md). Short version: the
external service and its response are untrusted and only ever see tokens; the
vault is local and encrypted; detection is best-effort with a blocking leak-scan
backstop; quasi-identifier anonymity is an advisory, not a guarantee.

## Design principle (non-negotiable)

The original sensitive data, the mappings, the encryption keys, and the detection
process require **no cloud at all**. Sensitive information never leaves the user's
trust boundary.

## License

Apache-2.0. See [LICENSE](LICENSE).
