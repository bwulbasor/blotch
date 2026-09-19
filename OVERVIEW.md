# blotch

A small gatekeeper that runs on your own computer. Before you paste something
sensitive into ChatGPT, Claude, or any outside service, it quietly swaps every
name, ID, email, and account number for a harmless placeholder like
`[[PERSON_001]]`. You send the safe version out. When the answer comes back
still using those placeholders, you drop it back into blotch and it puts the
real names back in. The actual secrets, and the table that remembers which
placeholder means what, never leave your machine.

---

## The round trip (the whole point)

```
your document
     │
     ▼
┌──────────────┐   sanitize     ┌────────────────────────┐
│  blotch      │ ─────────────► │  safe text with tokens │  ──►  AI service
│  (local)     │                │  [[PERSON_001]] ...     │       (ChatGPT,
│              │                └────────────────────────┘        Claude, etc.)
│  keeps the   │                                                      │
│  token→real  │                ┌────────────────────────┐           │
│  mapping     │ ◄───────────── │  AI reply, still using │  ◄────────┘
│  in memory   │   restore      │  the same tokens       │
└──────────────┘                └────────────────────────┘
     │
     ▼
readable answer with the real names back in
```

Yes, the return leg works exactly like you would hope. Once the AI has processed
your document and answered using those same tokens (models carry them through
fine), you paste that answer into the second box in the interface, hit
**Restore**, and every token turns back into the real name or number. You get a
clean, readable reply that talks about actual people again. The little vault that
knows "PERSON_001 means Alejandro" lives only in that browser page, so the
un-hashing happens purely on your machine.

---

## You can see and steer everything

You are not stuck trusting it blindly.

- **Everything it flagged is highlighted** right in the text, so you can see at a
  glance what will be hidden.
- **Missed something?** Select that text with your mouse and tag it yourself.
- **Caught something you would rather keep?** One click leaves it alone.
- **The hidden mapping is on the page.** A table at the bottom shows every token
  next to the real thing it stands for, so you can see the whole hashed table
  instead of guessing.
- **You choose how things get hidden.** Five modes:

  | Mode | Example | Reversible? |
  |---|---|---|
  | Semantic tokens (default) | `Alejandro Martinez → [[PERSON_001]]` | Yes |
  | Synthetic substitution | `Alejandro Martinez → Daniel Weber` (reads naturally) | Yes |
  | Generalize | `14 March 1976 → 1976`, else `[a person]` | No |
  | Total redaction | `[REDACTED]` | No |
  | Blackout | `████` | No |

  The same person stays consistent in every mode. "Alejandro" in paragraph one
  and paragraph nine become the same token or the same fake name, so the AI does
  not get confused about who is who.

---

## Why it is different from the usual tools

Most privacy tools have a hole in them.

- **Cloud based scrubbers** ask you to upload your document to them first so they
  can clean it, which is a bit silly if your whole worry was your data leaving in
  the first place.
- **Black marker tools** just blot things out for good, which is fine for a
  printed court file but useless when you actually wanted a sensible answer back
  from the AI.

blotch is the rare mix of both good halves. It stays fully on your machine,
and it is reversible, so you get a real usable answer instead of a page full of
black bars. And it does not just claim to be accurate. It is measured against
real public test sets, catching every direct identifier in a corpus of over a
thousand court cases (see Benchmarks below).

---

## Where it is actually useful

- Lawyers, doctors, HR people, and finance teams who want to use modern AI on
  real documents but are not allowed to hand raw client or patient data to a
  third party.
- Companies that have to keep data in house for GDPR or HIPAA reasons but still
  want their staff using AI.
- Any careful person about to paste a contract, a medical letter, or a bank
  statement into a chatbot.

---

## Cost of implementing it

Low.

- **To try it yourself:** a quick install and one command, then you open a
  browser tab.
- **For a team:** run it as a small internal service and point your tools at it.
  A day or two of setup, no cloud bill, no per document charge.
- **Optional extra:** a smarter name detector (spaCy) adds a bigger download, but
  everything works without it.

The real cost is not money or servers. It is the tuning, getting the balance
right between catching everything and not blacking out half the page. That is the
part that takes the work, and it is also why the human review screen exists. The
machine does most of the work and a person clicks the last few in a couple of
seconds.

**Scanned documents and images:** a scanned PDF, or a photo of a page, is just a
picture with no text to read. blotch now has an optional OCR layer for exactly
this: install an OCR engine and it renders each page and reads the text off the
image automatically. It is smart about mixed documents too, only OCR'ing the
pages that actually have no text layer, so a mostly-digital PDF with a couple of
scanned inserts stays fast. Image files (PNG, JPG, TIFF, ...) can be uploaded
directly. Without an engine installed, everything else works as before and a
scan simply comes back empty. OCR text is a best-effort transcription and can
contain recognition errors, so the review screen matters even more here.

You can choose the OCR engine. The default is a light, fast one that runs
anywhere. For the best accuracy there is an optional modern OCR model,
LightOnOCR-2, a small vision-language model that reads a page the way a person
would; it is heavier and works best with a GPU, so it is opt-in rather than the
default.

---

## Under the hood (how the working actually works)

For anyone who wants the mechanics, here is what happens between "your document"
and "safe text."

### 1. Detection, in two layers

**Deterministic layer.** Things with a fixed shape are matched by pattern and
then checked, not just guessed. IBANs are validated with the mod-97 checksum,
credit cards with the Luhn check, and so on. This layer covers emails, phones,
national IDs, card numbers, IBANs, crypto and MAC addresses, dates, case numbers,
and similar structured identifiers. Because it verifies, it rarely cries wolf.

**Name layer (NER).** People, organisations, and places do not have a fixed
shape, so this layer uses spaCy when it is installed, and falls back to a
dependency-free heuristic when it is not. The two are combined as a union rather
than one replacing the other, because dropping either one loses real names, and a
missed name is a leak. The heuristic leans slightly toward over-detecting on
purpose, and the human review screen is where that extra gets trimmed back.

One nice trick in the name layer: if a capitalised word also shows up in
lowercase somewhere else in the same document, it is almost certainly an ordinary
word rather than a name, so it is left alone. That single idea removes a huge
amount of noise in technical and legal documents without a hand-written word list.

### 2. Resolving who is who

All the detected spans are de-overlapped, then grouped so that repeated mentions
of the same entity map to one identity. This is what keeps "Alejandro" and "Also
Alejandro" and a later "Martinez" pointing at the same person, so they all get
the same token instead of three different ones.

### 3. Tokenising and the vault

Each entity gets an opaque, reversible token (`[[PERSON_001]]`). The mapping from
token back to the original is stored in a **vault**. On disk the vault can be
encrypted with AES-256-GCM using a key derived from your passphrase (scrypt). In
the web interface the vault simply lives in the page's memory and is never sent
anywhere.

### 4. A guaranteed no-leak sweep

After tokenising, the tool does a final pass over the output to make sure no
original value slipped through, and a separate leak scanner double-checks the
result. If anything sensitive is still visible, it gets caught here rather than
by the person on the other end. The process is deterministic, so the same
document always sanitises the same way.

### 5. Restoring

Restore is the mirror image. It finds the tokens in the AI's reply and puts the
originals back, and it flags anomalies (a token the AI invented that was never
issued, or one that went missing) so you know if the model misbehaved.

---

## Benchmarks (so it is not just vibes)

Measured against public, real-world test sets:

- **TAB (Text Anonymization Benchmark)** — 1,268 European Court of Human Rights
  cases. 100% recall on direct identifiers (names and case codes), with precision
  around 95%.
- **AI4Privacy (pii-masking-200k)** — broad synthetic PII. Around 92% recall on
  the identifier types blotch targets.

These run as regression gates, so a change that would quietly lower recall or
precision fails the build.

---

## Try it

```bash
pip install -e ".[docs]"
python -m blotch serve
```

Then open **http://127.0.0.1:8723**, upload a PDF, DOCX, or TXT (or just paste
text), and use **Sanitize**, **Review & tag**, or **Inspect**. Everything runs on
your machine and nothing is sent anywhere.
