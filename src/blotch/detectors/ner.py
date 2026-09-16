"""Layer B: named-entity detection for contextual entities (PERSON, ORG, ...).

Uses spaCy when installed (``pip install 'blotch[ner]'``), otherwise a
dependency-free heuristic fallback so the pipeline still runs everywhere. The
fallback is intentionally high-recall / lower-precision: for a privacy gateway a
false positive is an annoyance, a false negative is a leak (plan §4). The review
UI is where precision is recovered.
"""

from __future__ import annotations

import re

from ..spans import EntityType, Span

_TITLE_WORDS = {"mr", "mrs", "ms", "miss", "dr", "prof", "herr", "frau", "sir",
                "madam", "mx", "st"}
_ORG_SUFFIX_WORDS = {
    "inc", "llc", "ltd", "gmbh", "ag", "plc", "corp", "co", "company", "hospital",
    "clinic", "klinik", "university", "universität", "bank", "group", "holdings",
    "foundation", "court", "gericht", "sons", "partners", "associates",
}
# A single letter-led "word" (Unicode-aware: any letter start, then letters /
# apostrophe / hyphen). Uppercase is judged with str.isupper(), which is correct
# for accented and non-Latin letters that an ASCII char class ([A-Z]) misses.
_WORD = re.compile(r"[^\W\d_][^\W\d_'’\-]*", re.UNICODE)
_MAX_NAME_GAP = 2  # max spaces/tabs between two words of one name run

# Lowercase nobiliary / patronymic particles that join two capitalised name words
# ("Ludwig van Beethoven", "Charles de Gaulle", "Vincent van der Berg").
_PARTICLES = {
    "van", "von", "de", "da", "del", "della", "der", "den", "di", "du", "la",
    "le", "ten", "ter", "zu", "dos", "das", "bin", "ibn", "al", "af",
}

# Sentence-leading capitalised words that are usually not names.
_STOPWORDS = {
    "The", "A", "An", "This", "That", "These", "Those", "His", "Her", "Their",
    "It", "He", "She", "They", "We", "You", "I", "On", "In", "At", "For", "And",
    "But", "Or", "If", "When", "According", "Patient",
}

# Common words that open a sentence but are not names. A lone capitalised word at
# a sentence start is dropped only if it is one of these; an *unknown*
# capitalised word (likely a real name, e.g. "Kattie, ...") is kept - recall
# first, and over-redacting an unusual sentence-opener is safe, missing a name is
# not. spaCy handles this properly; this narrows the heuristic's blind spot.
_SENTENCE_OPENERS = {w.lower() for w in _STOPWORDS} | {
    "later", "however", "meanwhile", "therefore", "thus", "moreover",
    "furthermore", "nevertheless", "nonetheless", "subsequently", "additionally",
    "finally", "firstly", "secondly", "thirdly", "then", "now", "today",
    "yesterday", "tomorrow", "here", "there", "while", "after", "before",
    "during", "since", "although", "because", "unfortunately", "fortunately",
    "consequently", "hence", "indeed", "instead", "overall", "similarly",
    "specifically", "generally", "typically", "currently", "recently",
    "previously", "initially", "eventually", "ultimately", "perhaps", "maybe",
    "certainly", "clearly", "obviously", "actually", "basically", "essentially",
    "regardless", "accordingly", "alternatively", "besides", "conversely",
    "likewise", "namely", "notably", "otherwise", "presently", "undoubtedly",
    "whereas", "yet", "so", "also", "please", "thanks", "thank", "dear", "hello",
    "hi", "yes", "no", "ok", "okay", "well", "just", "only", "even", "still",
    "again", "once", "whenever", "wherever", "whether", "unless", "until",
    "meanwhile", "following", "regarding", "concerning", "per", "via", "note",
    "under", "within", "having", "pursuant", "applying", "acting", "both",
    "further", "given", "considering", "notwithstanding", "upon", "thereafter",
    "moreover", "furthermore", "whilst", "throughout", "hereinafter",
    # pronouns, modals, and common imperative verbs that open conversational /
    # form sentences (dropped only when sentence-initial, so real names are safe)
    "your", "our", "could", "can", "kindly", "use", "let", "need", "good",
    "check", "may", "might", "would", "should", "will", "shall", "must", "do",
    "does", "did", "get", "got", "make", "take", "give", "send", "provide",
    "enter", "click", "call", "contact", "reach", "confirm", "verify", "update",
    "review", "submit", "complete", "ensure", "what", "which", "who", "whom",
    "whose", "where", "why", "how", "want", "please", "kindly", "ensure",
    "all", "any", "looking", "remember", "join", "access", "greetings",
    "welcome", "hey", "connect", "received", "best", "reminder", "payment",
    "team", "education", "warm", "cheers", "attached", "let's", "we've",
    "you'll", "we'll", "here's", "there's", "it's", "that's", "thank",
}

# Words that are never a person's name: function words and document-structure
# / form-label words. A candidate run has these trimmed from its ends (so
# "In Vienna" -> "Vienna", "DISCHARGE SUMMARY" -> dropped) without touching real
# names in the middle. Lower-cased for lookup. Titles are handled separately and
# are deliberately NOT included here.
_NON_NAME = {w.lower() for w in _STOPWORDS} | {
    "of", "to", "from", "by", "with", "as", "is", "was", "were", "be", "been",
    "re", "cc", "bcc", "attn", "dear", "sincerely", "regards", "subject",
    "summary", "invoice", "discharge", "confidential", "draft", "section",
    "article", "chapter", "page", "figure", "note", "notes", "total",
    "subtotal", "amount", "balance", "date", "ref", "reference",
    "contact", "billing", "emergency", "plaintiff", "defendant", "exhibit",
    "appendix", "memo", "report", "statement", "notice", "admitting",
    "regarding", "dob", "name", "address", "phone", "email", "questions", "due",
    # form / field labels that open a line but are never names on their own
    "home", "records", "property", "ship", "shipping", "wallet", "order",
    "orders", "item", "items", "sender", "recipient", "account", "card", "cards",
    "server", "host", "device", "user", "username", "password", "login",
    # common capitalised nouns in formal / legal / institutional text - flagged
    # as names by a capitalisation heuristic but never names themselves. Role
    # words (president, judge, ...) are trimmed from run ends, so "President Smith"
    # still keeps "Smith". Data-driven from TAB false positives.
    "convention", "conventions", "court", "courts", "government", "governments",
    "rule", "rules", "agent", "agents", "commission", "commissioner", "president",
    "vice-president", "act", "acts", "state", "states", "chamber", "registrar",
    "board", "secretary", "law", "laws", "protocol", "protocols", "article",
    "articles", "section", "sections", "protection", "freedom", "freedoms",
    "right", "rights", "party", "parties", "applicant", "applicants",
    "respondent", "respondents", "judge", "judges", "member", "members",
    "committee", "council", "parliament", "ministry", "department", "office",
    "authority", "authorities", "republic", "kingdom", "union", "federation",
    "tribunal", "senate", "congress", "assembly", "bureau", "agency", "agencies",
    "prosecutor", "counsel", "attorney", "witness", "witnesses", "directive",
    "regulation", "regulations", "statute", "amendment", "clause", "paragraph",
    "paragraphs", "subsection", "schedule", "annex", "decree", "ordinance",
    "resolution", "treaty", "charter", "code", "motion", "petition", "appeal",
    "judgment", "judgement", "verdict", "ruling", "order", "orders", "decision",
    "decisions", "opinion", "hearing", "hearings", "trial", "session",
    "proceeding", "proceedings", "circumstances", "facts", "procedure",
    "background", "introduction", "conclusion", "analysis", "discussion",
    "findings", "reasons", "grounds", "merits", "admissibility", "jurisdiction",
    "remedy", "remedies", "damages", "costs", "compensation", "chairman",
    "chairwoman", "deputy", "minister", "governor", "ambassador", "delegate",
    "representative", "official", "officer", "fundamental", "human", "european",
    "case", "no", "criminal", "civil", "administrative", "constitutional",
    "supreme", "federal", "national", "international", "regional", "central",
    "special", "general", "foreign", "affairs", "grand", "adviser", "advisers",
    "class", "prevention", "tax", "vice", "appellate", "ordinary", "military",
    "legal", "justice", "justices", "directorate", "terrorism", "reports",
    "report", "judgments", "judgements", "lawyer", "lawyers", "public", "common",
    "employment", "district", "districts", "circuit", "circuits", "panel",
    "petitioner", "petitioners", "intervenor", "intervenors",
    # political adjectives / demonyms and Latin legal boilerplate that a
    # capitalisation heuristic reads as names ("Democratic", "Per Curiam",
    # "Ibid"). Multi-word proper names ("Sherrod Brown") are unaffected.
    "democratic", "republican", "congressional", "senatorial", "per", "curiam",
    "ibid", "cite", "ante", "post", "supra", "certiorari", "stay",
    # pure adverbs / conjunctions that can open a line before a name ("Also
    # Alejandro ...") - trimming them from run ends keeps the name a single entity
    # (fixes coreference: "Also Alejandro" -> "Alejandro").
    "also", "then", "thus", "hence", "therefore", "however", "meanwhile",
    "moreover", "furthermore", "nevertheless", "nonetheless", "subsequently",
    "additionally", "finally", "similarly", "likewise", "otherwise",
    "accordingly", "consequently", "indeed", "instead", "besides", "conversely",
    "namely", "notably", "whereas", "whilst", "regardless", "alternatively",
    "later", "meanwhile", "afterwards", "thereafter", "henceforth",
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
    # month and weekday names (part of dates via the date detector; a lone one is
    # not a person name)
    "january", "february", "march", "april", "june", "july", "august",
    "september", "october", "november", "december", "monday", "tuesday",
    "wednesday", "thursday", "friday", "saturday", "sunday",
    # technical / document vocabulary (specs, RFCs, APIs) - never names. Common
    # surnames (field, page, rich, baker, ...) are deliberately excluded.
    "standards", "track", "content", "request", "internet", "encoding", "range",
    "syntax", "accept", "cache", "length", "location", "transfer", "status",
    "line", "type", "control", "warning", "service", "domain", "modified",
    "continue", "header", "headers", "message", "messages", "response", "method",
    "methods", "protocol", "protocols", "network", "parameter", "parameters",
    "version", "format", "connection", "client", "port", "gateway", "proxy",
    "resource", "media", "scheme", "query", "cookie", "session", "token",
    "registry", "specification", "entity", "example", "error", "abstract",
    "category", "obsoletes", "updates", "ipv", "smtp", "http", "https", "ftp",
    "tcp", "udp", "dns", "uri", "api", "sdk", "html", "xml", "json", "css",
    "uuid", "ascii", "utf", "mime", "imap", "ssl", "tls", "ssh", "vpn", "see",
    "last", "mail", "extension", "extensions", "expect", "expires", "requested",
    "match", "command", "commands", "minutes", "vary", "partial", "etag", "uris",
    "chunked", "referer", "referrer", "pragma", "upgrade", "allow", "retry",
    "redirect", "timeout", "offset", "checksum", "digest", "boundary", "charset",
    "codec", "keepalive", "reply", "sender", "subject", "received",
    # ORG-suffix words also drop when standing alone (a lone "Court"/"Bank" is
    # not an org and not a name)
    "hospital", "clinic", "university", "bank", "group", "foundation", "company",
    "sons", "partners", "associates", "holdings",
    # ordinals used in section/chamber names
    "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth",
    "ninth", "tenth",
    # currency codes and financial labels (all-caps codes, never names)
    "eur", "usd", "gbp", "chf", "jpy", "cad", "aud", "cny", "sek", "nok", "dkk",
    "pln", "czk", "huf", "iban", "bic", "swift", "vat", "pin", "otp", "url",
    # tech / crypto type labels - the WORD, not the value (deterministic detectors
    # still catch the actual IP/MAC/SSN/wallet); these are never names on their own
    "ip", "mac", "ssn", "cvv", "cvc", "imei", "id", "stem", "bitcoin", "litecoin",
    "ethereum", "dogecoin", "crypto", "wallet", "vin", "vrm", "gps", "sim",
}


def _spacy_detect(text: str):  # pragma: no cover - exercised only when spaCy present
    try:
        import spacy
    except Exception:
        return None
    try:
        nlp = _spacy_detect._nlp  # type: ignore[attr-defined]
    except AttributeError:
        try:
            nlp = spacy.load("en_core_web_sm")
        except Exception:
            return None
        _spacy_detect._nlp = nlp  # type: ignore[attr-defined]

    label_map = {
        "PERSON": EntityType.PERSON,
        "ORG": EntityType.ORGANIZATION,
        "GPE": EntityType.LOCATION,
        "LOC": EntityType.LOCATION,
        "FAC": EntityType.LOCATION,
    }
    spans: list[Span] = []
    # spaCy raises over nlp.max_length (default 1M chars) as a memory guard, so
    # process large documents in offset-adjusted chunks split on line boundaries.
    limit = max(1, int(getattr(nlp, "max_length", 1_000_000) * 0.9))
    for base, chunk in _chunk_on_lines(text, limit):
        for ent in nlp(chunk).ents:
            etype = label_map.get(ent.label_)
            if etype is None:
                continue
            # A named-entity token never starts or ends with whitespace/newline;
            # spaCy sometimes glues a trailing wrap onto a span ("the \n"). Trim
            # the offsets so the surface is clean (interior bytes are untouched,
            # so a soft-wrapped name is still fully covered - no recall loss).
            surface = ent.text
            lead = len(surface) - len(surface.lstrip())
            trail = len(surface) - len(surface.rstrip())
            start = base + ent.start_char + lead
            end = base + ent.end_char - trail
            if end - start < 2:
                continue
            spans.append(Span(start, end, etype, surface.strip(), 0.85, "spacy"))
    return spans


def _chunk_on_lines(text: str, limit: int):
    """Yield ``(offset, chunk)`` pieces of ``text`` each <= ``limit`` chars, split
    at newlines so an entity is never cut across a chunk boundary."""
    if len(text) <= limit:
        yield 0, text
        return
    pos = 0
    n = len(text)
    while pos < n:
        end = min(pos + limit, n)
        if end < n:
            nl = text.rfind("\n", pos, end)
            if nl > pos:
                end = nl + 1
        yield pos, text[pos:end]
        pos = end


def _is_sentence_initial(text: str, start: int) -> bool:
    """True if the match at ``start`` begins a sentence (or the text).

    Only real sentence terminators and line breaks count - notably NOT ':' or
    ';', because names very often follow a label colon ("Emergency contact: ...").
    """

    i = start - 1
    while i >= 0 and text[i] in " \t":
        i -= 1
    return i < 0 or text[i] in ".!?…\n\r"


def _is_title(word: str) -> bool:
    return word.lower().rstrip(".") in _TITLE_WORDS


def _heuristic_detect(text: str) -> list[Span]:
    """Group consecutive capitalised words into PERSON / ORGANIZATION runs.

    Uppercase is tested with ``str.isupper()`` so accented and non-Latin names
    ("Škoda", "Łukasz", "Øthen") are caught. Words are joined only across plain
    horizontal whitespace - a run never crosses a line break or punctuation -
    except that a title may be followed by "." (e.g. "Dr. Keller").
    """

    # Words that also occur lower-case somewhere in the document are common words,
    # not names - a name is capitalised every time ("Content"/"content" -> common;
    # "Klensin" -> only ever capitalised). This document-internal, language- and
    # domain-agnostic signal removes most technical-term false positives with, on
    # the TAB/AI4Privacy benchmarks, zero loss of real names.
    doc_lower = set(re.findall(r"[a-zà-öø-ÿ][a-zà-öø-ÿ']{1,}", text))

    words = list(_WORD.finditer(text))
    spans: list[Span] = []
    i, n = 0, len(words)
    while i < n:
        w = words[i]
        if not (w.group(0)[:1].isupper() or _is_title(w.group(0))):
            i += 1
            continue
        run = [w]
        j = i + 1
        while j < n and len(run) < 5:
            prev, cur = run[-1], words[j]
            gap = text[prev.end():cur.start()]
            prev_is_title = _is_title(prev.group(0))
            # Words of a name are separated by a single space (rarely two), never
            # a wide column gap - "SMTP          October" in a table of contents
            # must NOT merge into one entity.
            gap_ok = (0 < len(gap) <= _MAX_NAME_GAP and all(c in " \t" for c in gap)) or (
                prev_is_title and re.fullmatch(r"\.?[ \t]{1,3}", gap) is not None)
            if not gap_ok:
                break
            if cur.group(0)[:1].isupper():
                run.append(cur)
                j += 1
            elif (cur.group(0).lower() in _PARTICLES and j + 1 < n
                  and (words[j + 1].group(0)[:1].isupper()
                       or words[j + 1].group(0).lower() in _PARTICLES)
                  and 0 < len(text[cur.end():words[j + 1].start()]) <= _MAX_NAME_GAP
                  and all(c in " \t" for c in text[cur.end():words[j + 1].start()])):
                run.append(cur)  # bridge particle(s); the capitalised word joins next
                j += 1
            else:
                break
        # drop any trailing particle left by the bridge (e.g. an over-run "van");
        # j already points past it, so the outer loop still advances correctly.
        while len(run) > 1 and run[-1].group(0).lower() in _PARTICLES:
            run.pop()
        lowered = {r.group(0).lower().rstrip(".") for r in run}
        titled = _is_title(run[0].group(0))

        # An entirely upper-case run is an acronym, protocol keyword, or heading
        # (SMTP, RFC, MUST, STANDARDS TRACK), never a person's name in body text.
        # This removes the dominant source of over-detection in technical
        # documents. The deterministic detectors still catch any actual PII.
        content_words = [r for r in run if not _is_title(r.group(0))]
        if content_words and all(w.group(0).isupper() and len(w.group(0)) > 1
                                 for w in content_words):
            i = j
            continue

        # NB: the case-consistency signal is applied only to LONE words below, not
        # to multi-word runs - a multi-word name of common words ("May Rich") would
        # otherwise be dropped, which is a leak.

        # ORG needs a suffix word AND a distinguishing word that is neither a
        # stopword nor a suffix - "Vienna General Hospital" is an org, but "Court",
        # "The Court" and "European Court" (only stopwords + a suffix) are not.
        if lowered & _ORG_SUFFIX_WORDS:
            distinguishing = [r for r in run
                              if r.group(0).lower().rstrip(".") not in _NON_NAME
                              and r.group(0).lower().rstrip(".") not in _ORG_SUFFIX_WORDS]
            if distinguishing:
                start, end = run[0].start(), run[-1].end()
                spans.append(Span(start, end, EntityType.ORGANIZATION,
                                  text[start:end], 0.55, "ner_heur"))
                i = j
                continue

        # PERSON candidate: trim function / structure words from both ends so
        # "In Vienna" -> "Vienna" and "DISCHARGE SUMMARY" -> nothing, without
        # touching a real name in the middle. Titles are kept as the leading word.
        person = list(run)
        while person and not _is_title(person[0].group(0)) \
                and person[0].group(0).lower().rstrip(".") in _NON_NAME:
            person.pop(0)
        while person and person[-1].group(0).lower().rstrip(".") in _NON_NAME:
            person.pop()
        if not person:
            i = j
            continue
        content = [r for r in person if not _is_title(r.group(0))]
        titled = _is_title(person[0].group(0))
        if not titled and len(content) == 1:
            first = content[0].group(0)
            # A lone single letter is an initial, not a name. A lone word is
            # dropped if: it is a stopword; it also appears lower-case in the
            # document (a common word, not a name); or it opens a sentence and is
            # a known opener. An unknown, consistently-capitalised word is kept.
            if (len(first) < 2 or first in _STOPWORDS
                    or first.lower() in doc_lower
                    or (_is_sentence_initial(text, content[0].start())
                        and first.lower() in _SENTENCE_OPENERS)):
                i = j
                continue
        if content:  # a bare title alone is not a person
            start, end = person[0].start(), person[-1].end()
            spans.append(Span(start, end, EntityType.PERSON, text[start:end], 0.5,
                              "ner_heur"))
        i = j
    return spans


def detect(text: str, use_spacy: bool = True) -> list[Span]:
    """Detect contextual entities.

    When spaCy is available it is *unioned* with the heuristic, not substituted
    for it. spaCy alone misses the cases most dangerous for a privacy tool -
    common-word names ("May", "Summer") and non-Latin names ("Łukasz Škoda") -
    so replacing the heuristic would drop recall and leak those. The union keeps
    the heuristic as a recall safety net (its spans are never lost) while spaCy
    adds correctly-typed ORG/LOCATION and names caught in natural context; where
    both cover the same text, spaCy's higher confidence wins overlap resolution,
    so its better typing prevails.
    """

    heuristic = _heuristic_detect(text)
    if use_spacy:
        spacy_spans = _spacy_detect(text)
        if spacy_spans is not None:
            return spacy_spans + heuristic
    return heuristic
