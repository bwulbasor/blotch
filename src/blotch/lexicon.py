"""Shared name lexicon: the word lists every layer uses to judge names.

One source of truth for honorific titles, nobiliary particles, organisation
suffixes, sentence openers and the "never a name" stoplist. The NER heuristic
(Layer B), the entity resolver (Layer C) and the pipeline's name-part
propagation all read these; before this module they kept their own copies,
which had already drifted apart.

All sets are lower-case (except STOPWORDS, which holds the capitalised
sentence-leading forms) and frozen, so no importer can mutate them for another.
"""

from __future__ import annotations

TITLE_WORDS = {"mr", "mrs", "ms", "miss", "dr", "prof", "herr", "frau", "sir",
                "madam", "mx", "st"}
ORG_SUFFIX_WORDS = {
    "inc", "llc", "ltd", "gmbh", "ag", "plc", "corp", "co", "company", "hospital",
    "clinic", "klinik", "university", "universität", "bank", "group", "holdings",
    "foundation", "court", "gericht", "sons", "partners", "associates",
}

# Lowercase nobiliary / patronymic particles that join two capitalised name words
# ("Ludwig van Beethoven", "Charles de Gaulle", "Vincent van der Berg").
PARTICLES = {
    "van", "von", "de", "da", "del", "della", "der", "den", "di", "du", "la",
    "le", "ten", "ter", "zu", "dos", "das", "bin", "ibn", "al", "af",
}

# Sentence-leading capitalised words that are usually not names.
STOPWORDS = {
    "The", "A", "An", "This", "That", "These", "Those", "His", "Her", "Their",
    "It", "He", "She", "They", "We", "You", "I", "On", "In", "At", "For", "And",
    "But", "Or", "If", "When", "According", "Patient",
}

# Common words that open a sentence but are not names. A lone capitalised word at
# a sentence start is dropped only if it is one of these; an *unknown*
# capitalised word (likely a real name, e.g. "Kattie, ...") is kept - recall
# first, and over-redacting an unusual sentence-opener is safe, missing a name is
# not. spaCy handles this properly; this narrows the heuristic's blind spot.
SENTENCE_OPENERS = {w.lower() for w in STOPWORDS} | {
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
NON_NAME = {w.lower() for w in STOPWORDS} | {
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
    # law-report / citation abbreviations that surface as lone capitalised
    # fragments ("Cir.", "Assn.", "F. Supp."); none are ever a first name.
    "cir", "assn", "cf", "seq", "vol", "rev", "supp",
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


TITLE_WORDS = frozenset(TITLE_WORDS)
ORG_SUFFIX_WORDS = frozenset(ORG_SUFFIX_WORDS)
PARTICLES = frozenset(PARTICLES)
STOPWORDS = frozenset(STOPWORDS)
SENTENCE_OPENERS = frozenset(SENTENCE_OPENERS)
NON_NAME = frozenset(NON_NAME)
