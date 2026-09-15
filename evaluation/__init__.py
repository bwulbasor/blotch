"""Evaluation subsystem for censorbot.

* :mod:`.synth` - generates synthetic documents with **ground-truth PII spans**
  (the only way to compute real precision/recall/F1), including a bank of hard
  cases: names that are common words, Unicode names, international phones/IBANs,
  ambiguous numbers, multi-line and adjacent entities.
* :mod:`.evaluate` - scores detection against ground truth.
* :mod:`.fetch_corpus` - downloads public-domain / public-record documents into a
  git-ignored corpus, sorted by domain (never committed: copyright + privacy).
* :mod:`.run_wild` - runs detection over the fetched corpus for robustness.
"""
