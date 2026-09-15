"""Download the evaluation corpus from public sources, sorted by category.

Content lands in ``<repo>/corpus/<category>/<id>.txt`` (git-ignored) with a
``corpus/index.json`` recording provenance. Only public-domain literature and
public-figure / public-reference Wikipedia articles are fetched; nothing is
committed. Re-run any time:

    python -m evaluation.fetch_corpus
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request

_HERE = os.path.dirname(__file__)
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
CORPUS_DIR = os.path.join(_ROOT, "corpus")
_UA = {"User-Agent": "censorbot-eval/0.1 (research; local PII-detection testing)"}


def _get(url: str, timeout: float = 60.0) -> str:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _wikipedia_extract(title: str) -> str:
    params = urllib.parse.urlencode({
        "action": "query", "format": "json", "prop": "extracts",
        "explaintext": "1", "redirects": "1", "titles": title,
    })
    data = json.loads(_get("https://en.wikipedia.org/w/api.php?" + params))
    pages = data["query"]["pages"]
    return next(iter(pages.values())).get("extract", "")


def _clean_gutenberg(text: str) -> str:
    """Strip the Project Gutenberg header/footer boilerplate if present."""
    start = text.find("*** START OF")
    if start != -1:
        text = text[text.find("\n", start) + 1:]
    end = text.find("*** END OF")
    if end != -1:
        text = text[:end]
    return text.strip()


def fetch(manifest_path: str | None = None) -> list[dict]:
    manifest_path = manifest_path or os.path.join(_HERE, "corpus_manifest.json")
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)

    index: list[dict] = []
    for src in manifest["sources"]:
        category = src["category"]
        out_dir = os.path.join(CORPUS_DIR, category)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, src["id"] + ".txt")
        try:
            if src["kind"] == "wikipedia":
                text = _wikipedia_extract(src["title"])
            else:
                text = _clean_gutenberg(_get(src["url"]))
            if "max_chars" in src:
                text = text[: src["max_chars"]]
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(text)
            index.append({**{k: src[k] for k in ("id", "category", "license")},
                          "path": os.path.relpath(out_path, _ROOT),
                          "chars": len(text), "status": "ok"})
            print(f"  ok   {src['id']:<28} {len(text):>8} chars -> {category}/")
        except Exception as exc:  # noqa: BLE001 - report and continue
            index.append({"id": src["id"], "category": category, "status": f"error: {exc}"})
            print(f"  FAIL {src['id']:<28} {exc}")

    os.makedirs(CORPUS_DIR, exist_ok=True)
    with open(os.path.join(CORPUS_DIR, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)
    ok = sum(1 for e in index if e.get("status") == "ok")
    print(f"\nfetched {ok}/{len(index)} sources into {CORPUS_DIR}")
    return index


if __name__ == "__main__":
    fetch()
