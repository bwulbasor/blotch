"""Fetch an English sample of the AI4Privacy pii-masking-200k dataset.

Pulls rows via the Hugging Face datasets-server API (no auth) and keeps the
English ones, saving {source_text, privacy_mask} records to
benchmarks/data/ai4privacy_en.json (git-ignored, downloaded on demand).

    python -m benchmarks.fetch_ai4privacy --n 2000
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request

_HERE = os.path.dirname(__file__)
_API = ("https://datasets-server.huggingface.co/rows"
        "?dataset=ai4privacy/pii-masking-200k&config=default&split=train")


def fetch(n: int = 2000) -> str:
    out = []
    offset = 0
    while len(out) < n and offset < n * 4:
        url = f"{_API}&offset={offset}&length=100"
        req = urllib.request.Request(url, headers={"User-Agent": "censorbot-eval/0.1"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            rows = json.loads(resp.read().decode("utf-8")).get("rows", [])
        if not rows:
            break
        for r in rows:
            row = r["row"]
            if row.get("language") == "en":
                out.append({"source_text": row["source_text"],
                            "privacy_mask": row["privacy_mask"]})
        offset += 100
        time.sleep(0.2)
        print(f"  fetched offset {offset}, kept {len(out)} English rows", end="\r")

    os.makedirs(os.path.join(_HERE, "data"), exist_ok=True)
    path = os.path.join(_HERE, "data", "ai4privacy_en.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out[:n], fh)
    print(f"\nsaved {min(len(out), n)} English rows -> {path}")
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    fetch(ap.parse_args().n)
