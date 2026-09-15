import io
import json
from contextlib import redirect_stdout

from censorbot.cli import main


def test_inspect_json(tmp_path):
    f = tmp_path / "n.txt"
    f.write_text("Alejandro Martinez, a.martinez@example.com, in Berlin.",
                 encoding="utf-8")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["inspect", str(f), "--policy", "personal", "--no-spacy", "--json"])
    assert rc == 0
    data = json.loads(buf.getvalue())
    assert data["policy"] == "personal"
    assert data["count"] >= 2
    types = {e["type"] for e in data["entities"]}
    assert "PERSON" in types and "EMAIL" in types
    assert "clean" in data["leak"]
    assert "level" in data["reid_risk"]
