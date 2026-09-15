"""Command-line interface.

    censorbot inspect  <file> [--policy P]
    censorbot sanitize <file> --out OUT --vault V [--policy P] [--passphrase PW]
    censorbot restore  <file> --vault V [--passphrase PW] [--out OUT]

All processing is local. ``sanitize`` writes the pseudonymised document and an
(encrypted) vault; ``restore`` rehydrates a model's response using that vault.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .ingest import load_text
from .pipeline import preview, sanitize
from .policy import BUILTIN, get_policy
from .rehydrate import restore
from .vault import Vault


def _read(path: str) -> str:
    if os.path.splitext(path)[1].lower() in (".txt", ".md", ".text", ".pdf", ".docx"):
        return load_text(path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _cmd_inspect(args) -> int:
    text = _read(args.file)
    policy = get_policy(args.policy)
    result = sanitize(text, policy, use_spacy=not args.no_spacy)
    print(f"Policy: {policy.name}")
    print(f"Detected {result.entity_count()} entity/entities "
          f"({result.num_tokenized} tokenized, {result.num_redacted} redacted)\n")
    for ent in sorted(result.entities, key=lambda e: (e.entity_type.value, e.index)):
        from .tokens import make_token
        token = make_token(ent.entity_type, ent.index)
        conf = max((s.confidence for s in ent.members), default=0.0)
        print(f"  {token:<20} {ent.entity_type.value:<14} "
              f"conf={conf:.2f}  {ent.canonical!r}")
    if result.leak_report and not result.leak_report.clean:
        print(f"\n[leak-scan] {result.leak_report.summary()}", file=sys.stderr)
    return 0


def _cmd_sanitize(args) -> int:
    text = _read(args.file)
    policy = get_policy(args.policy)
    result = sanitize(text, policy, use_spacy=not args.no_spacy)

    report = result.leak_report
    if report and report.blocked and not args.force:
        print(f"[BLOCKED] {report.summary()}", file=sys.stderr)
        print("Refusing to write output. Re-run with --force to override "
              "(the residual material will be recorded).", file=sys.stderr)
        return 2

    from .docwriter import VerificationError, write_document
    try:
        write_document(args.out, result.sanitized_text, vault=result.vault, verify=True)
    except VerificationError as exc:
        print(f"[BLOCKED] regenerated output failed verification: {exc}", file=sys.stderr)
        return 3
    result.vault.save(args.vault, passphrase=args.passphrase,
                      allow_plaintext=args.allow_plaintext)

    enc = "encrypted" if args.passphrase else "PLAINTEXT"
    print(f"Sanitized {result.entity_count()} entity/entities -> {args.out}")
    print(f"Vault ({enc}, session {result.vault.session_id}) -> {args.vault}")
    if report and report.blocked:
        print(f"[WARNING] leak-scan not clean but --force used: {report.summary()}",
              file=sys.stderr)
    return 0


def _cmd_serve(args) -> int:
    from .server import serve
    serve(host=args.host, port=args.port)
    return 0


def _cmd_benchmark(args) -> int:
    from .benchmark import run_benchmark
    policy = get_policy(args.policy)
    result = run_benchmark(policy, use_spacy=not args.no_spacy)
    print(f"Policy: {policy.name}")
    print(result.report())
    # non-zero exit if anything leaked - useful in CI
    return 1 if result.leaked else 0


def _cmd_restore(args) -> int:
    text = _read(args.file)
    vault = Vault.load(args.vault, passphrase=args.passphrase)
    result = restore(text, vault)
    out = result.text
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Restored -> {args.out}")
    else:
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
    if result.has_anomalies:
        print(f"[response-check] {result.summary()}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="censorbot", description=__doc__)
    p.add_argument("--version", action="version", version=f"censorbot {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--policy", default="personal",
                        choices=sorted(BUILTIN), help="privacy policy (default: personal)")
    common.add_argument("--no-spacy", action="store_true",
                        help="skip spaCy NER even if installed (use heuristics)")

    ins = sub.add_parser("inspect", parents=[common], help="list detected entities")
    ins.add_argument("file")
    ins.set_defaults(func=_cmd_inspect)

    san = sub.add_parser("sanitize", parents=[common], help="pseudonymise a document")
    san.add_argument("file")
    san.add_argument("--out", required=True, help="path for the sanitized text")
    san.add_argument("--vault", required=True, help="path for the token vault")
    san.add_argument("--passphrase", help="encrypt the vault with this passphrase")
    san.add_argument("--allow-plaintext", action="store_true",
                     help="permit writing an unencrypted vault (not recommended)")
    san.add_argument("--force", action="store_true",
                     help="write output even if the leak scan blocks")
    san.set_defaults(func=_cmd_sanitize)

    res = sub.add_parser("restore", help="rehydrate a response using a vault")
    res.add_argument("file")
    res.add_argument("--vault", required=True)
    res.add_argument("--passphrase", help="passphrase if the vault is encrypted")
    res.add_argument("--out", help="write to a file instead of stdout")
    res.set_defaults(func=_cmd_restore)

    srv = sub.add_parser("serve", help="run the local gateway HTTP daemon")
    srv.add_argument("--host", default="127.0.0.1", help="bind address (loopback only)")
    srv.add_argument("--port", type=int, default=8723)
    srv.set_defaults(func=_cmd_serve)

    bench = sub.add_parser("benchmark", parents=[common],
                           help="run the built-in detection/round-trip benchmark")
    bench.set_defaults(func=_cmd_benchmark)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
