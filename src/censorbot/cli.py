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
from .policy import BUILTIN, get_policy, load_policy_file
from .rehydrate import restore
from .vault import Vault


def _policy(args):
    """Resolve a built-in policy name or a --policy-file into a Policy."""
    if getattr(args, "policy_file", None):
        return load_policy_file(args.policy_file)
    return get_policy(args.policy)


def _read(path: str) -> str:
    if os.path.splitext(path)[1].lower() in (".txt", ".md", ".text", ".pdf", ".docx"):
        return load_text(path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _cmd_inspect(args) -> int:
    text = _read(args.file)
    policy = _policy(args)
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
    from .reidrisk import assess
    risk = assess(result.sanitized_text)
    if risk.level.value != "none":
        print(f"\n[re-id risk] {risk.summary()}", file=sys.stderr)
        for f in risk.findings:
            print(f"    {f.category:<18} {f.text!r}", file=sys.stderr)
    return 0


def _cmd_risk(args) -> int:
    from .reidrisk import assess
    text = _read(args.file)
    # assess the sanitized version - what would actually leave the device
    result = sanitize(text, _policy(args), use_spacy=not args.no_spacy)
    risk = assess(result.sanitized_text)
    print(risk.summary())
    for f in risk.findings:
        print(f"  {f.category:<18} {f.text!r}")
    return 0


def _cmd_sanitize(args) -> int:
    text = _read(args.file)
    policy = _policy(args)
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


def _cmd_review(args) -> int:
    from .review import render_review_html
    text = _read(args.file)
    policy = _policy(args)
    html_out = render_review_html(text, policy, use_spacy=not args.no_spacy)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    print(f"Review page -> {args.out}")
    return 0


def _cmd_batch(args) -> int:
    from .docwriter import VerificationError, write_document
    from .ingest import SUPPORTED
    policy = _policy(args)
    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(args.vaultdir, exist_ok=True)
    if not args.passphrase and not args.allow_plaintext:
        print("[error] batch needs --passphrase (or --allow-plaintext) for vaults",
              file=sys.stderr)
        return 2

    files: list[str] = []
    for root, _dirs, names in os.walk(args.indir):
        for name in names:
            if os.path.splitext(name)[1].lower() in SUPPORTED:
                files.append(os.path.join(root, name))
    if not files:
        print(f"no supported files ({', '.join(SUPPORTED)}) under {args.indir}")
        return 0

    done = blocked = failed = 0
    total_entities = 0
    for path in sorted(files):
        rel = os.path.relpath(path, args.indir)
        stem = os.path.splitext(rel)[0].replace(os.sep, "__")
        try:
            text = load_text(path)
            result = sanitize(text, policy, use_spacy=not args.no_spacy)
        except Exception as exc:  # noqa: BLE001
            print(f"  FAIL   {rel}: {exc}", file=sys.stderr)
            failed += 1
            continue
        report = result.leak_report
        if report and report.blocked and not args.force:
            print(f"  BLOCK  {rel}: {report.summary()}", file=sys.stderr)
            blocked += 1
            continue
        out_ext = os.path.splitext(rel)[1] if not args.txt else ".txt"
        out_path = os.path.join(args.outdir, stem + out_ext)
        vault_path = os.path.join(args.vaultdir, stem + ".cbv")
        try:
            write_document(out_path, result.sanitized_text, vault=result.vault,
                           verify=True)
        except VerificationError as exc:
            print(f"  BLOCK  {rel}: output failed verification: {exc}", file=sys.stderr)
            blocked += 1
            continue
        result.vault.save(vault_path, passphrase=args.passphrase,
                          allow_plaintext=args.allow_plaintext)
        total_entities += result.entity_count()
        done += 1
        print(f"  ok     {rel} -> {os.path.basename(out_path)} "
              f"({result.entity_count()} entities)")

    print(f"\nbatch: {done} sanitized, {blocked} blocked, {failed} failed; "
          f"{total_entities} entities total")
    return 1 if (blocked or failed) else 0


def _cmd_serve(args) -> int:
    from .server import serve
    serve(host=args.host, port=args.port)
    return 0


def _cmd_benchmark(args) -> int:
    from .benchmark import run_benchmark
    policy = _policy(args)
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
    common.add_argument("--policy-file",
                        help="path to a custom policy JSON (overrides --policy)")
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

    rev = sub.add_parser("review", parents=[common],
                         help="generate an HTML review preview of what will be hidden")
    rev.add_argument("file")
    rev.add_argument("--out", required=True, help="path for the HTML review page")
    rev.set_defaults(func=_cmd_review)

    bat = sub.add_parser("batch", parents=[common],
                         help="sanitise every supported file in a directory tree")
    bat.add_argument("indir")
    bat.add_argument("--outdir", required=True, help="directory for sanitized documents")
    bat.add_argument("--vaultdir", required=True, help="directory for per-file vaults")
    bat.add_argument("--passphrase", help="encrypt every vault with this passphrase")
    bat.add_argument("--allow-plaintext", action="store_true",
                     help="permit unencrypted vaults (not recommended)")
    bat.add_argument("--txt", action="store_true",
                     help="always write .txt output instead of the source format")
    bat.add_argument("--force", action="store_true",
                     help="write outputs even if the leak scan blocks")
    bat.set_defaults(func=_cmd_batch)

    srv = sub.add_parser("serve", help="run the local gateway HTTP daemon")
    srv.add_argument("--host", default="127.0.0.1", help="bind address (loopback only)")
    srv.add_argument("--port", type=int, default=8723)
    srv.set_defaults(func=_cmd_serve)

    bench = sub.add_parser("benchmark", parents=[common],
                           help="run the built-in detection/round-trip benchmark")
    bench.set_defaults(func=_cmd_benchmark)

    risk = sub.add_parser("risk", parents=[common],
                          help="assess residual re-identification risk (advisory)")
    risk.add_argument("file")
    risk.set_defaults(func=_cmd_risk)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
