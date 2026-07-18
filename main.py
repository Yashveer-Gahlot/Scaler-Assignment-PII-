#!/usr/bin/env python3
"""
main.py — PII Redaction Pipeline Orchestrator
==============================================

Central entry point that orchestrates the full PII redaction workflow:

  1. **Redact** — Parse a .docx prospectus and produce a redacted copy.
  2. **Evaluate** — Run the stratified evaluation suite and report metrics.
  3. **Full** — Execute both in sequence (default).

Auto-Discovery
--------------
If ``--input`` is not provided, the script automatically scans the current
working directory for ``.docx`` files, ignoring any whose name contains
"redacted" (case-insensitive) to prevent re-processing its own output.

Usage
-----
    # Auto-discover and redact the .docx in the current directory
    $ python main.py --mode redact

    # Explicit input
    $ python main.py --mode redact --input Prospectus.docx --output Clean.docx

    # Full pipeline: evaluate engine, then auto-discover and redact
    $ python main.py --mode full

    # Evaluate only (no document required)
    $ python main.py --mode evaluate

    # Smoke test the engine on inline text
    $ python main.py --mode smoke

Author : Orchestrator Team
License: MIT
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

# ──────────────────────────────────────────────
# §1  Lazy Imports (avoid loading spaCy until needed)
# ──────────────────────────────────────────────


def _import_engine():
    """Deferred import of engine module."""
    from src.pii_redactor.engine import RedactionPipeline, RedactionResult, create_pipeline

    return create_pipeline, RedactionResult


def _import_parser():
    """Deferred import of parser module."""
    from src.pii_redactor.parser import redact_document, RedactionStats

    return redact_document, RedactionStats


def _import_evaluator():
    """Deferred import of evaluator module."""
    from src.pii_redactor.evaluator import (
        EvaluationReport,
        run_evaluation,
        format_markdown_report,
        _build_test_corpus,
    )

    return run_evaluation, format_markdown_report, _build_test_corpus, EvaluationReport


# ──────────────────────────────────────────────
# §2  Mode Handlers
# ──────────────────────────────────────────────

def _run_smoke() -> bool:
    """Quick smoke test: redact a synthetic paragraph and verify determinism.

    Returns
    -------
    bool
        ``True`` if all assertions pass.
    """
    create_pipeline, _ = _import_engine()

    print("═" * 60)
    print("  SMOKE TEST — Hybrid PII Redaction Engine")
    print("═" * 60)
    print()

    pipe = create_pipeline()
    sample = (
        "Mr. Kushal Subbayya Hegde, Director of KSH International Limited, "
        "was born on 15/03/1990 (DOB). His PAN is ABCPK1234Z and Aadhaar "
        "number is 2345 6789 0123. Contact: +91 98765 43210 or "
        "kushal.hegde@example.com. Filing date: 01/07/2026."
    )

    result = pipe.redact(sample)
    print("Original:")
    print(f"  {sample[:100]}…\n")
    print("Redacted:")
    print(f"  {result.redacted_text[:100]}…\n")
    print(f"Entities redacted: {result.entity_count}")
    print(f"Breakdown: {result.summary()}")

    # Determinism check.
    r2 = pipe.redact("Kushal Subbayya Hegde signed the final documents.")
    first = [e for e in result.entries if e.original == "Kushal Subbayya Hegde"]
    second = [e for e in r2.entries if e.original == "Kushal Subbayya Hegde"]

    if first and second:
        assert first[0].replacement == second[0].replacement, "Determinism violated!"
        print(f"\n✅ Determinism check passed: '{first[0].original}' → "
              f"'{first[0].replacement}' (stable across calls)")
    else:
        print("\n⚠  Could not verify determinism (name not detected).")
        return False

    # Protected org check.
    assert "KSH International Limited" in result.redacted_text, (
        "Protected org was incorrectly redacted!"
    )
    print("✅ Org protection check passed: 'KSH International Limited' preserved")

    # Filing date check (should NOT be redacted — no birth context).
    assert "01/07/2026" in result.redacted_text, (
        "Filing date was incorrectly redacted!"
    )
    print("✅ Date filtering check passed: filing date '01/07/2026' preserved")

    print("\n✅ All smoke tests passed.")
    return True


def _run_evaluate() -> bool:
    """Execute the stratified evaluation suite and print the Markdown report.

    Returns
    -------
    bool
        ``True`` if the quality gate passes (Micro-F1 ≥ 50%).
    """
    create_pipeline, _ = _import_engine()
    run_evaluation, format_markdown_report, _build_test_corpus, _ = _import_evaluator()

    print("═" * 60)
    print("  EVALUATION SUITE — Stratified PII Detection Metrics")
    print("═" * 60)

    print("\n🔧 Initialising pipeline…")
    pipeline = create_pipeline(score_threshold=0.50)
    print("   Pipeline ready.\n")

    test_cases = _build_test_corpus()
    print(f"📋 Loaded {len(test_cases)} test cases.\n")

    report = run_evaluation(pipeline, test_cases, iou_threshold=0.5, verbose=True)
    md_report = format_markdown_report(report)

    print("\n" + "═" * 60)
    print(md_report)
    print("═" * 60)

    if report.micro_f1 < 0.50:
        print(
            "\n⚠  Quality gate FAILED: Micro-F1 < 50%.",
            file=sys.stderr,
        )
        return False

    print(f"\n✅ Quality gate PASSED: Micro-F1 = {report.micro_f1:.1%}")
    return True


def _run_redact(input_path: str, output_path: Optional[str]) -> bool:
    """Parse and redact a .docx document.

    Parameters
    ----------
    input_path:
        Path to the source Word document.
    output_path:
        Path for the redacted output (defaults to ``Redacted_Prospectus.docx``).

    Returns
    -------
    bool
        ``True`` if redaction completes successfully.
    """
    redact_document, _ = _import_parser()

    print("═" * 60)
    print("  DOCUMENT REDACTION — Run-Level DOCX Parser")
    print("═" * 60)
    print()

    try:
        stats = redact_document(input_path, output_path)
        return stats.entities_redacted > 0
    except FileNotFoundError as exc:
        print(f"\n❌ File Not Found:\n   {exc}", file=sys.stderr)
        return False
    except ValueError as exc:
        print(f"\n❌ Invalid Input:\n   {exc}", file=sys.stderr)
        return False
    except RuntimeError as exc:
        print(f"\n❌ Processing Error:\n   {exc}", file=sys.stderr)
        return False


def _run_full(input_path: Optional[str], output_path: Optional[str]) -> bool:
    """Execute the complete pipeline: evaluate → redact.

    Parameters
    ----------
    input_path:
        Path to the .docx file. If ``None``, only evaluation runs.
    output_path:
        Path for the redacted output.

    Returns
    -------
    bool
        ``True`` if all stages complete successfully.
    """
    wall_start: float = time.perf_counter()

    # Stage 1: Evaluation.
    print("\n┌─────────────────────────────────────────────┐")
    print("│  Stage 1/2: Engine Evaluation               │")
    print("└─────────────────────────────────────────────┘\n")
    eval_ok: bool = _run_evaluate()

    # Stage 2: Document Redaction (if input provided).
    if input_path:
        print("\n\n┌─────────────────────────────────────────────┐")
        print("│  Stage 2/2: Document Redaction              │")
        print("└─────────────────────────────────────────────┘\n")
        redact_ok: bool = _run_redact(input_path, output_path)
    else:
        print("\n\nℹ  No input document provided — skipping redaction stage.")
        print("   Use --input <path.docx> to redact a document.\n")
        redact_ok = True

    elapsed: float = time.perf_counter() - wall_start

    # Final summary.
    print("\n" + "═" * 60)
    print("  PIPELINE COMPLETE")
    print("═" * 60)
    print(f"  Evaluation : {'✅ PASSED' if eval_ok else '❌ FAILED'}")
    if input_path:
        print(f"  Redaction  : {'✅ DONE' if redact_ok else '❌ FAILED'}")
    print(f"  Total time : {elapsed:.2f}s")
    print("═" * 60)

    return eval_ok and redact_ok


# ──────────────────────────────────────────────
# §3  CLI Argument Parser
# ──────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "PII Redaction Pipeline — Orchestrator for SEBI Prospectus documents.\n"
            "Combines a Hybrid NER Engine (spaCy + Presidio + custom regex) with\n"
            "a deterministic Faker-based anonymizer and a stratified evaluator."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --mode full --input Prospectus.docx\n"
            "  python main.py --mode evaluate\n"
            "  python main.py --mode redact --input Prospectus.docx --output Clean.docx\n"
            "  python main.py --mode smoke\n"
        ),
    )

    parser.add_argument(
        "--mode",
        choices=["full", "evaluate", "redact", "smoke"],
        default="full",
        help=(
            "Execution mode. "
            "'full' = evaluate + redact (default). "
            "'evaluate' = run evaluation suite only. "
            "'redact' = redact a document only. "
            "'smoke' = quick engine smoke test."
        ),
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        default=None,
        dest="input_path",
        help=(
            "Path to the source .docx file. If omitted, the script "
            "auto-discovers .docx files in the current directory "
            "(ignoring files containing 'redacted')."
        ),
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        dest="output_path",
        help=(
            "Path for the redacted output file. "
            "Defaults to 'Redacted_Prospectus.docx' in the input directory."
        ),
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float,
        default=0.50,
        help="Minimum confidence score for PII detection (default: 0.50).",
    )

    return parser


# ──────────────────────────────────────────────
# §4  Auto-Discovery
# ──────────────────────────────────────────────

def _discover_docx(search_dir: Optional[Path] = None) -> Optional[str]:
    """Scan a directory for a usable .docx file.

    Ignores filenames containing 'redacted' (case-insensitive) to
    prevent the pipeline from accidentally re-processing its own output.
    Also ignores hidden files and temporary Word lock files (~$...).

    Parameters
    ----------
    search_dir:
        Directory to scan.  Defaults to the current working directory.

    Returns
    -------
    Optional[str]
        Path to the discovered file, or ``None`` if no candidates found.
    """
    directory: Path = search_dir or (Path.cwd() / "data" / "input")

    # Collect all .docx files, excluding redacted outputs and temp files.
    candidates: List[Path] = sorted(
        p for p in directory.glob("*.docx")
        if p.is_file()
        and "redacted" not in p.stem.lower()
        and not p.name.startswith("~$")
        and not p.name.startswith(".")
    )

    if not candidates:
        print(
            "\n❌ Auto-Discovery Failed:\n"
            f"   No .docx files found in '{directory}'.\n"
            "   Files containing 'redacted' in the name are excluded.\n"
            "   Please provide an explicit path: --input <file.docx>\n",
            file=sys.stderr,
        )
        return None

    selected: Path = candidates[0]

    if len(candidates) == 1:
        print(f"📂 Auto-discovered: {selected.name}")
    else:
        print(f"📂 Auto-discovered {len(candidates)} .docx files:")
        for idx, c in enumerate(candidates):
            marker: str = "  →" if idx == 0 else "   "
            print(f"{marker} {c.name}")
        print(f"\n⚠  Multiple files found — selecting '{selected.name}'.")
        print("   Use --input <file.docx> to choose a specific file.\n")

    return str(selected)


# ──────────────────────────────────────────────
# §5  Main Entry Point
# ──────────────────────────────────────────────

def main() -> None:
    """Parse arguments, auto-discover input if needed, and dispatch."""
    parser = _build_parser()
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║     PII REDACTION PIPELINE — SEBI Prospectus Engine     ║")
    print("║     Local · Privacy-First · Deterministic               ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # ── Auto-discover input if needed ──────────────────────────────
    # Modes that require a document: 'redact' and 'full'.
    needs_document: bool = args.mode in ("redact", "full")

    if needs_document and not args.input_path:
        discovered: Optional[str] = _discover_docx()
        if discovered is None:
            # Auto-discovery found nothing.
            if args.mode == "redact":
                # Redact mode with no file → fatal.
                sys.exit(2)
            else:
                # Full mode → run evaluation only, skip redaction.
                print("ℹ  Proceeding with evaluation only (no document to redact).\n")
        args.input_path = discovered

    # ── Dispatch ───────────────────────────────────────────────────
    success: bool = False
    try:
        if args.mode == "smoke":
            success = _run_smoke()
        elif args.mode == "evaluate":
            success = _run_evaluate()
        elif args.mode == "redact":
            success = _run_redact(args.input_path, args.output_path)
        elif args.mode == "full":
            success = _run_full(args.input_path, args.output_path)
    except KeyboardInterrupt:
        print("\n\n⏹  Interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"\n❌ Unexpected error: {exc}", file=sys.stderr)
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
