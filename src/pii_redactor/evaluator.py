"""
evaluator.py — PII Redaction Engine Evaluation Suite
=====================================================

Stand-alone evaluation script that measures the accuracy, precision,
recall, and F1 score of the Hybrid PII Redaction Pipeline defined in
``engine.py``.

Methodology
-----------
1. A curated set of **synthetic SEBI prospectus paragraphs** is defined,
   each annotated with ground-truth PII spans (entity type + character
   offsets).
2. The engine's detections are compared against ground truth using
   **span-overlap matching** (IoU ≥ 0.5 by default) to tolerate minor
   boundary differences inherent in NER/regex systems.
3. Per-category and aggregate metrics are computed:
   True Positives (TP), False Positives (FP), False Negatives (FN),
   Precision, Recall, F1.
4. Results are printed as a clean **Markdown table** suitable for
   evaluation logging and CI reporting.

Usage
-----
    $ python evaluator.py

    # Prints per-category and aggregate metrics to stdout.

Author : Evaluation Team
License: MIT
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .engine import RedactionPipeline, create_pipeline, RecognizerResult


# ──────────────────────────────────────────────
# §1  Data Structures
# ──────────────────────────────────────────────

@dataclass(frozen=True)
class AnnotatedSpan:
    """A single ground-truth PII annotation.

    Attributes
    ----------
    entity_type:
        Canonical PII category label.
    start:
        Inclusive character offset in the source text.
    end:
        Exclusive character offset in the source text.
    text:
        The literal PII string (for readability / debugging).
    """

    entity_type: str
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class TestCase:
    """A single evaluation example.

    Attributes
    ----------
    name:
        Human-readable identifier for the test scenario.
    text:
        The source paragraph to feed into the engine.
    ground_truth:
        Exhaustive list of PII spans the engine *should* detect.
    description:
        Optional note explaining what the test is stress-testing.
    """

    name: str
    text: str
    ground_truth: Tuple[AnnotatedSpan, ...]
    description: str = ""


@dataclass
class CategoryMetrics:
    """Accumulates TP / FP / FN for a single entity category."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def support(self) -> int:
        """Total ground-truth positives."""
        return self.tp + self.fn


# ──────────────────────────────────────────────
# §2  Entity-Type Equivalence Groups
# ──────────────────────────────────────────────

# The engine may label an entity with a slightly different type than our
# ground truth (e.g., spaCy's PERSON vs. a regex PERSON).  These groups
# define which labels are considered equivalent during matching.

_EQUIVALENCE_GROUPS: Dict[str, FrozenSet[str]] = {
    "PERSON":           frozenset({"PERSON"}),
    "EMAIL_ADDRESS":    frozenset({"EMAIL_ADDRESS"}),
    "IN_PHONE_NUMBER":  frozenset({"IN_PHONE_NUMBER", "PHONE_NUMBER"}),
    "IN_PAN":           frozenset({"IN_PAN"}),
    "IN_AADHAAR":       frozenset({"IN_AADHAAR"}),
    "CREDIT_CARD":      frozenset({"CREDIT_CARD"}),
    "IP_ADDRESS":       frozenset({"IP_ADDRESS"}),
    "US_SSN":           frozenset({"US_SSN"}),
    "LOCATION":         frozenset({"LOCATION", "LOC", "GPE"}),
    "ORGANIZATION":     frozenset({"ORGANIZATION", "ORG"}),
    "DATE_TIME":        frozenset({"DATE_TIME"}),
}


def _types_match(gt_type: str, det_type: str) -> bool:
    """Check if a ground-truth type and a detected type are equivalent."""
    group: FrozenSet[str] = _EQUIVALENCE_GROUPS.get(gt_type, frozenset({gt_type}))
    return det_type in group


# ──────────────────────────────────────────────
# §3  Span Overlap Matching
# ──────────────────────────────────────────────

def _iou(start_a: int, end_a: int, start_b: int, end_b: int) -> float:
    """Compute Intersection-over-Union for two character spans.

    Parameters
    ----------
    start_a, end_a:
        Span A boundaries (inclusive start, exclusive end).
    start_b, end_b:
        Span B boundaries.

    Returns
    -------
    float
        IoU value in [0.0, 1.0].
    """
    inter_start: int = max(start_a, start_b)
    inter_end: int = min(end_a, end_b)
    intersection: int = max(0, inter_end - inter_start)

    union: int = (end_a - start_a) + (end_b - start_b) - intersection
    return intersection / union if union > 0 else 0.0


def match_detections(
    ground_truth: Tuple[AnnotatedSpan, ...],
    detections: List[RecognizerResult],
    source_text: str,
    iou_threshold: float = 0.5,
) -> Tuple[List[Tuple[AnnotatedSpan, RecognizerResult]], List[AnnotatedSpan], List[RecognizerResult]]:
    """Match engine detections against ground-truth annotations.

    Uses a greedy best-IoU matching strategy:
    1. For each ground-truth span, find the detection with the highest
       IoU that also has a compatible entity type.
    2. If IoU ≥ ``iou_threshold``, count as a True Positive.
    3. Unmatched ground-truth spans → False Negatives.
    4. Unmatched detections → False Positives.

    Parameters
    ----------
    ground_truth:
        Annotated PII spans.
    detections:
        Raw ``RecognizerResult`` list from the engine (post-filtering).
    source_text:
        The original text (used for debug display of FP spans).
    iou_threshold:
        Minimum IoU to accept a match.

    Returns
    -------
    matched:
        List of (ground_truth_span, detection) pairs (TPs).
    false_negatives:
        Ground-truth spans with no matching detection.
    false_positives:
        Detections with no matching ground-truth span.
    """
    matched: List[Tuple[AnnotatedSpan, RecognizerResult]] = []
    used_detections: Set[int] = set()
    unmatched_gt: List[AnnotatedSpan] = []

    for gt in ground_truth:
        best_iou: float = 0.0
        best_idx: int = -1

        for idx, det in enumerate(detections):
            if idx in used_detections:
                continue
            if not _types_match(gt.entity_type, det.entity_type):
                continue

            overlap: float = _iou(gt.start, gt.end, det.start, det.end)
            if overlap > best_iou:
                best_iou = overlap
                best_idx = idx

        if best_iou >= iou_threshold and best_idx != -1:
            matched.append((gt, detections[best_idx]))
            used_detections.add(best_idx)
        else:
            unmatched_gt.append(gt)

    false_positives: List[RecognizerResult] = [
        det for idx, det in enumerate(detections) if idx not in used_detections
    ]

    return matched, unmatched_gt, false_positives


# ──────────────────────────────────────────────
# §4  Test Corpus — Synthetic SEBI Prospectus Data
# ──────────────────────────────────────────────

def _build_test_corpus() -> List[TestCase]:
    """Construct the evaluation corpus.

    Each test case simulates a section of an Indian SEBI prospectus and
    is annotated with ground-truth PII spans.  Cases include both genuine
    PII targets and *false-positive bait* — legitimate financial/legal
    text that naive detectors often mis-flag.

    Returns
    -------
    List[TestCase]
        Ordered list of evaluation scenarios.
    """
    cases: List[TestCase] = []

    # ── Case 1: Director bio with mixed PII ────────────────────────
    text_1 = (
        "Mr. Arjun Ramesh Kulkarni, aged 47 years, has been appointed as "
        "the Managing Director of KSH International Limited with effect from "
        "April 15, 2024. He was born on 12/08/1977 (DOB) in Pune, Maharashtra. "
        "His PAN is BKMPK9821R and Aadhaar number is 4532 8821 7743. "
        "Contact: +91 99887 76655 or arjun.kulkarni@kshintl.com."
    )
    cases.append(TestCase(
        name="Director Bio — Mixed PII",
        text=text_1,
        ground_truth=(
            AnnotatedSpan("PERSON", 4, 25, "Arjun Ramesh Kulkarni"),
            # "KSH International Limited" is protected — NOT expected.
            # "April 15, 2024" is a filing date (no birth context) — NOT expected.
            AnnotatedSpan("DATE_TIME", 163, 173, "12/08/1977"),  # DOB context
            AnnotatedSpan("LOCATION", 183, 187, "Pune"),
            AnnotatedSpan("IN_PAN", 213, 223, "BKMPK9821R"),
            AnnotatedSpan("IN_AADHAAR", 246, 260, "4532 8821 7743"),
            AnnotatedSpan("IN_PHONE_NUMBER", 271, 286, "+91 99887 76655"),
            AnnotatedSpan("EMAIL_ADDRESS", 290, 316, "arjun.kulkarni@kshintl.com"),
        ),
        description=(
            "Tests person detection, DOB-gated date filtering, org protection, "
            "Indian PAN/Aadhaar/phone, and email."
        ),
    ))

    # ── Case 2: Financial table row with false-positive bait ───────
    text_2 = (
        "As per the audited financial statements for the year ended "
        "March 31, 2025, the total revenue stood at ₹4,200.00 million. "
        "The company raised ₹750 crore through its IPO under Section 32 "
        "of the Companies Act, 2013. SEBI registration number: INZ000012345. "
        "For queries, contact Priya Sharma at priya.sharma@sebi.gov.in or "
        "call +91-22-2644-9000."
    )
    cases.append(TestCase(
        name="Financial Data — False Positive Bait",
        text=text_2,
        ground_truth=(
            # "March 31, 2025" — filing date, no birth context → NOT expected.
            # "₹4,200.00 million", "₹750 crore", "Section 32" → NOT PII.
            AnnotatedSpan("PERSON", 273, 285, "Priya Sharma"),
            AnnotatedSpan("EMAIL_ADDRESS", 289, 313, "priya.sharma@sebi.gov.in"),
            AnnotatedSpan("IN_PHONE_NUMBER", 322, 338, "+91-22-2644-9000"),
        ),
        description=(
            "Stress-tests that monetary values, section references, and "
            "non-birth dates are NOT flagged as PII."
        ),
    ))

    # ── Case 3: Board member roster ────────────────────────────────
    text_3 = (
        "Board of Directors:\n"
        "1. Vikram Singh Chauhan (DIN: 08123456), Chairman. "
        "Born on 05-Jan-1965 (date of birth). PAN: AABPC5678D.\n"
        "2. Meera Nair (DIN: 09876543), Independent Director. "
        "Email: meera.nair@directorsboard.co.in. Phone: 9876543210.\n"
        "3. Rajesh Kumar Verma, CFO. SSN: 312-56-7890. "
        "IP address on file: 10.0.45.201."
    )
    cases.append(TestCase(
        name="Board Roster — Multi-Entity Mix",
        text=text_3,
        ground_truth=(
            AnnotatedSpan("PERSON", 23, 43, "Vikram Singh Chauhan"),
            AnnotatedSpan("DATE_TIME", 79, 90, "05-Jan-1965"),  # birth context
            AnnotatedSpan("IN_PAN", 113, 123, "AABPC5678D"),
            AnnotatedSpan("PERSON", 128, 138, "Meera Nair"),
            AnnotatedSpan("EMAIL_ADDRESS", 185, 216, "meera.nair@directorsboard.co.in"),
            AnnotatedSpan("IN_PHONE_NUMBER", 225, 235, "9876543210"),
            AnnotatedSpan("PERSON", 240, 258, "Rajesh Kumar Verma"),
            AnnotatedSpan("US_SSN", 270, 281, "312-56-7890"),
            AnnotatedSpan("IP_ADDRESS", 303, 314, "10.0.45.201"),
        ),
        description=(
            "Tests multi-person detection in a list format, with mixed "
            "Indian and US PII types."
        ),
    ))

    # ── Case 4: Credit card with Luhn validation ───────────────────
    text_4 = (
        "Payment details for subscription:\n"
        "Subscriber: Deepa Venkatesh Iyer\n"
        "Valid Card: 4539 1488 0343 6467\n"
        "Invalid Card: 1234 5678 9012 3456\n"
        "Billing address: 42, MG Road, Bengaluru 560001."
    )
    cases.append(TestCase(
        name="Credit Card — Luhn Validation",
        text=text_4,
        ground_truth=(
            AnnotatedSpan("PERSON", 46, 66, "Deepa Venkatesh Iyer"),
            AnnotatedSpan("CREDIT_CARD", 79, 98, "4539 1488 0343 6467"),
            # "1234 5678 9012 3456" fails Luhn → NOT expected.
            AnnotatedSpan("LOCATION", 163, 172, "Bengaluru"),
        ),
        description=(
            "Validates that only Luhn-valid credit card numbers are detected. "
            "The invalid card (1234 5678 9012 3456) must NOT be flagged."
        ),
    ))

    # ── Case 5: Legal boilerplate with org protection ──────────────
    text_5 = (
        "KSH International Limited (formerly known as KSH Intl Ltd) hereby "
        "confirms compliance with SEBI (Listing Obligations and Disclosure "
        "Requirements) Regulations, 2015. The registered office is at "
        "Plot No. 42, Andheri East, Mumbai 400069. Contact the compliance "
        "officer Sunil Bhatt at sunil.bhatt@ksh.co.in or +91 22 4056 7890."
    )
    cases.append(TestCase(
        name="Legal Boilerplate — Org Protection",
        text=text_5,
        ground_truth=(
            # Both "KSH International Limited" and "KSH Intl Ltd" → protected.
            AnnotatedSpan("LOCATION", 220, 226, "Mumbai"),
            AnnotatedSpan("PERSON", 266, 277, "Sunil Bhatt"),
            AnnotatedSpan("EMAIL_ADDRESS", 281, 302, "sunil.bhatt@ksh.co.in"),
            AnnotatedSpan("IN_PHONE_NUMBER", 306, 322, "+91 22 4056 7890"),
        ),
        description=(
            "Verifies that KSH International Limited and its variations are "
            "excluded from redaction while other PII is caught."
        ),
    ))

    # ── Case 6: Complex Aadhaar + phone format variations ──────────
    text_6 = (
        "KYC Verification Record:\n"
        "Name: Ananya Deshpande\n"
        "Aadhaar: 8765-4321-0987\n"
        "Mobile: +91-98765-43210\n"
        "Alternate: 07012345678\n"
        "Email: ananya.d@verifykyc.in\n"
        "Date of KYC: December 10, 2025."
    )
    cases.append(TestCase(
        name="KYC Record — Format Variations",
        text=text_6,
        ground_truth=(
            AnnotatedSpan("PERSON", 31, 47, "Ananya Deshpande"),
            AnnotatedSpan("IN_AADHAAR", 57, 71, "8765-4321-0987"),
            AnnotatedSpan("IN_PHONE_NUMBER", 80, 95, "+91-98765-43210"),
            AnnotatedSpan("IN_PHONE_NUMBER", 107, 118, "07012345678"),
            AnnotatedSpan("EMAIL_ADDRESS", 126, 147, "ananya.d@verifykyc.in"),
            # "December 10, 2025" — no birth context → NOT expected.
        ),
        description=(
            "Tests Aadhaar with dashes, phone with STD prefix, and confirms "
            "non-birth dates are excluded."
        ),
    ))

    # ── Case 7: Dense paragraph — stress test ─────────────────────
    text_7 = (
        "The promoter, Mr. Karthik Subramanian (PAN: DEXPS4321K, Aadhaar: "
        "3456 7890 1234), born on 22/11/1982 (DOB), resides at 15 Residency "
        "Road, Chennai 600020. He holds 42.5% equity. His wife, Lakshmi "
        "Subramanian (email: lakshmi.s@gmail.com, phone: 9988776655), also "
        "serves as a promoter. Server logs indicate access from 172.16.0.55."
    )
    cases.append(TestCase(
        name="Dense Paragraph — Stress Test",
        text=text_7,
        ground_truth=(
            AnnotatedSpan("PERSON", 18, 37, "Karthik Subramanian"),
            AnnotatedSpan("IN_PAN", 44, 54, "DEXPS4321K"),
            AnnotatedSpan("IN_AADHAAR", 65, 79, "3456 7890 1234"),
            AnnotatedSpan("DATE_TIME", 90, 100, "22/11/1982"),  # DOB context
            AnnotatedSpan("LOCATION", 138, 145, "Chennai"),
            AnnotatedSpan("PERSON", 187, 206, "Lakshmi Subramanian"),
            AnnotatedSpan("EMAIL_ADDRESS", 215, 234, "lakshmi.s@gmail.com"),
            AnnotatedSpan("IN_PHONE_NUMBER", 243, 253, "9988776655"),
            AnnotatedSpan("IP_ADDRESS", 316, 327, "172.16.0.55"),
        ),
        description=(
            "High-density paragraph with 9 distinct PII entities of 6 types. "
            "Tests the engine under realistic prospectus prose."
        ),
    ))

    return cases


# ──────────────────────────────────────────────
# §5  Evaluation Runner
# ──────────────────────────────────────────────

@dataclass
class EvaluationReport:
    """Complete evaluation report across all test cases.

    Attributes
    ----------
    per_category:
        ``{entity_type: CategoryMetrics}`` mapping.
    per_case_details:
        Detailed match/miss info for each test case (for verbose output).
    elapsed_seconds:
        Wall-clock time for the full evaluation run.
    """

    per_category: Dict[str, CategoryMetrics] = field(default_factory=dict)
    per_case_details: List[Dict] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def _ensure_category(self, entity_type: str) -> CategoryMetrics:
        if entity_type not in self.per_category:
            self.per_category[entity_type] = CategoryMetrics()
        return self.per_category[entity_type]

    def record_tp(self, entity_type: str) -> None:
        self._ensure_category(entity_type).tp += 1

    def record_fp(self, entity_type: str) -> None:
        self._ensure_category(entity_type).fp += 1

    def record_fn(self, entity_type: str) -> None:
        self._ensure_category(entity_type).fn += 1

    # ── Aggregates ─────────────────────────────────────────────────

    @property
    def total_tp(self) -> int:
        return sum(m.tp for m in self.per_category.values())

    @property
    def total_fp(self) -> int:
        return sum(m.fp for m in self.per_category.values())

    @property
    def total_fn(self) -> int:
        return sum(m.fn for m in self.per_category.values())

    @property
    def macro_precision(self) -> float:
        vals = [m.precision for m in self.per_category.values() if m.support > 0]
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def macro_recall(self) -> float:
        vals = [m.recall for m in self.per_category.values() if m.support > 0]
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def macro_f1(self) -> float:
        vals = [m.f1 for m in self.per_category.values() if m.support > 0]
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def micro_precision(self) -> float:
        denom = self.total_tp + self.total_fp
        return self.total_tp / denom if denom > 0 else 0.0

    @property
    def micro_recall(self) -> float:
        denom = self.total_tp + self.total_fn
        return self.total_tp / denom if denom > 0 else 0.0

    @property
    def micro_f1(self) -> float:
        p, r = self.micro_precision, self.micro_recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def run_evaluation(
    pipeline: RedactionPipeline,
    test_cases: List[TestCase],
    *,
    iou_threshold: float = 0.5,
    verbose: bool = True,
) -> EvaluationReport:
    """Execute the full evaluation suite.

    Parameters
    ----------
    pipeline:
        An initialised ``RedactionPipeline`` from engine.py.
    test_cases:
        The annotated test corpus.
    iou_threshold:
        Minimum IoU for a detection to count as a TP.
    verbose:
        If ``True``, print per-case details during execution.

    Returns
    -------
    EvaluationReport
        Aggregated metrics across all test cases.
    """
    report: EvaluationReport = EvaluationReport()
    start_time: float = time.perf_counter()

    for case_idx, case in enumerate(test_cases, 1):
        if verbose:
            print(f"\n{'━' * 60}")
            print(f"  Case {case_idx}: {case.name}")
            print(f"{'━' * 60}")
            if case.description:
                print(f"  ℹ  {case.description}")
            print()

        # Run detection.
        detections: List[RecognizerResult] = pipeline.analyze(case.text)

        # Match against ground truth.
        matched, false_negatives, false_positives = match_detections(
            case.ground_truth, detections, case.text, iou_threshold
        )

        # Record metrics.
        case_detail: Dict = {
            "name": case.name,
            "tp": len(matched),
            "fp": len(false_positives),
            "fn": len(false_negatives),
        }

        for gt_span, det in matched:
            report.record_tp(gt_span.entity_type)
            if verbose:
                det_text = case.text[det.start:det.end]
                print(
                    f"  ✅ TP  [{gt_span.entity_type:<18}] "
                    f"expected='{gt_span.text}' ↔ detected='{det_text}' "
                    f"(score={det.score:.2f})"
                )

        for gt_span in false_negatives:
            report.record_fn(gt_span.entity_type)
            if verbose:
                print(
                    f"  ❌ FN  [{gt_span.entity_type:<18}] "
                    f"missed='{gt_span.text}' "
                    f"(offsets {gt_span.start}–{gt_span.end})"
                )

        for det in false_positives:
            det_text = case.text[det.start:det.end]
            report.record_fp(det.entity_type)
            if verbose:
                print(
                    f"  ⚠️  FP  [{det.entity_type:<18}] "
                    f"spurious='{det_text}' "
                    f"(score={det.score:.2f}, offsets {det.start}–{det.end})"
                )

        report.per_case_details.append(case_detail)

        if verbose:
            print(
                f"\n  Summary: TP={case_detail['tp']}  "
                f"FP={case_detail['fp']}  FN={case_detail['fn']}"
            )

    report.elapsed_seconds = time.perf_counter() - start_time
    return report


# ──────────────────────────────────────────────
# §6  Markdown Report Formatter
# ──────────────────────────────────────────────

def format_markdown_report(report: EvaluationReport) -> str:
    """Render the evaluation report as a Markdown table.

    Parameters
    ----------
    report:
        A completed ``EvaluationReport``.

    Returns
    -------
    str
        Multi-line Markdown string with per-category and aggregate rows.
    """
    lines: List[str] = []

    lines.append("")
    lines.append("## PII Redaction Engine — Evaluation Report")
    lines.append("")
    lines.append(f"⏱  **Execution time**: {report.elapsed_seconds:.2f}s")
    lines.append("")

    # ── Per-Case Summary ───────────────────────────────────────────
    lines.append("### Per-Case Results")
    lines.append("")
    lines.append("| # | Test Case | TP | FP | FN |")
    lines.append("|---|-----------|---:|---:|---:|")
    for idx, detail in enumerate(report.per_case_details, 1):
        lines.append(
            f"| {idx} | {detail['name']} "
            f"| {detail['tp']} | {detail['fp']} | {detail['fn']} |"
        )
    lines.append("")

    # ── Per-Category Metrics ───────────────────────────────────────
    lines.append("### Per-Category Metrics")
    lines.append("")
    lines.append(
        "| Entity Type        | TP | FP | FN | Precision | Recall |   F1   |"
    )
    lines.append(
        "|--------------------|---:|---:|---:|----------:|-------:|-------:|"
    )

    # Sort by entity type for consistency.
    for etype in sorted(report.per_category.keys()):
        m: CategoryMetrics = report.per_category[etype]
        lines.append(
            f"| {etype:<18} | {m.tp:>2} | {m.fp:>2} | {m.fn:>2} "
            f"| {m.precision:>8.1%} | {m.recall:>5.1%} | {m.f1:>5.1%} |"
        )

    lines.append("")

    # ── Aggregate Metrics ──────────────────────────────────────────
    lines.append("### Aggregate Metrics")
    lines.append("")
    lines.append(
        "| Averaging | Precision | Recall |   F1   |"
    )
    lines.append(
        "|-----------|----------:|-------:|-------:|"
    )
    lines.append(
        f"| **Micro** | {report.micro_precision:>8.1%} "
        f"| {report.micro_recall:>5.1%} | {report.micro_f1:>5.1%} |"
    )
    lines.append(
        f"| **Macro** | {report.macro_precision:>8.1%} "
        f"| {report.macro_recall:>5.1%} | {report.macro_f1:>5.1%} |"
    )
    lines.append("")

    # ── Totals ─────────────────────────────────────────────────────
    lines.append(
        f"> **Totals**: TP={report.total_tp}  FP={report.total_fp}  "
        f"FN={report.total_fn}  |  "
        f"**{len(report.per_case_details)} test cases** evaluated"
    )
    lines.append("")

    return "\n".join(lines)


# ──────────────────────────────────────────────
# §7  CLI Entry Point
# ──────────────────────────────────────────────

def main() -> None:
    """Stand-alone evaluation runner."""
    print("=" * 60)
    print("  PII REDACTION ENGINE — EVALUATION SUITE")
    print("=" * 60)

    # Build pipeline.
    print("\n🔧 Initialising pipeline…")
    pipeline: RedactionPipeline = create_pipeline(score_threshold=0.35)
    print("   Pipeline ready.\n")

    # Build test corpus.
    test_cases: List[TestCase] = _build_test_corpus()
    print(f"📋 Loaded {len(test_cases)} test cases.\n")

    # Run evaluation.
    report: EvaluationReport = run_evaluation(
        pipeline, test_cases, iou_threshold=0.5, verbose=True
    )

    # Render and print the Markdown report.
    md_report: str = format_markdown_report(report)
    print("\n" + "=" * 60)
    print(md_report)
    print("=" * 60)

    # Exit code reflects quality gate.
    if report.micro_f1 < 0.50:
        print(
            "\n⚠  Quality gate FAILED: Micro-F1 < 50%. "
            "Review false positives and missed entities.",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        print(f"\n✅ Quality gate PASSED: Micro-F1 = {report.micro_f1:.1%}")


if __name__ == "__main__":
    main()
