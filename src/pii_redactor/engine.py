"""
engine.py — Hybrid PII Redaction Pipeline
==========================================

A production-grade PII detection and redaction engine purpose-built for
Indian financial documents (SEBI prospectuses). Combines Microsoft Presidio's
NER-backed analysis with custom regex recognizers for India-specific PII
(PAN, Aadhaar, +91 phones) and a deterministic, seed-stable anonymizer
powered by Faker.

Architecture
------------
┌──────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  Raw Text    │────▶│  AnalyzerEngine  │────▶│  Post-Filter Layer  │
│              │     │  (spaCy NER +    │     │  (org exclusion,    │
│              │     │   custom regex)  │     │   date filtering)   │
└──────────────┘     └──────────────────┘     └────────┬────────────┘
                                                       │
                                               ┌───────▼────────────┐
                                               │ StatefulAnonymizer  │
                                               │ (Faker, hash-seeded,│
                                               │  deterministic map) │
                                               └────────────────────┘

Author : Engine Team
License: MIT
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from faker import Faker
from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider


# ──────────────────────────────────────────────
# §1  Constants & Configuration
# ──────────────────────────────────────────────

# Organization names that must NOT be redacted (preserves document utility).
_PROTECTED_ORG_VARIANTS: Tuple[str, ...] = (
    "ksh international limited",
    "ksh international ltd",
    "ksh international ltd.",
    "ksh international",
    "ksh intl limited",
    "ksh intl ltd",
    "ksh intl ltd.",
    "ksh intl",
)

# DATE_TIME results are dropped unless one of these birth-related markers
# appears within a ±80-char window around the match.
_BIRTH_CONTEXT_PATTERNS: re.Pattern[str] = re.compile(
    r"\b(?:dob|d\.o\.b|date\s+of\s+birth|born|birth\s*date|birthdate)\b",
    re.IGNORECASE,
)

# Context window (chars) around a DATE_TIME match to scan for birth keywords.
_BIRTH_CONTEXT_WINDOW: int = 80

# Short tokens that spaCy's NER frequently mis-labels as ORGANIZATION or
# PERSON.  These are common abbreviations in Indian financial documents.
_NER_NOISE_TOKENS: frozenset = frozenset({
    "pan", "dob", "cfo", "ssn", "din", "cin", "kyc", "nri", "ipo",
    "aum", "nav", "roi", "emi", "gst", "tds", "nro", "nre", "sebi",
    "bse", "nse", "rbi", "nbfc", "amc",
})

# Minimum character length for spaCy-sourced NER entities (PERSON, ORG,
# LOCATION) to be considered valid.  Suppresses noisy 1–4 char tags.
_MIN_NER_ENTITY_LENGTH: int = 5

# Domain-specific denylist: capitalised financial / legal jargon that spaCy's
# en_core_web_sm model frequently mis-classifies as ORGANIZATION or PERSON.
# All entries are stored lower-cased; lookups are O(1) via frozenset.
_DENYLIST_TERMS: frozenset = frozenset({
    # --- Financial terms ---
    "equity shares", "equity", "shares", "share", "bidders", "bidder",
    "rupees", "rupee", "inr", "rs.", "rs", "₹", "crore", "crores",
    "lakh", "lakhs", "million", "billion",
    # --- Legal / regulatory ---
    "board", "board of directors", "prospectus", "red herring prospectus",
    "offer", "offer price", "offer document", "company", "the company",
    "issuer", "registrar", "tribunal", "act", "the act",
    "regulation", "regulations", "listing", "compliance",
    # --- SEBI / regulatory bodies (already in NER noise but repeated
    #     here for multi-word variants) ---
    "sebi", "reserve bank", "reserve bank of india", "rbi",
    "stock exchange", "national stock exchange", "bombay stock exchange",
    "nse", "bse", "nsdl", "cdsl", "depository",
    # --- Document structure terms ---
    "chapter", "section", "schedule", "annexure", "part",
    "table", "form", "certificate", "report", "resolution",
    "agenda", "minutes", "notice", "consent", "declaration",
    # --- Roles / titles mistaken for person names ---
    "managing director", "director", "directors", "chairman",
    "promoter", "promoters", "promoter group", "investor", "investors",
    "shareholder", "shareholders", "allottee", "allottees",
    "subscriber", "subscribers", "applicant", "applicants",
    "underwriter", "underwriters", "auditor", "auditors",
    # --- Misc high-frequency FP triggers ---
    "india", "indian", "government", "government of india",
    "fiscal year", "financial year", "assessment year",
    "filing date", "effective date", "record date",
    "net worth", "face value", "book value", "market capitalisation",
    "paid-up", "authorised", "subscribed", "issued",
})


# ──────────────────────────────────────────────
# §2  Luhn Check Utility
# ──────────────────────────────────────────────

def _passes_luhn(card_number: str) -> bool:
    """Validate a credit-card number using the Luhn (mod-10) algorithm.

    Parameters
    ----------
    card_number:
        A string of digits (spaces/dashes already stripped by caller).

    Returns
    -------
    bool
        ``True`` if the digit sequence satisfies the Luhn checksum.
    """
    digits: List[int] = [int(ch) for ch in card_number if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum: int = 0
    reverse_digits: List[int] = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled: int = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


# ──────────────────────────────────────────────
# §3  Custom Presidio Recognizers
# ──────────────────────────────────────────────

def _build_indian_phone_recognizer() -> PatternRecognizer:
    """Recognizer for Indian phone numbers.

    Covers:
      • +91-XXXXX-XXXXX / +91 XXXXX XXXXX
      • 0XXXXX XXXXX  (STD prefix)
      • Raw 10-digit sequences starting with 6-9

    Uses strict word boundaries (``\b``) and digit look-around to prevent
    matching financial figures or registration numbers.
    """
    patterns: List[Pattern] = [
        Pattern(
            name="in_phone_intl",
            regex=r"\b\+91[\s\-]?[6-9]\d{4}[\s\-]?\d{5}\b",
            score=0.85,
        ),
        Pattern(
            name="in_phone_std",
            regex=r"\b0[6-9]\d{4}[\s\-]?\d{5}\b",
            score=0.70,
        ),
        Pattern(
            name="in_phone_raw",
            regex=r"(?<!\d)\b[6-9]\d{9}\b(?!\d)",
            score=0.60,
        ),
    ]
    return PatternRecognizer(
        supported_entity="IN_PHONE_NUMBER",
        name="IndianPhoneRecognizer",
        patterns=patterns,
        supported_language="en",
        context=[
            "phone", "mobile", "cell", "contact", "call", "tel",
            "telephone", "whatsapp", "reach", "number",
        ],
    )


def _build_pan_recognizer() -> PatternRecognizer:
    """Recognizer for Indian Permanent Account Numbers (PAN).

    Format: 5 upper-case letters → 4 digits → 1 upper-case letter.
    The 4th character encodes the holder type (C, P, H, F, A, T, B, L, J, G).

    Uses strict word boundaries (``\b``) to isolate the 10-char alphanumeric
    token from surrounding text.
    """
    patterns: List[Pattern] = [
        Pattern(
            name="in_pan",
            regex=r"\b[A-Z]{3}[CPHFATBLJG][A-Z]\d{4}[A-Z]\b",
            score=0.85,
        ),
    ]
    return PatternRecognizer(
        supported_entity="IN_PAN",
        name="IndianPANRecognizer",
        patterns=patterns,
        supported_language="en",
        context=[
            "PAN", "pan", "permanent account", "account number",
            "tax", "income tax", "IT",
        ],
    )


def _build_aadhaar_recognizer() -> PatternRecognizer:
    """Recognizer for Indian Aadhaar numbers.

    Format: 12 digits, commonly written as XXXX XXXX XXXX or XXXX-XXXX-XXXX.
    First digit is never 0 or 1.
    """
    patterns: List[Pattern] = [
        Pattern(
            name="in_aadhaar_spaced",
            regex=r"(?<!\d)[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}(?!\d)",
            score=0.85,
        ),
        Pattern(
            name="in_aadhaar_raw",
            regex=r"(?<!\d)[2-9]\d{11}(?!\d)",
            score=0.60,
        ),
    ]
    return PatternRecognizer(
        supported_entity="IN_AADHAAR",
        name="IndianAadhaarRecognizer",
        patterns=patterns,
        supported_language="en",
        context=[
            "aadhaar", "aadhar", "UID", "UIDAI", "identity",
            "ID", "unique identification", "enrolment",
        ],
    )


def _build_email_recognizer() -> PatternRecognizer:
    """Recognizer for email addresses (RFC-5321 simplified)."""
    patterns: List[Pattern] = [
        Pattern(
            name="email",
            regex=r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}",
            score=0.90,
        ),
    ]
    return PatternRecognizer(
        supported_entity="EMAIL_ADDRESS",
        name="EmailRecognizer",
        patterns=patterns,
        supported_language="en",
        context=[
            "email", "e-mail", "mail", "contact", "reach",
            "write", "send", "@",
        ],
    )


def _build_credit_card_recognizer() -> PatternRecognizer:
    """Recognizer for credit/debit card numbers (13–19 digits).

    The recognizer fires on plausible digit sequences; the Luhn check is
    applied as a post-validation step inside ``RedactionPipeline``.
    """
    patterns: List[Pattern] = [
        Pattern(
            name="cc_spaced",
            regex=r"(?<!\d)\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}(?!\d)",
            score=0.70,
        ),
        Pattern(
            name="cc_raw",
            regex=r"(?<!\d)(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})(?!\d)",
            score=0.75,
        ),
    ]
    return PatternRecognizer(
        supported_entity="CREDIT_CARD",
        name="CreditCardRecognizer",
        patterns=patterns,
        supported_language="en",
        context=[
            "card", "credit", "debit", "visa", "mastercard",
            "payment", "billing", "subscription",
        ],
    )


def _build_ip_address_recognizer() -> PatternRecognizer:
    """Recognizer for IPv4 addresses."""
    patterns: List[Pattern] = [
        Pattern(
            name="ipv4",
            regex=(
                r"(?<!\d)"
                r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
                r"(?!\d)"
            ),
            score=0.70,
        ),
    ]
    return PatternRecognizer(
        supported_entity="IP_ADDRESS",
        name="IPAddressRecognizer",
        patterns=patterns,
        supported_language="en",
        context=[
            "IP", "ip", "address", "server", "host", "network",
            "access", "log", "connection",
        ],
    )


def _build_ssn_recognizer() -> PatternRecognizer:
    """Recognizer for US Social Security Numbers (XXX-XX-XXXX)."""
    patterns: List[Pattern] = [
        Pattern(
            name="ssn",
            regex=r"(?<!\d)\d{3}[\s\-]\d{2}[\s\-]\d{4}(?!\d)",
            score=0.80,
        ),
    ]
    return PatternRecognizer(
        supported_entity="US_SSN",
        name="SSNRecognizer",
        patterns=patterns,
        supported_language="en",
        context=[
            "SSN", "social security", "social", "security number",
        ],
    )


# ──────────────────────────────────────────────
# §4  StatefulAnonymizer  (Faker, deterministic)
# ──────────────────────────────────────────────

@dataclass
class StatefulAnonymizer:
    """Deterministic, seed-stable PII anonymizer backed by ``Faker``.

    For each unique PII string encountered, the anonymizer derives a
    *stable integer seed* from the SHA-256 hash of the original value.
    That seed is fed into a dedicated ``Faker`` instance so the same
    input always produces the same synthetic replacement — even across
    process restarts.

    Parameters
    ----------
    locale:
        BCP-47 locale tag forwarded to Faker (default ``'en_IN'``).

    Attributes
    ----------
    _cache:
        ``{(entity_type, original_text): synthetic_replacement}`` mapping
        that guarantees referential consistency within a single run.
    """

    locale: str = "en_IN"
    _cache: Dict[Tuple[str, str], str] = field(default_factory=dict, repr=False)

    # ---- public API ------------------------------------------------

    def anonymize(self, entity_type: str, original: str) -> str:
        """Return a deterministic synthetic replacement for *original*.

        Parameters
        ----------
        entity_type:
            Presidio entity label (``PERSON``, ``EMAIL_ADDRESS``, …).
        original:
            The raw PII string extracted from the source text.

        Returns
        -------
        str
            A fake but plausible replacement, consistent across calls.
        """
        cache_key: Tuple[str, str] = (entity_type, original)
        if cache_key in self._cache:
            return self._cache[cache_key]

        seed: int = self._stable_seed(original)
        fake: Faker = Faker(self.locale)
        fake.seed_instance(seed)

        synthetic: str = self._generate(fake, entity_type, original)
        self._cache[cache_key] = synthetic
        return synthetic

    def reset(self) -> None:
        """Clear the internal cache (useful between unrelated documents)."""
        self._cache.clear()

    # ---- internals -------------------------------------------------

    @staticmethod
    def _stable_seed(value: str) -> int:
        """Derive a deterministic integer seed from an arbitrary string.

        Uses the first 16 bytes of a SHA-256 digest interpreted as a
        big-endian unsigned integer.  This gives 128 bits of entropy —
        far more than ``Faker`` actually consumes — while remaining
        perfectly reproducible.
        """
        digest: bytes = hashlib.sha256(value.encode("utf-8")).digest()
        return int.from_bytes(digest[:16], byteorder="big")

    @staticmethod
    def _generate(fake: Faker, entity_type: str, original: str) -> str:
        """Dispatch to the appropriate Faker provider by entity type.

        Parameters
        ----------
        fake:
            A seeded ``Faker`` instance.
        entity_type:
            Presidio entity label.
        original:
            The original PII value (used for format-matching heuristics).

        Returns
        -------
        str
            Synthetic replacement text.
        """
        generators: Dict[str, str] = {
            "PERSON":           "_gen_person",
            "EMAIL_ADDRESS":    "_gen_email",
            "IN_PHONE_NUMBER":  "_gen_in_phone",
            "PHONE_NUMBER":     "_gen_in_phone",
            "IN_PAN":           "_gen_in_pan",
            "IN_AADHAAR":       "_gen_in_aadhaar",
            "CREDIT_CARD":      "_gen_credit_card",
            "IP_ADDRESS":       "_gen_ip",
            "US_SSN":           "_gen_ssn",
            "LOCATION":         "_gen_location",
            "ORGANIZATION":     "_gen_organization",
            "DATE_TIME":        "_gen_date",
        }
        method_name: str = generators.get(entity_type, "_gen_fallback")
        method = getattr(StatefulAnonymizer, method_name)
        return method(fake, original)

    # ---- per-type generators ---------------------------------------

    @staticmethod
    def _gen_person(fake: Faker, _original: str) -> str:
        return fake.name()

    @staticmethod
    def _gen_email(fake: Faker, _original: str) -> str:
        return fake.email()

    @staticmethod
    def _gen_in_phone(fake: Faker, original: str) -> str:
        raw_digits: str = "".join(ch for ch in fake.phone_number() if ch.isdigit())
        # Ensure we produce a plausible 10-digit Indian mobile number.
        base: str = fake.random_element(["6", "7", "8", "9"])
        suffix: str = "".join(str(fake.random_digit()) for _ in range(9))
        number: str = base + suffix
        if original.startswith("+91"):
            return f"+91 {number[:5]} {number[5:]}"
        return number

    @staticmethod
    def _gen_in_pan(fake: Faker, _original: str) -> str:
        prefix: str = "".join(fake.random_uppercase_letter() for _ in range(3))
        holder: str = fake.random_element(["C", "P", "H", "F", "A", "T", "B", "L", "J", "G"])
        fifth: str = fake.random_uppercase_letter()
        digits: str = "".join(str(fake.random_digit()) for _ in range(4))
        last: str = fake.random_uppercase_letter()
        return f"{prefix}{holder}{fifth}{digits}{last}"

    @staticmethod
    def _gen_in_aadhaar(fake: Faker, original: str) -> str:
        first: str = str(fake.random_int(min=2, max=9))
        rest: str = "".join(str(fake.random_digit()) for _ in range(11))
        raw: str = first + rest
        if " " in original or "-" in original:
            sep: str = " " if " " in original else "-"
            return f"{raw[:4]}{sep}{raw[4:8]}{sep}{raw[8:]}"
        return raw

    @staticmethod
    def _gen_credit_card(fake: Faker, _original: str) -> str:
        return fake.credit_card_number(card_type=None)

    @staticmethod
    def _gen_ip(fake: Faker, _original: str) -> str:
        return fake.ipv4()

    @staticmethod
    def _gen_ssn(fake: Faker, _original: str) -> str:
        return fake.ssn()

    @staticmethod
    def _gen_location(fake: Faker, _original: str) -> str:
        return fake.city()

    @staticmethod
    def _gen_organization(fake: Faker, _original: str) -> str:
        return fake.company()

    @staticmethod
    def _gen_date(fake: Faker, _original: str) -> str:
        return fake.date(pattern="%d/%m/%Y")

    @staticmethod
    def _gen_fallback(fake: Faker, _original: str) -> str:
        return f"[REDACTED-{fake.bothify('??##??')}]"


# ──────────────────────────────────────────────
# §5  Post-Analysis Filter Layer (Denylist + NER Noise + Context)
# ──────────────────────────────────────────────

def _is_denylisted(text: str, result: RecognizerResult) -> bool:
    """Return ``True`` if *result*'s text span matches a domain denylist term.

    Prevents spaCy NER hallucinations on capitalised financial and legal
    jargon (e.g. "Equity Shares" → ORGANIZATION, "Bidders" → PERSON).

    The comparison is case-insensitive with leading/trailing whitespace
    stripped.  Lookup is O(1) against the pre-lowercased ``_DENYLIST_TERMS``
    frozenset.

    Parameters
    ----------
    text:
        Full source document text.
    result:
        A single Presidio ``RecognizerResult``.
    """
    # Only filter NER-sourced entity types — never suppress regex recognizers.
    if result.entity_type not in ("ORGANIZATION", "ORG", "PERSON", "LOCATION", "GPE"):
        return False

    span: str = text[result.start : result.end].strip().lower()
    return span in _DENYLIST_TERMS


def _is_ner_noise(text: str, result: RecognizerResult) -> bool:
    """Return ``True`` if *result* is a short spaCy NER tag that matches
    known abbreviation noise (PAN, DOB, CFO, SSN, etc.).

    spaCy's ``en_core_web_sm`` model frequently mis-labels common
    financial/legal abbreviations as ORGANIZATION or PERSON.  This
    filter suppresses those false positives.

    Parameters
    ----------
    text:
        Full source document text.
    result:
        A single Presidio ``RecognizerResult``.
    """
    # Only filter NER-sourced entity types (not regex custom recognizers).
    if result.entity_type not in ("ORGANIZATION", "ORG", "PERSON", "LOCATION", "GPE"):
        return False

    span: str = text[result.start : result.end].strip()

    # Check against known abbreviation noise list.
    if span.lower() in _NER_NOISE_TOKENS:
        return True

    # Short NER entities (< 5 chars) from spaCy are overwhelmingly noise
    # in financial documents.  Filter them unless they are title-cased
    # words (likely real names like "Pune" or "Nair").
    if len(span) < _MIN_NER_ENTITY_LENGTH:
        # Keep title-cased tokens (e.g. "Pune", "Nair") — likely real entities.
        if span[0].isupper() and span[1:].islower() and span.isalpha():
            return False
        return True

    return False


def _is_protected_organization(text: str, result: RecognizerResult) -> bool:
    """Return ``True`` if *result* matches a protected org name variant.

    Parameters
    ----------
    text:
        Full source document text.
    result:
        A single Presidio ``RecognizerResult``.
    """
    if result.entity_type not in ("ORGANIZATION", "ORG", "PERSON"):
        return False
    matched: str = text[result.start : result.end].strip().lower()
    return any(matched == variant for variant in _PROTECTED_ORG_VARIANTS)


def _is_non_birth_date(text: str, result: RecognizerResult) -> bool:
    """Return ``True`` if *result* is a DATE_TIME without birth context.

    Scans a ±``_BIRTH_CONTEXT_WINDOW``-char window around the match for
    keywords like 'DOB', 'born', 'date of birth', etc.  Dates lacking
    those markers are considered standard filing timelines and excluded
    from redaction.

    Parameters
    ----------
    text:
        Full source document text.
    result:
        A single Presidio ``RecognizerResult``.
    """
    if result.entity_type != "DATE_TIME":
        return False

    window_start: int = max(0, result.start - _BIRTH_CONTEXT_WINDOW)
    window_end: int = min(len(text), result.end + _BIRTH_CONTEXT_WINDOW)
    surrounding: str = text[window_start:window_end]

    return _BIRTH_CONTEXT_PATTERNS.search(surrounding) is None


def _validate_credit_card(text: str, result: RecognizerResult) -> bool:
    """Return ``True`` if a CREDIT_CARD result fails the Luhn check.

    Parameters
    ----------
    text:
        Full source document text.
    result:
        A single Presidio ``RecognizerResult`` with entity_type ``CREDIT_CARD``.
    """
    if result.entity_type != "CREDIT_CARD":
        return False
    raw: str = text[result.start : result.end]
    digits_only: str = re.sub(r"\D", "", raw)
    return not _passes_luhn(digits_only)


def filter_results(
    text: str,
    results: List[RecognizerResult],
    score_threshold: float = 0.50,
) -> List[RecognizerResult]:
    """Apply business-logic filters to raw Presidio results.

    Removes:
      1. Results below ``score_threshold``.
      2. Domain denylist matches (financial/legal jargon).
      3. Short NER noise tokens.
      4. Protected organization names.
      5. DATE_TIME tokens without birth context.
      6. Credit-card candidates that fail Luhn validation.

    Parameters
    ----------
    text:
        Full source document text.
    results:
        Raw ``RecognizerResult`` list from the analyzer.
    score_threshold:
        Minimum confidence score to retain a result.

    Returns
    -------
    List[RecognizerResult]
        Cleaned, de-duplicated result set sorted by start offset.
    """
    filtered: List[RecognizerResult] = []
    for r in results:
        if r.score < score_threshold:
            continue
        if _is_denylisted(text, r):
            continue
        if _is_ner_noise(text, r):
            continue
        if _is_protected_organization(text, r):
            continue
        if _is_non_birth_date(text, r):
            continue
        if _validate_credit_card(text, r):
            continue
        filtered.append(r)

    # De-duplicate overlapping spans: keep highest-scoring match.
    filtered.sort(key=lambda r: (r.start, -r.score))
    deduped: List[RecognizerResult] = []
    last_end: int = -1
    for r in filtered:
        if r.start >= last_end:
            deduped.append(r)
            last_end = r.end
        else:
            # Overlapping — keep only if score is strictly higher.
            if deduped and r.score > deduped[-1].score:
                deduped[-1] = r
                last_end = r.end
    return deduped


# ──────────────────────────────────────────────
# §6  Pipeline Orchestrator
# ──────────────────────────────────────────────

@dataclass
class RedactionPipeline:
    """End-to-end PII redaction pipeline.

    Orchestrates detection (Presidio + custom recognizers), filtering
    (org exclusion, date logic, Luhn validation), and deterministic
    anonymization (``StatefulAnonymizer``).

    Parameters
    ----------
    score_threshold:
        Minimum confidence to accept a detection result.
    anonymizer_locale:
        Locale forwarded to ``Faker`` inside the anonymizer.

    Example
    -------
    >>> pipeline = RedactionPipeline()
    >>> result = pipeline.redact("Contact Kushal Subbayya Hegde at +91 98765 43210.")
    >>> "Kushal" not in result.redacted_text
    True
    """

    score_threshold: float = 0.50
    anonymizer_locale: str = "en_IN"

    # Populated during ``__post_init__``.
    _analyzer: AnalyzerEngine = field(init=False, repr=False)
    _anonymizer: StatefulAnonymizer = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._analyzer = self._build_analyzer()
        self._anonymizer = StatefulAnonymizer(locale=self.anonymizer_locale)

    # ---- analyzer construction ------------------------------------

    @staticmethod
    def _build_analyzer() -> AnalyzerEngine:
        """Construct a Presidio ``AnalyzerEngine`` with spaCy + custom recognizers."""
        # Configure spaCy NLP backend.
        nlp_config: Dict[str, object] = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider: NlpEngineProvider = NlpEngineProvider(nlp_configuration=nlp_config)
        nlp_engine = provider.create_engine()

        analyzer: AnalyzerEngine = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["en"],
        )

        # Register all custom recognizers.
        custom_recognizers: List[PatternRecognizer] = [
            _build_indian_phone_recognizer(),
            _build_pan_recognizer(),
            _build_aadhaar_recognizer(),
            _build_email_recognizer(),
            _build_credit_card_recognizer(),
            _build_ip_address_recognizer(),
            _build_ssn_recognizer(),
        ]
        for recognizer in custom_recognizers:
            analyzer.registry.add_recognizer(recognizer)

        return analyzer

    # ---- public API ------------------------------------------------

    def analyze(self, text: str) -> List[RecognizerResult]:
        """Run detection + filtering without anonymization.

        Parameters
        ----------
        text:
            Source document text.

        Returns
        -------
        List[RecognizerResult]
            Filtered, de-duplicated PII detections.
        """
        raw_results: List[RecognizerResult] = self._analyzer.analyze(
            text=text,
            language="en",
            entities=[
                "PERSON",
                "LOCATION",
                "ORGANIZATION",
                "EMAIL_ADDRESS",
                "DATE_TIME",
                "CREDIT_CARD",
                "IP_ADDRESS",
                "US_SSN",
                "IN_PHONE_NUMBER",
                "IN_PAN",
                "IN_AADHAAR",
                "PHONE_NUMBER",
            ],
        )
        return filter_results(text, raw_results, self.score_threshold)

    def redact(self, text: str) -> "RedactionResult":
        """Detect, filter, and anonymize all PII in *text*.

        Parameters
        ----------
        text:
            Source document text.

        Returns
        -------
        RedactionResult
            Container holding the redacted text and a manifest of every
            substitution performed.
        """
        detections: List[RecognizerResult] = self.analyze(text)

        # Sort detections in reverse offset order so that replacements
        # do not shift the positions of subsequent spans.
        detections.sort(key=lambda r: r.start, reverse=True)

        redacted: str = text
        manifest: List[RedactionEntry] = []

        for det in detections:
            original_span: str = text[det.start : det.end]
            replacement: str = self._anonymizer.anonymize(det.entity_type, original_span)

            redacted = redacted[: det.start] + replacement + redacted[det.end :]
            manifest.append(
                RedactionEntry(
                    entity_type=det.entity_type,
                    start=det.start,
                    end=det.end,
                    original=original_span,
                    replacement=replacement,
                    score=det.score,
                )
            )

        # Return manifest in reading order.
        manifest.reverse()
        return RedactionResult(redacted_text=redacted, entries=manifest)

    def reset_anonymizer(self) -> None:
        """Clear anonymizer state between unrelated documents."""
        self._anonymizer.reset()


# ──────────────────────────────────────────────
# §7  Result Data Structures
# ──────────────────────────────────────────────

@dataclass(frozen=True)
class RedactionEntry:
    """Single PII substitution record."""

    entity_type: str
    start: int
    end: int
    original: str
    replacement: str
    score: float


@dataclass(frozen=True)
class RedactionResult:
    """Aggregate output of a redaction pass."""

    redacted_text: str
    entries: Tuple[RedactionEntry, ...] | List[RedactionEntry]

    @property
    def entity_count(self) -> int:
        """Total number of PII entities redacted."""
        return len(self.entries)

    def summary(self) -> Dict[str, int]:
        """Return a ``{entity_type: count}`` breakdown."""
        counts: Dict[str, int] = {}
        for entry in self.entries:
            counts[entry.entity_type] = counts.get(entry.entity_type, 0) + 1
        return counts


# ──────────────────────────────────────────────
# §8  Module-Level Convenience
# ──────────────────────────────────────────────

def create_pipeline(
    score_threshold: float = 0.50,
    locale: str = "en_IN",
) -> RedactionPipeline:
    """Factory function — preferred entry point.

    Parameters
    ----------
    score_threshold:
        Minimum confidence score for keeping a detection.
    locale:
        Faker locale for synthetic data generation.

    Returns
    -------
    RedactionPipeline
        Ready-to-use pipeline instance.

    Example
    -------
    >>> pipe = create_pipeline()
    >>> out = pipe.redact(
    ...     "Kushal Subbayya Hegde (DOB: 15/03/1990) works at "
    ...     "KSH International Limited. Email: kushal@example.com"
    ... )
    >>> "KSH International Limited" in out.redacted_text
    True
    >>> "kushal@example.com" not in out.redacted_text
    True
    """
    return RedactionPipeline(
        score_threshold=score_threshold,
        anonymizer_locale=locale,
    )


# ──────────────────────────────────────────────
# §9  CLI / Quick Smoke Test
# ──────────────────────────────────────────────

if __name__ == "__main__":
    sample_text: str = (
        "Mr. Kushal Subbayya Hegde, Director of KSH International Limited, "
        "was born on 15/03/1990 (DOB). His PAN is ABCPK1234Z and Aadhaar "
        "number is 2345 6789 0123. He can be reached at +91 98765 43210 or "
        "kushal.hegde@example.com. Filing date: 01/07/2026. "
        "IP: 192.168.1.100. SSN: 123-45-6789. "
        "Credit Card: 4539 1488 0343 6467. "
        "Kushal Subbayya Hegde approved the prospectus on behalf of "
        "KSH International Ltd."
    )

    pipe: RedactionPipeline = create_pipeline()
    result: RedactionResult = pipe.redact(sample_text)

    print("=" * 72)
    print("REDACTED TEXT")
    print("=" * 72)
    print(result.redacted_text)
    print()
    print("=" * 72)
    print(f"MANIFEST  ({result.entity_count} entities)")
    print("=" * 72)
    for entry in result.entries:
        print(
            f"  [{entry.entity_type:<18}] "
            f"score={entry.score:.2f}  "
            f"'{entry.original}' → '{entry.replacement}'"
        )
    print()
    print("SUMMARY:", result.summary())

    # Determinism check: same name must yield same replacement.
    r2: RedactionResult = pipe.redact(
        "Kushal Subbayya Hegde signed the documents."
    )
    first_kushal = [e for e in result.entries if e.original == "Kushal Subbayya Hegde"]
    second_kushal = [e for e in r2.entries if e.original == "Kushal Subbayya Hegde"]
    if first_kushal and second_kushal:
        assert first_kushal[0].replacement == second_kushal[0].replacement, (
            "Determinism violated!"
        )
        print(f"\n✓ Determinism check passed: "
              f"'{first_kushal[0].original}' → '{first_kushal[0].replacement}' (stable)")
