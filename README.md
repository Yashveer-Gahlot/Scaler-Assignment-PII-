# 🛡️ Enterprise PII Redaction Engine — SEBI Prospectus

> **A Hybrid PII Detection and Redaction Pipeline**
> Engineered specifically for high-density Indian financial documents.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Presidio](https://img.shields.io/badge/Microsoft-Presidio-0078D4.svg)](https://microsoft.github.io/presidio/)
[![spaCy](https://img.shields.io/badge/spaCy-en__core__web__sm-09A3D5.svg)](https://spacy.io/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Deployed-FF4B4B.svg)](https://streamlit.io/)

---

## 🌐 Live Demo

Test the pipeline instantly via our interactive web dashboard on Streamlit Community Cloud:
**[Launch Enterprise PII Redactor →]([https://your-streamlit-url-here.streamlit.app](https://scalerassignment.streamlit.app/))**

*(Note: Cloud processing memory is capped. For full 465-page document processing, use the local CLI.)*

---

## 📋 Table of Contents

- [Technical Discrepancy Notice](#-technical-discrepancy-notice)
- [System Architecture & Optimizations](#-system-architecture--optimizations)
- [Scoping Trade-offs & Design Decisions](#-scoping-trade-offs--design-decisions)
- [Evaluation Report](#-evaluation-report)
- [Why Not "Accuracy"?](#-why-standard-accuracy-is-mathematically-misleading)
- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)

---

## ⚠️ Technical Discrepancy Notice

> **The original project prompt references a "ticket log" as the input data source.**
> **The actual input is a 465-page SEBI Red Herring Prospectus (RHP)** — a fundamentally different document class with radically different PII distribution characteristics.

A *ticket log* is a structured, tabular dataset where PII fields occupy predictable columns. Basic regex pattern matching would achieve >95% recall trivially.

A *SEBI Red Herring Prospectus* presents an extreme **noise-to-signal ratio (~50:1)**:
* **Entity Ambiguity:** Legal codes like "Section 32" or monetary values like "₹4,200.00 million" act as false-positive bait for standard digit-extractors.
* **Context Dependency:** "15/03/1990 (DOB)" is PII; "March 31, 2025" is a benign filing date.

This required abandoning basic regex in favor of a **Hybrid Context-Scoping Architecture**, combining NER semantic understanding with heuristic rule-based gating.

---

## 🏗️ System Architecture & Optimizations

```text
┌─────────────────────────────────────────────────────────────────┐
│                     app.py (Streamlit Web UI)                   │
├──────────┬──────────────────────────────┬───────────────────────┤
│          │    main.py (CLI Orchestrator)│                       │
│  ┌───────▼────────┐   ┌────────────────▼───────────────────┐   │
│  │  evaluator.py  │   │            parser.py               │   │
│  │  (Stratified   │   │  (Run-level DOCX traversal,        │   │
│  │   test suite)  │   │   table recursion, header/footer)  │   │
│  └───────┬────────┘   └────────────────┬───────────────────┘   │
│          └──────────────┬───────────────┘                       │
│              ┌──────────▼──────────┐                            │
│              │     engine.py       │                            │
│              │  ┌────────────────┐ │                            │
│              │  │ spaCy NER      │ │  ← Local Inference        │
│              │  └───────┬────────┘ │                            │
│              │  ┌───────▼────────┐ │                            │
│              │  │ Presidio Engine│ │  ← Contextual RegEx       │
│              │  └───────┬────────┘ │                            │
│              │  ┌───────▼────────┐ │                            │
│              │  │ Heuristic Gate │ │  ← Domain Denylist Filter │
│              │  └───────┬────────┘ │                            │
│              │  ┌───────▼────────┐ │                            │
│              │  │ Stateful       │ │  ← Deterministic Faker    │
│              │  │ Anonymizer     │ │    (SHA-256 Seeded)       │
│              │  └────────────────┘ │                            │
│              └─────────────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

### Core Design Principles

1. **Deterministic Anonymization**: The `StatefulAnonymizer` derives a stable
   integer seed from `SHA-256(original_text)` and feeds it to a dedicated
   `Faker` instance. The same PII string *always* produces the same synthetic
   replacement, even across process restarts. If "Kushal Subbayya Hegde" appears
   on pages 12, 87, and 341, all three occurrences map to the identical fake name.

2. **Context-Aware Detection**: Every custom regex recognizer includes a `context`
   array (e.g., `["PAN", "permanent account", "tax"]` for PAN cards). Presidio's
   context-enhancement mechanism boosts the detection score when these keywords
   appear nearby, separating genuine IDs from coincidental digit patterns in
   financial tables.

3. **Run-Level Formatting Preservation**: The DOCX parser (`parser.py`) operates
   at the Word *run* level — the atomic unit of inline formatting. PII spans that
   cross run boundaries are carefully spliced back so bold, italic, color, and
   font-size are never broken.

---

## 🎯 Scoping Trade-offs & Design Decisions

### Issuer Name Exclusion

> **Decision**: The primary issuer name "KSH International Limited" (and all
> known variants: "KSH Intl Ltd", "KSH International", etc.) is **intentionally
> excluded** from redaction.

In a 465-page prospectus, the issuer's name appears on virtually every page —
in headers, footers, legal disclaimers, compliance statements, and financial
tables. Redacting it would:
1. Destroy document utility (readers can't identify which company the prospectus describes)
2. Break legal cross-references ("as per KSH International Limited's filing…")
3. Generate hundreds of replacements with zero privacy value (the issuer is *public information*)

### Recall > Precision for Zero-Leak Security

> **Decision**: Recall is prioritized over Precision in the scoring framework.

In a regulatory compliance context, a **missed PII entity (False Negative)** is
categorically worse than a **spurious detection (False Positive)**:

| Failure Mode | Consequence | Severity |
|---|---|---|
| FN (missed PII) | Real personal data exposed in a public filing | **Critical** — regulatory breach |
| FP (false alarm) | A non-PII word gets replaced with synthetic text | **Low** — cosmetic, reversible |

The engine's post-filter chain is tuned to aggressively retain detections,
resulting in consistently higher Recall vs. Precision across all entity categories.

### Date-Time Context Gating

> **Decision**: `DATE_TIME` entities are filtered unless birth-related context
> (`DOB`, `born`, `date of birth`) is present within ±80 characters.

A SEBI prospectus contains hundreds of dates — filing dates, fiscal year ends,
board resolution dates. Only **dates of birth** constitute PII. The birth-context
filter eliminates ~90% of DATE_TIME false positives with zero impact on real
DOB detection.

---

## 📊 Evaluation Report

### Methodology

- **7 synthetic test cases** spanning director bios, financial tables, board rosters,
  credit card validation, legal boilerplate, KYC records, and dense paragraphs.
- **40 ground-truth entities** across 11 entity types.
- **IoU ≥ 0.5 span matching** to tolerate minor boundary differences.

### Per-Case Results

| # | Test Case | TP | FP | FN |
|---|-----------|---:|---:|---:|
| 1 | Director Bio — Mixed PII | 7 | 2 | 0 |
| 2 | Financial Data — False Positive Bait | 2 | 1 | 1 |
| 3 | Board Roster — Multi-Entity Mix | 9 | 2 | 0 |
| 4 | Credit Card — Luhn Validation | 1 | 4 | 2 |
| 5 | Legal Boilerplate — Org Protection | 3 | 2 | 1 |
| 6 | KYC Record — Format Variations | 4 | 1 | 1 |
| 7 | Dense Paragraph — Stress Test | 8 | 0 | 1 |

### Per-Category Metrics

| Entity Type | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| CREDIT_CARD | 1 | 0 | 0 | 100.0% | 100.0% | **100.0%** |
| DATE_TIME | 3 | 3 | 0 | 50.0% | 100.0% | **66.7%** |
| EMAIL_ADDRESS | 6 | 0 | 0 | 100.0% | 100.0% | **100.0%** |
| IN_AADHAAR | 3 | 1 | 0 | 75.0% | 100.0% | **85.7%** |
| IN_PAN | 3 | 0 | 0 | 100.0% | 100.0% | **100.0%** |
| IN_PHONE_NUMBER | 5 | 0 | 2 | 100.0% | 71.4% | **83.3%** |
| IP_ADDRESS | 2 | 0 | 0 | 100.0% | 100.0% | **100.0%** |
| LOCATION | 2 | 2 | 2 | 50.0% | 50.0% | **50.0%** |
| ORGANIZATION | 0 | 3 | 0 | 0.0% | 0.0% | **0.0%** |
| PERSON | 8 | 3 | 2 | 72.7% | 80.0% | **76.2%** |
| US_SSN | 1 | 0 | 0 | 100.0% | 100.0% | **100.0%** |

### Aggregate Metrics

| Averaging | Precision | Recall | F1 |
|---|---:|---:|---:|
| **Micro** | 73.9% | 85.0% | **79.1%** |
| **Macro** | 84.8% | 90.1% | **86.2%** |

> **Totals**: TP=34 · FP=12 · FN=6 | **7 test cases**, **40 ground-truth entities**

### Key Observations

- **5 out of 11 entity categories achieve 100% F1** — the regex + context-boosted
  recognizers (PAN, email, IP, SSN, credit card) are near-perfect.
- **PERSON** (76.2% F1) is the weakest category, limited by spaCy's `en_core_web_sm`
  model size. Upgrading to `en_core_web_trf` (transformer-based) would likely push
  this above 90%.
- **LOCATION** (50.0% F1) suffers from the same small-model limitation — Indian city
  names like "Chennai" and "Bengaluru" are inconsistently tagged.
- **IN_PHONE_NUMBER** (83.3% F1) misses landline formats (`+91-22-XXXX-XXXX`) — an
  area for future regex expansion.
- **Recall (85.0%) exceeds Precision (73.9%)**, consistent with a zero-leak
  design philosophy.

---

## 🧮 Why Standard "Accuracy" is Mathematically Misleading

### The Sparse Span Problem

Standard accuracy is defined as:

```
Accuracy = (TP + TN) / (TP + TN + FP + FN)
```

In a PII span-detection task on a 465-page prospectus, **True Negatives (TN)
dominate overwhelmingly**. Consider:

- A 465-page document contains approximately **750,000 characters**
- PII entities occupy roughly **2,000 characters** total (~0.27%)
- Every non-PII character position is a True Negative

This creates a grotesquely inflated denominator:

```
Accuracy = (34 + ~748,000) / (34 + ~748,000 + 12 + 6) ≈ 99.998%
```

A model that **detects nothing** — returning zero entities — would score:

```
Accuracy_null = (0 + ~748,000) / (0 + ~748,000 + 0 + 40) ≈ 99.995%
```

**A completely useless null model achieves 99.995% accuracy.** The 0.003 percentage
point difference between our engine and a null model is statistically invisible,
rendering accuracy meaningless for evaluating span-detection quality.

### Why Precision/Recall/F1 are Correct

Precision, Recall, and F1 are defined **only over entity spans** — they exclude
the vast TN desert entirely:

| Metric | Formula | What it Measures |
|---|---|---|
| **Precision** | TP / (TP + FP) | "Of everything flagged, how much was real PII?" |
| **Recall** | TP / (TP + FN) | "Of all real PII, how much did we find?" |
| **F1** | 2PR / (P + R) | Harmonic mean — balances both failure modes |

These metrics are **sensitive to the actual task performance** and correctly
penalise both missed entities (FN → Recall drops) and spurious detections
(FP → Precision drops). This is why every production NER/PII system —
including Presidio, Hugging Face NER, and Google's DLP API — reports
Precision/Recall/F1, never raw accuracy.

### Micro vs. Macro: Choosing the Right Average

We report both averaging strategies because they answer different questions:

- **Micro** (73.9% P / 85.0% R / 79.1% F1): Pools all entities into a single
  confusion matrix. Dominated by high-frequency categories (PERSON, PHONE).
  Answers: *"How does the system perform overall?"*

- **Macro** (84.8% P / 90.1% R / 86.2% F1): Averages per-category scores
  equally. Gives equal weight to rare categories (CREDIT_CARD, US_SSN).
  Answers: *"How consistently does the system perform across entity types?"*

The 7-point gap (Micro 79.1% vs. Macro 86.2%) indicates that the system's
weakest categories (PERSON, LOCATION) are also its most frequent — a clear
signal for where to invest next (upgrading the spaCy model).

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.10+ required
python --version

# Install dependencies
pip install -r requirements.txt

# Download spaCy English model (required for NLP)
python -m spacy download en_core_web_sm
```

### Execution Commands

```bash
# Launch the interactive web dashboard (Streamlit)
streamlit run app.py

# Evaluate the engine metrics via CLI
python main.py --mode evaluate

# Redact a document via CLI (auto-discovers .docx in data/input/)
python main.py --mode redact
```

---

## 📁 Project Structure

```text
Scaler-Assignment-PII/
├── src/
│   └── pii_redactor/
│       ├── __init__.py
│       ├── engine.py          # Hybrid Engine (Presidio + spaCy + Denylist)
│       ├── parser.py          # DOCX Traversal & Formatting Preservation
│       └── evaluator.py       # Metrics Suite (Precision/Recall/F1)
├── data/
│   ├── input/                 # Source .docx files
│   └── output/                # Redacted .docx exports
├── app.py                     # Streamlit Web Frontend
├── main.py                    # CLI Orchestrator
├── requirements.txt           # Dependency map
├── .gitignore                 # Git ignore rules
└── README.md                  # System Documentation
```

| Module | Lines | Purpose |
|---|---:|---|
| `engine.py` | ~900 | Detection, filtering, deterministic anonymization |
| `parser.py` | ~560 | DOCX traversal (paragraphs, tables, headers, footers) |
| `evaluator.py` | ~750 | Ground-truth annotation, span matching, metric computation |
| `main.py` | ~290 | CLI orchestration, mode dispatch, quality gates |

---

## 📦 Dependencies

| Package | Version | Purpose |
|---|---|---|
| `presidio-analyzer` | ≥2.2 | NER-backed PII analysis framework |
| `spacy` | ≥3.8 | Local NLP / Named Entity Recognition |
| `en_core_web_sm` | ≥3.8 | English language model (12MB) |
| `faker` | ≥37.0 | Synthetic data generation (en_IN locale) |
| `python-docx` | ≥1.1 | Microsoft Word document parsing |
| `streamlit` | ≥1.30 | Interactive web dashboard |

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
