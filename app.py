"""
app.py — Enterprise PII Redaction Tool (Streamlit Frontend)
=============================================================

A sleek, production-grade web interface for the Hybrid PII Redaction
Pipeline.  Provides drag-and-drop .docx upload, real-time progress
feedback, entity-level analytics, and instant download of the redacted
document.

Launch
------
    $ streamlit run app.py

Author : Frontend Team
License: MIT
"""

from __future__ import annotations

import os
import sys
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────
# §0  Auto-Dependency: spaCy Model Download
# ──────────────────────────────────────────────
# Ensures en_core_web_sm is available before Presidio/engine imports.
# Critical for cloud sandbox deployments (Streamlit Cloud, HuggingFace Spaces)
# where the model may not be pre-installed.

try:
    import en_core_web_sm  # noqa: F401
except ImportError:
    try:
        subprocess.run(
            [sys.executable, "-m", "spacy", "download", "en_core_web_sm", "--quiet"],
            check=True, capture_output=True,
        )
    except Exception:
        pass  # Model should be installed via requirements.txt

import streamlit as st

# ──────────────────────────────────────────────
# §1  Page Configuration (must be first st call)
# ──────────────────────────────────────────────

st.set_page_config(
    page_title="Enterprise PII Redaction Tool",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ──────────────────────────────────────────────
# §2  Custom CSS — Premium Dark Theme
# ──────────────────────────────────────────────

st.markdown("""
<style>
    /* --- Global overrides --- */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    .stApp {
        font-family: 'Inter', sans-serif;
    }

    /* --- Hero header --- */
    .hero-container {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
        border-radius: 16px;
        padding: 2.5rem 3rem;
        margin-bottom: 2rem;
        border: 1px solid rgba(255, 255, 255, 0.08);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    }
    .hero-title {
        font-size: 2.4rem;
        font-weight: 700;
        color: #ffffff;
        margin: 0 0 0.5rem 0;
        letter-spacing: -0.5px;
    }
    .hero-subtitle {
        font-size: 1.05rem;
        color: rgba(255, 255, 255, 0.65);
        margin: 0;
        line-height: 1.6;
        max-width: 720px;
    }
    .hero-badge {
        display: inline-block;
        background: rgba(99, 102, 241, 0.25);
        color: #a5b4fc;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.5px;
        margin-bottom: 1rem;
        border: 1px solid rgba(99, 102, 241, 0.3);
    }

    /* --- Metric cards --- */
    .metric-row {
        display: flex;
        gap: 1rem;
        margin: 1.5rem 0;
    }
    .metric-card {
        flex: 1;
        background: linear-gradient(145deg, #1e1b4b, #312e81);
        border: 1px solid rgba(99, 102, 241, 0.2);
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        text-align: center;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #818cf8;
        margin: 0;
    }
    .metric-label {
        font-size: 0.8rem;
        color: rgba(255, 255, 255, 0.5);
        text-transform: uppercase;
        letter-spacing: 1px;
        margin: 4px 0 0 0;
    }

    /* --- Entity breakdown table --- */
    .entity-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid rgba(255, 255, 255, 0.08);
        margin-top: 1rem;
    }
    .entity-table th {
        background: rgba(99, 102, 241, 0.15);
        color: #a5b4fc;
        padding: 12px 16px;
        text-align: left;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
    }
    .entity-table td {
        padding: 10px 16px;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        font-size: 0.9rem;
    }
    .entity-table tr:hover td {
        background: rgba(99, 102, 241, 0.06);
    }
    .entity-tag {
        display: inline-block;
        background: rgba(99, 102, 241, 0.18);
        color: #c7d2fe;
        padding: 3px 10px;
        border-radius: 6px;
        font-family: 'SF Mono', 'Fira Code', monospace;
        font-size: 0.8rem;
        font-weight: 500;
    }
    .entity-count {
        font-weight: 600;
        color: #e0e7ff;
        font-size: 1rem;
    }

    /* --- Status badges --- */
    .status-success {
        background: linear-gradient(135deg, #064e3b, #065f46);
        border: 1px solid rgba(52, 211, 153, 0.3);
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        margin: 1rem 0;
    }
    .status-success p {
        color: #6ee7b7;
        margin: 0;
        font-weight: 500;
    }

    /* --- Upload area --- */
    .upload-zone {
        background: rgba(99, 102, 241, 0.05);
        border: 2px dashed rgba(99, 102, 241, 0.25);
        border-radius: 16px;
        padding: 2rem;
        text-align: center;
        transition: all 0.3s ease;
    }
    .upload-zone:hover {
        border-color: rgba(99, 102, 241, 0.5);
        background: rgba(99, 102, 241, 0.08);
    }

    /* --- Pipeline steps --- */
    .pipeline-step {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.6rem 0;
        color: rgba(255, 255, 255, 0.7);
        font-size: 0.9rem;
    }
    .step-icon {
        width: 28px;
        height: 28px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.85rem;
        flex-shrink: 0;
    }
    .step-active {
        background: rgba(99, 102, 241, 0.2);
    }
    .step-done {
        background: rgba(52, 211, 153, 0.2);
    }

    /* --- Info panel --- */
    .info-panel {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 12px;
        padding: 1.5rem;
        margin-top: 1rem;
    }
    .info-panel h4 {
        color: #a5b4fc;
        margin: 0 0 0.75rem 0;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .info-panel p, .info-panel li {
        color: rgba(255, 255, 255, 0.55);
        font-size: 0.85rem;
        line-height: 1.7;
    }

    /* --- Hide streamlit branding --- */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* --- Button override --- */
    .stDownloadButton > button {
        background: linear-gradient(135deg, #4f46e5, #7c3aed) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.65rem 2rem !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 14px rgba(79, 70, 229, 0.4) !important;
    }
    .stDownloadButton > button:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(79, 70, 229, 0.5) !important;
    }
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# §3  Hero Header
# ──────────────────────────────────────────────

st.markdown("""
<div class="hero-container">
    <div class="hero-badge">🔒 LOCAL · PRIVACY-FIRST · DETERMINISTIC</div>
    <h1 class="hero-title">🛡️ Enterprise PII Redaction Engine</h1>
    <p class="hero-subtitle">
        Hybrid NLP pipeline combining <strong>spaCy NER</strong>,
        <strong>Microsoft Presidio</strong>, and domain-tuned regex recognizers
        to deterministically detect and redact sensitive entities from SEBI
        prospectuses and legal filings — entirely offline, with zero data exfiltration.
    </p>
</div>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# §4  Layout: Upload + Info Sidebar
# ──────────────────────────────────────────────

col_main, col_info = st.columns([3, 1.2])

with col_info:
    st.markdown("""
    <div class="info-panel">
        <h4>🧠 Detection Capabilities</h4>
        <ul>
            <li><strong>PERSON</strong> — Names via NER</li>
            <li><strong>IN_PAN</strong> — Indian PAN cards</li>
            <li><strong>IN_AADHAAR</strong> — Aadhaar numbers</li>
            <li><strong>IN_PHONE</strong> — +91 / STD / raw</li>
            <li><strong>EMAIL</strong> — RFC-5321 addresses</li>
            <li><strong>CREDIT_CARD</strong> — Luhn-validated</li>
            <li><strong>IP_ADDRESS</strong> — IPv4</li>
            <li><strong>US_SSN</strong> — Social Security</li>
            <li><strong>DATE (DOB)</strong> — Birth dates only</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-panel" style="margin-top: 1rem;">
        <h4>⚙️ Pipeline Architecture</h4>
        <p>
            <strong>Step 1:</strong> Load .docx via python-docx<br>
            <strong>Step 2:</strong> Traverse paragraphs, tables, headers<br>
            <strong>Step 3:</strong> Run-level PII detection (Presidio)<br>
            <strong>Step 4:</strong> Context filtering &amp; denylist<br>
            <strong>Step 5:</strong> Deterministic Faker replacement<br>
            <strong>Step 6:</strong> Save redacted copy
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-panel" style="margin-top: 1rem;">
        <h4>🛡️ Security Guarantees</h4>
        <p>
            ✅ Fully local — no cloud APIs<br>
            ✅ Deterministic — same input → same output<br>
            ✅ Formatting preserved — bold, color, size<br>
            ✅ Org names protected (KSH Intl Ltd)
        </p>
    </div>
    """, unsafe_allow_html=True)

with col_main:
    # ── File Upload ─────────────────────────────────
    st.markdown("### 📄 Upload Document")
    uploaded_file = st.file_uploader(
        "Drag and drop a .docx file or click to browse",
        type=["docx"],
        help="Supports Microsoft Word (.docx) documents up to 200MB.",
        label_visibility="collapsed",
    )

    if uploaded_file is not None:
        file_size_mb: float = len(uploaded_file.getvalue()) / (1024 * 1024)
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; gap: 0.75rem;
                        padding: 0.75rem 1rem; background: rgba(99, 102, 241, 0.08);
                        border-radius: 10px; border: 1px solid rgba(99, 102, 241, 0.15);
                        margin-bottom: 1rem;">
                <span style="font-size: 1.5rem;">📎</span>
                <div>
                    <p style="margin: 0; font-weight: 600; color: #e0e7ff;">
                        {uploaded_file.name}
                    </p>
                    <p style="margin: 0; font-size: 0.8rem; color: rgba(255,255,255,0.45);">
                        {file_size_mb:.2f} MB
                    </p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Redaction Controls ──────────────────────────
    run_col1, run_col2 = st.columns([1, 2])
    with run_col1:
        run_clicked: bool = st.button(
            "🚀 Run Redaction",
            disabled=uploaded_file is None,
            use_container_width=True,
            type="primary",
        )

    # ── Processing Pipeline ─────────────────────────
    if run_clicked and uploaded_file is not None:
        tmp_input_path: Optional[str] = None
        tmp_output_path: Optional[str] = None

        try:
            # --- Save uploaded file to temp location ---
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".docx", prefix="pii_input_"
            ) as tmp_in:
                tmp_in.write(uploaded_file.getvalue())
                tmp_input_path = tmp_in.name

            # --- Define output path ---
            tmp_output_fd, tmp_output_path = tempfile.mkstemp(
                suffix=".docx", prefix="pii_redacted_"
            )
            os.close(tmp_output_fd)

            # --- Run the pipeline ---
            with st.spinner(""):
                # Progress display
                progress_placeholder = st.empty()
                progress_placeholder.markdown("""
                <div style="padding: 1.5rem; background: rgba(99, 102, 241, 0.06);
                            border-radius: 12px; border: 1px solid rgba(99,102,241,0.15);">
                    <div class="pipeline-step">
                        <div class="step-icon step-active">⏳</div>
                        <span>Initialising Presidio + spaCy NER engine…</span>
                    </div>
                    <div class="pipeline-step">
                        <div class="step-icon step-active">📑</div>
                        <span>Parsing document structure (paragraphs, tables, headers)…</span>
                    </div>
                    <div class="pipeline-step">
                        <div class="step-icon step-active">🔍</div>
                        <span>Scanning for PII entities (run-level detection)…</span>
                    </div>
                    <div class="pipeline-step">
                        <div class="step-icon step-active">🔄</div>
                        <span>Applying deterministic Faker replacements…</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Import and execute
                from src.pii_redactor.parser import redact_document  # noqa: E402

                stats = redact_document(tmp_input_path, tmp_output_path)

                # Clear progress
                progress_placeholder.empty()

            # ── Results ─────────────────────────────
            st.markdown("""
            <div class="status-success">
                <p>✅ Redaction complete — document processed successfully.</p>
            </div>
            """, unsafe_allow_html=True)

            # Metric cards
            total_entities: int = stats.entities_redacted
            total_runs: int = stats.runs_modified
            total_paras: int = stats.paragraphs_scanned
            n_categories: int = len(stats.entity_breakdown)

            st.markdown(f"""
            <div class="metric-row">
                <div class="metric-card">
                    <p class="metric-value">{total_entities:,}</p>
                    <p class="metric-label">Entities Redacted</p>
                </div>
                <div class="metric-card">
                    <p class="metric-value">{total_runs:,}</p>
                    <p class="metric-label">Runs Modified</p>
                </div>
                <div class="metric-card">
                    <p class="metric-value">{total_paras:,}</p>
                    <p class="metric-label">Paragraphs Scanned</p>
                </div>
                <div class="metric-card">
                    <p class="metric-value">{n_categories}</p>
                    <p class="metric-label">Entity Categories</p>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Entity breakdown table
            if stats.entity_breakdown:
                sorted_entities = sorted(
                    stats.entity_breakdown.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
                rows_html: str = ""
                for etype, count in sorted_entities:
                    pct: float = (count / total_entities * 100) if total_entities else 0
                    bar_width: int = int(pct * 2)
                    rows_html += f"""
                    <tr>
                        <td><span class="entity-tag">{etype}</span></td>
                        <td class="entity-count">{count:,}</td>
                        <td style="color: rgba(255,255,255,0.45);">{pct:.1f}%</td>
                        <td>
                            <div style="background: rgba(99,102,241,0.15);
                                        border-radius: 4px; height: 8px;
                                        width: 200px; overflow: hidden;">
                                <div style="background: linear-gradient(90deg, #6366f1, #8b5cf6);
                                            height: 100%; width: {bar_width}px;
                                            border-radius: 4px;"></div>
                            </div>
                        </td>
                    </tr>
                    """

                st.markdown(f"""
                <table class="entity-table">
                    <thead>
                        <tr>
                            <th>Entity Type</th>
                            <th>Count</th>
                            <th>Share</th>
                            <th>Distribution</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
                """, unsafe_allow_html=True)

            # ── Download Button ─────────────────────
            st.markdown("<br>", unsafe_allow_html=True)

            if tmp_output_path and os.path.exists(tmp_output_path):
                with open(tmp_output_path, "rb") as f:
                    redacted_bytes: bytes = f.read()

                output_filename: str = (
                    f"Redacted_{uploaded_file.name}"
                    if not uploaded_file.name.lower().startswith("redacted")
                    else uploaded_file.name
                )

                st.download_button(
                    label="⬇️  Download Redacted Document",
                    data=redacted_bytes,
                    file_name=output_filename,
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    use_container_width=True,
                )

        except FileNotFoundError as exc:
            st.error(f"**File Error**: {exc}")
        except ValueError as exc:
            st.error(f"**Validation Error**: {exc}")
        except RuntimeError as exc:
            st.error(f"**Processing Error**: {exc}")
        except Exception as exc:
            st.error(f"**Unexpected Error**: {type(exc).__name__}: {exc}")

        finally:
            # ── Cleanup temp files ──────────────────
            if tmp_input_path and os.path.exists(tmp_input_path):
                try:
                    os.unlink(tmp_input_path)
                except OSError:
                    pass
            if tmp_output_path and os.path.exists(tmp_output_path):
                # Keep alive for download button — Streamlit reads lazily.
                # We schedule cleanup for the *next* rerun via session state.
                if "cleanup_paths" not in st.session_state:
                    st.session_state.cleanup_paths = []
                st.session_state.cleanup_paths.append(tmp_output_path)

    # ── Deferred cleanup from previous run ──────────
    if "cleanup_paths" in st.session_state and not run_clicked:
        for path in st.session_state.cleanup_paths:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError:
                pass
        st.session_state.cleanup_paths = []


# ──────────────────────────────────────────────
# §5  Footer
# ──────────────────────────────────────────────

st.markdown("---")
st.markdown(
    """
    <div style="text-align: center; padding: 1rem 0; color: rgba(255,255,255,0.3);
                font-size: 0.8rem;">
        <p>
            Built with <strong>spaCy</strong> · <strong>Presidio</strong> ·
            <strong>Faker</strong> · <strong>python-docx</strong> ·
            <strong>Streamlit</strong><br>
            🛡️ All processing happens locally — zero data leaves your machine.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)
