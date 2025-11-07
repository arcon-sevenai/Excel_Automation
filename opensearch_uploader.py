# ============================================================
# MODULE 3: Uploader — Standardize Excel & Push to OpenSearch
# (env: OPENSEARCH_HOST, OPENSEARCH_USER, OPENSEARCH_PASS, OPENSEARCH_INDEX)
# ============================================================

import os
import re
import json
import pandas as pd
import numpy as np
from datetime import datetime
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
import spacy
import sys
from urllib.parse import urlparse

from opensearchpy import OpenSearch
from opensearchpy.exceptions import TransportError

# ============================================================
# STEP 1: ENVIRONMENT SETUP
# ============================================================
load_dotenv()

HOST_URL = os.getenv("OPENSEARCH_HOST", "https://localhost:9200")
OS_USER  = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS  = os.getenv("OPENSEARCH_PASS", "admin")
FINAL_INDEX = os.getenv("OPENSEARCH_INDEX", "final")

print("Initializing OpenSearch & NLP model...")
model = SentenceTransformer("all-MiniLM-L6-v2")
spacy_nlp = spacy.load("en_core_web_sm")

# Parse full URL (scheme://host:port)
u = urlparse(HOST_URL)
if not u.scheme or not u.hostname:
    raise RuntimeError(f"Invalid OPENSEARCH_HOST URL: {HOST_URL}")
scheme = u.scheme
host = u.hostname
port = u.port or (443 if scheme == "https" else 80)

# If you have self-signed certs, set verify_certs=False
os_client = OpenSearch(
    hosts=[{"host": host, "port": port, "scheme": scheme}],
    http_auth=(OS_USER, OS_PASS),
    verify_certs=False,           # change to True if you have proper certs
    ssl_show_warn=True,
    timeout=60,
)

# ============================================================
# STEP 1.1: Ensure index exists with proper KNN mapping
# ============================================================
def ensure_final_index():
    try:
        if os_client.indices.exists(index=FINAL_INDEX):
            return
    except TransportError as e:
        print(f"WARN: Index existence check failed (continuing): {e}")

    body = {
        "settings": {"index": {"knn": True}},
        "mappings": {
            "properties": {
                "vec": {
                    "type": "knn_vector",
                    "dimension": 384,
                    # If you prefer explicit cosine at index time, uncomment:
                    # "method": {
                    #   "name": "hnsw",
                    #   "space_type": "cosinesimil",
                    #   "engine": "nmslib"
                    # }
                },
                "title": {"type": "text"},
                "description": {"type": "text"},
                "solution": {"type": "text"},
                "devseccomments": {"type": "text"},
                "pluginoutput": {"type": "text"},
                "cve_cwe": {"type": "text"},
                "cves": {"type": "keyword"},
                "cwes": {"type": "keyword"},
                "extra": {"type": "text"},
                "created_at": {"type": "date"},
                "source": {"type": "keyword"}
            }
        }
    }
    try:
        os_client.indices.create(index=FINAL_INDEX, body=body)
        print(f"OK: Created index '{FINAL_INDEX}' with KNN mapping")
    except TransportError as e:
        print(f"WARN: Index create returned: {getattr(e, 'info', e)}")

ensure_final_index()

# ============================================================
# STEP 2: COLUMN MAPPINGS (Standardization)
# ============================================================
COLUMN_MAPPINGS = {
    "title": [
        "title", "vulnerability name", "vulnerability", "vulnerability title",
        "plugin name", "name", "name of vulnerability", "vulnerability_name",
        "observation", "title / vulnerability", "issue",
        "vulnerability name (plugin name)"
    ],
    "description": [
        "impact", "vulnerability description in detail", "likely impact",
        "description", "description and impact", "threat",
        "description/impact", "observation", "vulnerability description",
        "finding description"
    ],
    "solution": [
        "recommendation", "prevention", "remediation", "solution",
        "steps to remediate", "recommendation/countermeasure",
        "vulnerability solution"
    ],
    "devseccomments": [
        "devsec comments", "dev comment", "devsec suggestions", "devsec response",
        "arcon remarks", "developer comments", "arcon response", "dev sec comments",
        "top_devsec_summary"
    ],
    "cvecwe": [
        "cve/cwe", "cve", "cwe", "cwe id", "cvss3.1", "cve id", "cve_cwe",
        "cwe_from_text", "cwe_from_cve"
    ],
    "pluginoutput": ["plugin_output", "plugin output", "plugin text", "pluginoutput"]
}

# ============================================================
# STEP 3: TEXT PREPROCESSING
# ============================================================
def preprocess_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
    doc = spacy_nlp(text)
    tokens = [t.lemma_ for t in doc if not t.is_stop and not t.is_punct and not t.is_space]
    return " ".join(tokens)

# ============================================================
# STEP 4: STANDARDIZATION FUNCTION (with `extra`)
# ============================================================
def standardize_vulnerability_sheet(input_path, drop_empty=True) -> pd.DataFrame:
    """
    - Maps known headers to canonical columns per COLUMN_MAPPINGS.
    - Any unmapped columns are concatenated into a single `extra` column
      as 'header: value' pairs joined by ' | '.
    """
    df = pd.read_excel(input_path)
    if df.empty or df.isna().all(axis=None):
        return pd.DataFrame()

    df.columns = [str(c).strip().lower() for c in df.columns]
    standardized_df = pd.DataFrame()

    mapped_cols_total = set()

    # Map known columns
    for target_col, synonyms in COLUMN_MAPPINGS.items():
        matched_cols = []
        for synonym in synonyms:
            s = synonym.strip().lower()
            for col in df.columns:
                if s == col and col not in matched_cols:
                    matched_cols.append(col)
        if matched_cols:
            mapped_cols_total.update(matched_cols)
            combined_series = df[matched_cols].apply(
                lambda row: " | ".join(
                    [str(x).strip() for x in row
                     if pd.notna(x) and str(x).strip() != "" and str(x).lower() != "nan"]
                ),
                axis=1
            )
            standardized_df[target_col] = combined_series
        elif not drop_empty:
            standardized_df[target_col] = ""

    # Build `extra` from all unmapped columns
    unmapped_cols = [c for c in df.columns if c not in mapped_cols_total]

    def _row_to_extra(row):
        items = []
        for col in unmapped_cols:
            val = row.get(col, None)
            if pd.notna(val):
                sval = str(val).strip()
                if sval and sval.lower() != "nan":
                    items.append(f"{col}: {sval}")
        return " | ".join(items)

    if unmapped_cols:
        extra_series = df.apply(_row_to_extra, axis=1)
        if not drop_empty:
            standardized_df["extra"] = extra_series
        else:
            if (extra_series.astype(str).str.strip() != "").any():
                standardized_df["extra"] = extra_series

    if drop_empty and not standardized_df.empty:
        standardized_df = standardized_df.loc[:, (standardized_df.astype(str).apply(lambda s: s.str.strip() != "")).any(axis=0)]

    return standardized_df

# ============================================================
# STEP 5: PUSH TO OPENSEARCH
# ============================================================
def push_to_opensearch(excel_path):
    print(f"\nReading Excel for upload: {excel_path}")

    df = standardize_vulnerability_sheet(excel_path, drop_empty=False)
    df = df.replace([np.nan, np.inf, -np.inf], "")

    if df.empty:
        print("Excel has no valid rows. Exiting.")
        return

    uploaded = 0
    for _, row in df.iterrows():
        title = str(row.get("title", "") or "")
        description = str(row.get("description", "") or "")
        solution = str(row.get("solution", "") or "")
        plugin_output = str(row.get("pluginoutput", "") or "")
        devsec_summary = str(row.get("devseccomments", "") or "")
        cve_cwe_raw = str(row.get("cvecwe", "") or "")
        extra = str(row.get("extra", "") or "")

        # Extract CVEs / CWEs
        cves = re.findall(r"CVE-\d{4}-\d+", cve_cwe_raw, flags=re.IGNORECASE)
        cwes = re.findall(r"CWE-\d+", cve_cwe_raw, flags=re.IGNORECASE)

        # Combine text for embedding (include `extra` at the end)
        combined_text_parts = [title, description, solution, plugin_output, devsec_summary, cve_cwe_raw]
        if extra.strip():
            combined_text_parts.append(extra)
        combined_text = " ".join([p for p in combined_text_parts if p]).strip()

        if len(combined_text) > 10000:
            combined_text = combined_text[:10000]

        cleaned_text = preprocess_text(combined_text)
        if not cleaned_text:
            continue

        embedding = model.encode(cleaned_text).tolist()  # 384-dim

        doc = {
            "vec": embedding,
            "title": title,
            "description": description,
            "solution": solution,
            "devseccomments": devsec_summary,
            "pluginoutput": plugin_output,
            "cve_cwe": cve_cwe_raw,
            "cves": ", ".join(cves),
            "cwes": ", ".join(cwes),
            "extra": extra,
            "created_at": datetime.utcnow().isoformat(),
            "source": "Human Verified Upload"
        }

        vector_id = f"vuln-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        try:
            os_client.index(index=FINAL_INDEX, id=vector_id, body=doc, refresh=False)
            uploaded += 1
            print("-" * 60)
            print(f"Uploaded Doc ID: {vector_id}")
            print(f"  - Title: {title[:60] or '(no title)'}")
            print(f"  - CVEs: {', '.join(cves) or 'None'}")
            print(f"  - CWEs: {', '.join(cwes) or 'None'}")
            print(f"  - Created At: {doc['created_at']}")
            print("-" * 60)
        except Exception as e:
            print(f"Failed to index {vector_id}: {e}")

    try:
        os_client.indices.refresh(index=FINAL_INDEX)
    except Exception:
        pass

    print(f"\nUpload complete — {uploaded} records added to index '{FINAL_INDEX}'.")

# ============================================================
# STEP 6: MAIN ENTRY POINT
# ============================================================
if __name__ == "__main__":
    excel_path = input("Enter full path to Excel file to upload: ").strip()
    if not excel_path or not os.path.exists(excel_path):
        print("Invalid path. Exiting.")
        sys.exit(0)
    push_to_opensearch(excel_path)
