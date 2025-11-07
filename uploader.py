# # ============================================================
# # MODULE 3: Uploader — Standardize Excel & Push to Pinecone
# # ============================================================

# import os
# import re
# import json
# import pandas as pd
# import numpy as np
# from datetime import datetime
# from sentence_transformers import SentenceTransformer
# from pinecone import Pinecone
# from dotenv import load_dotenv
# import spacy
# import sys

# # ============================================================
# # STEP 1: ENVIRONMENT SETUP
# # ============================================================
# load_dotenv()
# PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
# PINECONE_HOST = os.getenv("PINECONE_HOST")

# UPLOAD_NAMESPACE = "vuln-base-namespace"

# print(" Initializing Pinecone & NLP model...")
# model = SentenceTransformer("all-MiniLM-L6-v2")
# pc = Pinecone(api_key=PINECONE_API_KEY)
# index = pc.Index(host=PINECONE_HOST)
# spacy_nlp = spacy.load("en_core_web_sm")

# # ============================================================
# # STEP 2: COLUMN MAPPINGS (Standardization)
# # ============================================================
# COLUMN_MAPPINGS = {
#     "title": ["title", "vulnerability name", "vulnerability", "vulnerability title",
#               "plugin name", "name", "name of vulnerability", "vulnerability_name",
#               "observation", "title / vulnerability", "issue", "Vulnerability Name (Plugin Name)"],
#     "description": ["impact", "vulnerability description in detail", "likely impact",
#                     "description", "description and impact", "threat",
#                     "description/impact", "observation", "vulnerability description",
#                     "finding description"],
#     "solution": ["recommendation", "prevention", "remediation", "solution",
#                  "steps to remediate", "recommendation/countermeasure",
#                  "vulnerability solution"],
#     "devseccomments": ["devsec comments", "dev comment", "devsec suggestions", "devsec response",
#                        "arcon remarks", "developer comments", "arcon response", "dev sec comments","top_devsec_summary"],
#     "cvecwe": ["cve/cwe", "cve", "cwe", "cwe id", "cvss3.1", "cve id", "cve_cwe","cwe_from_text", "cwe_from_cve"],
#     "pluginoutput": ["plugin_output", "plugin output"]
# }

# # ============================================================
# # STEP 3: TEXT PREPROCESSING
# # ============================================================
# def preprocess_text(text: str) -> str:
#     if not isinstance(text, str):
#         return ""
#     text = text.lower()
#     text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
#     doc = spacy_nlp(text)
#     tokens = [token.lemma_ for token in doc if not token.is_stop and not token.is_punct and not token.is_space]
#     return " ".join(tokens)

# # ============================================================
# # STEP 4: STANDARDIZATION FUNCTION
# # ============================================================
# def standardize_vulnerability_sheet(input_path, drop_empty=True) -> pd.DataFrame:
#     df = pd.read_excel(input_path)
#     df.columns = [c.strip().lower() for c in df.columns]
#     standardized_df = pd.DataFrame()

#     for target_col, synonyms in COLUMN_MAPPINGS.items():
#         matched_cols = []
#         for synonym in synonyms:
#             for col in df.columns:
#                 if synonym.strip().lower() == col and col not in matched_cols:
#                     matched_cols.append(col)
#         if matched_cols:
#             combined_series = df[matched_cols].apply(
#                 lambda row: " | ".join(
#                     [str(x).strip() for x in row if pd.notna(x) and str(x).strip() != "" and str(x).lower() != "nan"]
#                 ),
#                 axis=1
#             )
#             standardized_df[target_col] = combined_series
#         elif not drop_empty:
#             standardized_df[target_col] = ""

#     if drop_empty:
#         standardized_df = standardized_df.loc[:, (standardized_df != "").any(axis=0)]
#     return standardized_df

# # ============================================================
# # STEP 5: PUSH TO PINECONE
# # ============================================================
# def push_to_pinecone(excel_path):
#     print(f"\n Reading Excel for upload: {excel_path}")

#     df = standardize_vulnerability_sheet(excel_path, drop_empty=False)
#     df = df.replace([np.nan, np.inf, -np.inf], "")

#     if df.empty:
#         print(" Excel has no valid rows. Exiting.")
#         return

#     uploaded = 0
#     for _, row in df.iterrows():
#         title = str(row.get("title", "") or "")
#         description = str(row.get("description", "") or "")
#         solution = str(row.get("solution", "") or "")
#         plugin_output = str(row.get("pluginoutput", "") or "")
#         devsec_summary = str(row.get("devseccomments", "") or "")
#         cve_cwe_raw = str(row.get("cvecwe", "") or "")

#         # Extract CVEs / CWEs
#         cves = re.findall(r"CVE-\d{4}-\d+", cve_cwe_raw, flags=re.IGNORECASE)
#         cwes = re.findall(r"CWE-\d+", cve_cwe_raw, flags=re.IGNORECASE)

#         # Combine text for embedding
#         combined_text = " ".join([title, description, solution, plugin_output,devsec_summary, cve_cwe_raw]).strip()
#         cleaned_text = preprocess_text(combined_text)
#         if not cleaned_text:
#             continue

#         embedding = model.encode(cleaned_text).tolist()

#         # Metadata
#         metadata = {
#             "title": title,
#             "description": description,
#             "solution": solution,
#             "devseccomments": devsec_summary,
#             "plugin_output": plugin_output,
#             "cve_cwe": cve_cwe_raw,
#             "cves": ", ".join(cves),
#             "cwes": ", ".join(cwes),
#             "created_at": datetime.utcnow().isoformat(),
#             "source": "Human Verified Upload"
#         }

#         vector_id = f"vuln-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
#         try:
#             index.upsert(
#                 vectors=[{"id": vector_id, "values": embedding, "metadata": metadata}],
#                 namespace=UPLOAD_NAMESPACE
#             )
#             uploaded += 1
#             print("──────────────────────────────────────────────")
#             print(f" Uploaded Vector ID: {vector_id}")
#             print(f"   ├─ Title: {title[:60] or '(no title)'}")
#             print(f"   ├─ CVEs: {', '.join(cves) or 'None'}")
#             print(f"   ├─ CWEs: {', '.join(cwes) or 'None'}")
#             print(f"   └─ Created At: {metadata['created_at']}")
#             print("──────────────────────────────────────────────")
#         except Exception as e:
#             print(f" Failed to upload {vector_id}: {e}")

#     print(f"\n Upload complete — {uploaded} records added to namespace '{UPLOAD_NAMESPACE}'.")

# # ============================================================
# # STEP 6: MAIN ENTRY POINT
# # ============================================================
# # if __name__ == "__main__":
# #     excel_path = input(" Enter full path to Excel file to upload: ").strip()
# #     if not excel_path or not os.path.exists(excel_path):
# #         print(" Invalid path. Exiting.")
# #         sys.exit(0)

# #     push_to_pinecone(excel_path)


























# ============================================================
# MODULE 3: Uploader — Standardize Excel & Push to Pinecone
# (updated: add 'extra' column from unmapped headers and include it in embeddings)
# ============================================================

import os
import re
import json
import pandas as pd
import numpy as np
from datetime import datetime
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone
from dotenv import load_dotenv
import spacy
import sys

# ============================================================
# STEP 1: ENVIRONMENT SETUP
# ============================================================
load_dotenv()
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_HOST = os.getenv("PINECONE_HOST")

UPLOAD_NAMESPACE = "vuln-base-namespace"

print(" Initializing Pinecone & NLP model...")
model = SentenceTransformer("all-MiniLM-L6-v2")
pc = Pinecone(api_key=PINECONE_API_KEY)
index = pc.Index(host=PINECONE_HOST)
spacy_nlp = spacy.load("en_core_web_sm")

# ============================================================
# STEP 2: COLUMN MAPPINGS (Standardization)
# ============================================================
COLUMN_MAPPINGS = {
    "title": ["title", "vulnerability name", "vulnerability", "vulnerability title",
              "plugin name", "name", "name of vulnerability", "vulnerability_name",
              "observation", "title / vulnerability", "issue", "vulnerability name (plugin name)",
              "vulnerability name (plugin name)"],
    "description": ["impact", "vulnerability description in detail", "likely impact",
                    "description", "description and impact", "threat",
                    "description/impact", "observation", "vulnerability description",
                    "finding description"],
    "solution": ["recommendation", "prevention", "remediation", "solution",
                 "steps to remediate", "recommendation/countermeasure",
                 "vulnerability solution"],
    "devseccomments": ["devsec comments", "dev comment", "devsec suggestions", "devsec response",
                       "arcon remarks", "developer comments", "arcon response", "dev sec comments",
                       "top_devsec_summary"],
    "cvecwe": ["cve/cwe", "cve", "cwe", "cwe id", "cvss3.1", "cve id", "cve_cwe",
               "cwe_from_text", "cwe_from_cve"],
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
    tokens = [token.lemma_ for token in doc if not token.is_stop and not token.is_punct and not token.is_space]
    return " ".join(tokens)

# ============================================================
# STEP 4: STANDARDIZATION FUNCTION (with `extra`)
# ============================================================
def standardize_vulnerability_sheet(input_path, drop_empty=True) -> pd.DataFrame:
    """
    - Maps known headers to canonical columns per COLUMN_MAPPINGS.
    - Any *unmapped* columns are concatenated into a single `extra` column
      as 'header: value' pairs joined by ' | '.
    """
    df = pd.read_excel(input_path)
    if df.empty or df.isna().all(axis=None):
        return pd.DataFrame()

    # normalize headers
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

    # Drop empty columns if requested
    if drop_empty and not standardized_df.empty:
        standardized_df = standardized_df.loc[:, (standardized_df.astype(str).apply(lambda s: s.str.strip() != "")).any(axis=0)]

    return standardized_df

# ============================================================
# STEP 5: PUSH TO PINECONE
# ============================================================
def push_to_pinecone(excel_path):
    print(f"\n Reading Excel for upload: {excel_path}")

    df = standardize_vulnerability_sheet(excel_path, drop_empty=False)
    df = df.replace([np.nan, np.inf, -np.inf], "")

    if df.empty:
        print(" Excel has no valid rows. Exiting.")
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

        # (Optional) Cap extremely long text to protect latency/costs
        if len(combined_text) > 10000:
            combined_text = combined_text[:10000]

        cleaned_text = preprocess_text(combined_text)
        if not cleaned_text:
            continue

        embedding = model.encode(cleaned_text).tolist()

        # Metadata — include `extra` for traceability
        metadata = {
            "title": title,
            "description": description,
            "solution": solution,
            "devseccomments": devsec_summary,
            "plugin_output": plugin_output,
            "cve_cwe": cve_cwe_raw,
            "cves": ", ".join(cves),
            "cwes": ", ".join(cwes),
            "extra": extra,
            "created_at": datetime.utcnow().isoformat(),
            "source": "Human Verified Upload"
        }

        vector_id = f"vuln-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        try:
            index.upsert(
                vectors=[{"id": vector_id, "values": embedding, "metadata": metadata}],
                namespace=UPLOAD_NAMESPACE
            )
            uploaded += 1
            print("──────────────────────────────────────────────")
            print(f" Uploaded Vector ID: {vector_id}")
            print(f"   ├─ Title: {title[:60] or '(no title)'}")
            print(f"   ├─ CVEs: {', '.join(cves) or 'None'}")
            print(f"   ├─ CWEs: {', '.join(cwes) or 'None'}")
            print(f"   └─ Created At: {metadata['created_at']}")
            print("──────────────────────────────────────────────")
        except Exception as e:
            print(f" Failed to upload {vector_id}: {e}")

    print(f"\n Upload complete — {uploaded} records added to namespace '{UPLOAD_NAMESPACE}'.")

# ============================================================
# STEP 6: MAIN ENTRY POINT
# ============================================================
# if __name__ == "__main__":
#     excel_path = input(" Enter full path to Excel file to upload: ").strip()
#     if not excel_path or not os.path.exists(excel_path):
#         print(" Invalid path. Exiting.")
#         sys.exit(0)
#     push_to_pinecone(excel_path)
