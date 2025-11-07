# vuln_analyzer.py
import os
import re
import io
import json
import sys
import nltk
import spacy
import unicodedata
import numpy as np
import pandas as pd
import requests
import warnings
from nltk.corpus import stopwords
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone
from dotenv import load_dotenv
from openai import OpenAI
from datetime import datetime

# ============================================================
# STEP 0: LIGHTWEIGHT LOGGER (ASCII ONLY)
# ============================================================
def _info(msg: str): print(f"INFO: {msg}")
def _ok(msg: str): print(f"OK: {msg}")
def _warn(msg: str): print(f"WARN: {msg}")
def _err(msg: str): print(f"ERROR: {msg}")

# ============================================================
# STEP 1: ENVIRONMENT SETUP
# ============================================================
load_dotenv()
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_HOST = os.getenv("PINECONE_HOST")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# OpenSearch config for FINAL (vuln-base-namespace)
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "https://10.10.3.25:9200")
OPENSEARCH_INDEX_FINAL = os.getenv("OPENSEARCH_INDEX_FINAL", "final")
OPENSEARCH_USERNAME = os.getenv("OPENSEARCH_USERNAME", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
OPENSEARCH_VERIFY_SSL = os.getenv("OPENSEARCH_VERIFY_SSL", "false").lower() == "true"

CVE_NAMESPACE = "cve-description"
CWE_NAMESPACE = "vuln-namespace"
FINAL_NAMESPACE = "vuln-base-namespace"  # kept for reference, but search now done in OpenSearch
UPLOAD_NAMESPACE = "vuln-base-namespace"

_missing_env = []
if not PINECONE_API_KEY: _missing_env.append("PINECONE_API_KEY")
if not PINECONE_HOST: _missing_env.append("PINECONE_HOST")
if not OPENAI_API_KEY: _missing_env.append("OPENAI_API_KEY")
if _missing_env:
    _err(f"Required configuration missing: {', '.join(_missing_env)}")
    _warn("Some features may not work (vector search / GPT). Continue at your own risk.")

# OpenSearch init note
_os_ok = True
try:
    if not OPENSEARCH_URL or not OPENSEARCH_INDEX_FINAL:
        _os_ok = False
        _warn("OpenSearch not configured; FINAL namespace queries will be skipped.")
    if not OPENSEARCH_VERIFY_SSL:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    _ok("OpenSearch configuration loaded")
except Exception as e:
    _os_ok = False
    _err(f"OpenSearch init warning: {e}")

# ============================================================
# STEP 2: NLP SETUP
# ============================================================
nltk.download("stopwords", quiet=True)
nltk.download("punkt", quiet=True)
nltk.download("wordnet", quiet=True)
nltk.download("omw-1.4", quiet=True)

def load_spacy_model():
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS  # type: ignore[attr-defined]
        model_path = os.path.join(base_path, "en_core_web_sm")
        return spacy.load(model_path)
    else:
        try:
            import en_core_web_sm  # type: ignore
            return en_core_web_sm.load()
        except Exception:
            return spacy.load("en_core_web_sm")

try:
    spacy_nlp = load_spacy_model()
    stop_words = set(stopwords.words("english"))
except Exception as e:
    _err(f"NLP model unavailable. Ensure 'en_core_web_sm' is installed. ({e})")
    # Safe fallbacks
    spacy_nlp = None
    stop_words = set()

def preprocess_text(text: str) -> str:
    if not isinstance(text, str) or not text.strip():
        return ""
    text = text.lower()
    text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
    if spacy_nlp is None:
        # Minimal fallback: whitespace tokenize
        tokens = [t for t in text.split() if t not in stop_words]
        return " ".join(tokens)
    doc = spacy_nlp(text)
    tokens = [t.lemma_ for t in doc if t.text not in stop_words and not t.is_punct and not t.is_space]
    return " ".join(tokens)

# ============================================================
# STEP 3: INITIALIZE MODEL & PINECONE
# ============================================================
_model_ok = True
try:
    _info("Initializing embedding model & Pinecone client...")
    # 384-dim model
    model = SentenceTransformer("all-MiniLM-L6-v2")
except Exception as e:
    _err(f"Couldn't load SentenceTransformer model: {e}")
    _model_ok = False
    model = None

_index_ok = True
try:
    if PINECONE_API_KEY and PINECONE_HOST:
        pc = Pinecone(api_key=PINECONE_API_KEY)
        index = pc.Index(host=PINECONE_HOST)
        _ok("Connected to Pinecone")
    else:
        _index_ok = False
        index = None  # type: ignore
        _warn("Pinecone not configured; CVE/CWE vector fetches will be skipped.")
except Exception as e:
    _index_ok = False
    index = None  # type: ignore
    _err(f"Pinecone connection failed: {e}")

# ============================================================
# STEP 4: OPENAI CLIENT
# ============================================================
_client_ok = True
try:
    if OPENAI_API_KEY:
        client = OpenAI(api_key=OPENAI_API_KEY)
    else:
        client = None  # type: ignore
        _client_ok = False
        _warn("OpenAI key not configured; GPT validation/remediation will be skipped.")
except Exception as e:
    _client_ok = False
    client = None  # type: ignore
    _err(f"OpenAI client init failed: {e}")

def ask_gpt_yes_no(desc_a: str, desc_b: str) -> str:
    if not _client_ok:
        _warn("OpenAI request skipped (no API key).")
        return "No"
    if not desc_a.strip() or not desc_b.strip():
        return "No"
    prompt = (
        "You are a cybersecurity analyst. Determine if the following two descriptions refer to the same "
        "or overlapping vulnerability. Respond only 'Yes' or 'No'.\n\n"
        f"Description A:\n{desc_a}\n\nDescription B:\n{desc_b}"
    )
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        answer = resp.choices[0].message.content.strip().lower()
        return "Yes" if "yes" in answer else "No"
    except Exception as e:
        _warn(f"OpenAI validation failed for a row (continuing without GPT): {e}")
        return "No"

def generate_remediation_summary(cwe_descriptions):
    if not _client_ok:
        _warn("OpenAI request skipped (no API key).")
        return ""
    text = " ".join([d for d in cwe_descriptions if isinstance(d, str) and d.strip()])
    if not text.strip():
        return ""
    prompt = (
        "You are a cybersecurity expert. Based on the following CWE vulnerability descriptions, "
        "suggest concise, actionable remediation steps.\n\n"
        f"{text}"
    )
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        _warn(f"OpenAI remediation generation failed (continuing without GPT): {e}")
        return ""

# ============================================================
# STEP 4.5: MANUAL-UPLOAD SPLIT (per-sheet right/ wrong) + CLEANER
# ============================================================
def _safe_name(s: str, fallback: str = "sheet") -> str:
    if not s:
        s = fallback
    s = unicodedata.normalize("NFKD", s)
    s = re.sub(r'[\\/:*?"<>|]', "_", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s or fallback

def _detect_header_and_data(df_no_header: pd.DataFrame):
    """
    Header row = first row with >= 2 non-empty cells.
    Must have at least one non-empty row below header.
    """
    header_row_idx = None
    for i, row in df_no_header.iterrows():
        if row.count() >= 2:
            header_row_idx = i
            break
    if header_row_idx is None:
        return None, False
    below = df_no_header.loc[header_row_idx + 1 :]
    has_data = below.notna().any(axis=1).any()
    return header_row_idx, has_data

def _export_df_to_single_sheet_xlsx(out_xlsx_path: str, df_no_header: pd.DataFrame):
    os.makedirs(os.path.dirname(out_xlsx_path), exist_ok=True)
    with pd.ExcelWriter(out_xlsx_path, engine="openpyxl") as writer:
        df_no_header.to_excel(writer, index=False, header=False, sheet_name="Sheet1")

def split_to_right_wrong_under_manual_upload(input_path: str) -> list:
    """
    For a manually provided Excel/CSV, create:
      uploads/manual_upload/<FileBase>/
        <FileBase>__right_sheetK__<Sheet>.xlsx
        <FileBase>__wrong_sheetM__<Sheet>.xlsx
        _intake_manifest.json
    Only return paths of RIGHT files.
    """
    base = os.path.splitext(os.path.basename(input_path))[0]
    parent = os.path.join("uploads", "manual_upload", _safe_name(base))
    os.makedirs(parent, exist_ok=True)

    manifest = {"file": os.path.basename(input_path), "sheets": []}
    right_paths: list[str] = []

    ext = os.path.splitext(input_path)[1].lower()

    # CSV -> single "sheet"
    if ext == ".csv":
        try:
            try:
                df = pd.read_csv(input_path, header=None, encoding="utf-8")
            except UnicodeDecodeError:
                df = pd.read_csv(input_path, header=None, encoding="latin-1")

            header_row_idx, has_data = _detect_header_and_data(df)
            if header_row_idx is not None and has_data:
                decision = "right"; reason = "header_found"
            else:
                decision = "wrong"; reason = "no_header_or_data"

            out_path = os.path.join(parent, f"{base}__{decision}_sheet1__CSV.xlsx")
            _export_df_to_single_sheet_xlsx(out_path, df)
            if decision == "right":
                right_paths.append(out_path)

            manifest["sheets"].append({
                "sheet_index": 1, "sheet_name": "CSV",
                "decision": decision.upper(), "reason": reason,
                "export_path": out_path
            })

        except Exception as e:
            manifest["sheets"].append({
                "sheet_index": 1, "sheet_name": "CSV",
                "decision": "SKIP", "reason": f"csv_load_error: {e}",
                "export_path": None
            })

        with open(os.path.join(parent, "_intake_manifest.json"), "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2, ensure_ascii=False)
        return right_paths

    # Excel (xls, xlsx, xlsm)
    try:
        xls = pd.ExcelFile(input_path)
        sheet_names = xls.sheet_names
    except Exception as e:
        with open(os.path.join(parent, "_intake_manifest.json"), "w", encoding="utf-8") as mf:
            json.dump({"error": f"workbook_open_error: {e}"}, mf, indent=2, ensure_ascii=False)
        return right_paths

    for idx, sheet in enumerate(sheet_names, start=1):
        try:
            df_raw = pd.read_excel(xls, sheet_name=sheet, header=None)
            header_row_idx, has_data = _detect_header_and_data(df_raw)

            if header_row_idx is not None and has_data:
                decision = "right"; reason = "header_found"
            else:
                decision = "wrong"; reason = "no_header_or_data"

            out_path = os.path.join(parent, f"{base}__{decision}_sheet{idx}__{_safe_name(str(sheet))}.xlsx")
            _export_df_to_single_sheet_xlsx(out_path, df_raw)
            if decision == "right":
                right_paths.append(out_path)

            manifest["sheets"].append({
                "sheet_index": idx, "sheet_name": str(sheet),
                "decision": decision.upper(), "reason": reason,
                "export_path": out_path
            })

        except Exception as e:
            manifest["sheets"].append({
                "sheet_index": idx, "sheet_name": str(sheet),
                "decision": "SKIP", "reason": f"sheet_load_error: {e}",
                "export_path": None
            })

    with open(os.path.join(parent, "_intake_manifest.json"), "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2, ensure_ascii=False)

    return right_paths

# ============================================================
# Short per-sheet folder resolver (for short filenames)
# ============================================================
_SHEET_TAG_RE = re.compile(r"__right_sheet(\d+)__|__sheet(\d+)__", re.IGNORECASE)

def _sheet_folder_for(path: str) -> str:
    """
    Given a per-sheet file path like:
      uploads/.../<ticket>/<file_name>/<file_name>__right_sheet3__SheetName.xlsx
    Return a stable folder path (no double nesting):
      uploads/.../<ticket>/<file_name>/sheet3
    If path is already inside sheetN/, return that folder as-is.
    """
    dir_name = os.path.dirname(path)
    # If already in a sheet folder, do not nest again
    if os.path.basename(dir_name).lower().startswith("sheet"):
        return dir_name

    base = os.path.basename(path)
    m = _SHEET_TAG_RE.search(base)
    sheet_idx = None
    if m:
        sheet_idx = m.group(1) or m.group(2)
    if not sheet_idx:
        sheet_idx = "1"

    out_dir = os.path.join(dir_name, f"sheet{sheet_idx}")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir

# ============================================================
# create_clean_copy — write to sheetN/clean.xlsx
# ============================================================
def create_clean_copy(original_path: str) -> str:
    """
    Make a cleaned Excel under 'sheetN/clean.xlsx':
      - Trim leading empty rows/cols
      - Use first non-empty row within trimmed block as header
    If cleaning fails, returns original_path.
    """
    try:
        df_raw = pd.read_excel(original_path, header=None)

        # all-empty?
        if df_raw.isna().all(axis=None):
            _warn(f"Nothing to process: the sheet is empty after reading -> {original_path}")
            return original_path

        non_empty_rows = df_raw.index[df_raw.notna().any(axis=1)]
        non_empty_cols = df_raw.columns[df_raw.notna().any(axis=0)]
        if len(non_empty_rows) == 0 or len(non_empty_cols) == 0:
            _warn(f"Nothing to process: the sheet is empty after trimming -> {original_path}")
            return original_path

        r0, r1 = non_empty_rows.min(), non_empty_rows.max()
        c0, c1 = non_empty_cols.min(), non_empty_cols.max()
        block = df_raw.loc[r0:r1, c0:c1].copy()

        # header detection
        header_idx = None
        for i in block.index:
            if block.loc[i].count() >= 2:
                header_idx = i
                break
        if header_idx is None:
            _warn(f"Could not find a header row (first non-empty row should contain column names) -> {original_path}")
            return original_path

        # must have rows below header
        if header_idx == block.index.max():
            _warn(f"Found headers but no data rows below -> {original_path}")
            return original_path

        header_values = [str(x).strip() for x in block.loc[header_idx].tolist()]
        if all((not h or h.lower().startswith("unnamed")) for h in header_values):
            _warn(f"Invalid headers: all empty/'Unnamed' -> {original_path}")
            return original_path

        data = block.loc[header_idx + 1 :].reset_index(drop=True)
        # fill headers; create placeholders for blanks
        data.columns = [h if h else f"col_{j}" for j, h in enumerate(header_values)]
        data = data.dropna(axis=1, how="all")

        out_dir = _sheet_folder_for(original_path)
        cleaned_path = os.path.join(out_dir, "clean.xlsx")
        data.to_excel(cleaned_path, index=False)

        _ok(f"Cleaned copy created -> {cleaned_path}")
        return cleaned_path
    except Exception as e:
        _warn(f"Cleaning failed for {original_path}: {e}")
        return original_path

# ============================================================
# STEP 5: COLUMN MAPPINGS
# ============================================================
COLUMN_MAPPINGS = {
    "title": [
        "title", "vulnerability name", "vulnerability", "vulnerability title",
        "plugin name", "name", "name of vulnerability", "vulnerability_name",
        "observation", "title / vulnerability", "issue", "vulnerability name (plugin name)"
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
        "arcon remarks", "developer comments", "arcon response", "dev sec comments"
    ],
    "cvecwe": ["cve/cwe", "cve", "cwe", "cwe id", "cvss3.1", "cve id", "cve_cwe"],
    "pluginoutput": ["plugin_output", "plugin output", "plugin text"]
}

# ============================================================
# STANDARDIZE + VALIDATE (with 'extra' support)
# ============================================================
def _standardize_and_validate(input_path, drop_empty=True):
    """
    Returns (standardized_df, warnings_list).
    - Maps known columns into canonical targets.
    - Concatenates ALL other (unmapped) columns into a single 'extra' column
      as 'header: value' pairs, pipe-separated per row.
    """
    warnings_list = []
    try:
        df = pd.read_excel(input_path)
    except Exception as e:
        _err(f"File is not a valid Excel sheet or is corrupted: {e}")
        return pd.DataFrame(), ["workbook_open_error"]

    if df.empty or df.isna().all(axis=None):
        warnings_list.append("sheet_empty")
        _warn("The cleaned sheet is empty. Nothing to process.")
        return pd.DataFrame(), warnings_list

    # detect if all headers unnamed/blank
    raw_headers = [str(h).strip().lower() for h in df.columns]
    if all((not h or h.startswith("unnamed")) for h in raw_headers):
        warnings_list.append("invalid_headers")
        _warn("Invalid headers: column names are empty/'Unnamed'.")

    # normalize headers
    df.columns = [c.strip().lower() for c in df.columns]
    standardized_df = pd.DataFrame()

    # Track which columns got mapped
    mapped_cols_total = set()

    # 1) Map known targets (exact matches from synonyms)
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

    # 2) Build 'extra' from all unmapped columns
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
            # Only keep if there's any non-empty content
            if (extra_series.astype(str).str.strip() != "").any():
                standardized_df["extra"] = extra_series

    # 3) Warnings if nothing mapped at all
    if standardized_df.empty:
        warnings_list.append("no_recognizable_columns")
        _warn("No recognizable columns found. Expected any of: Title, Description, Solution, CVE/CWE. Kept in 'extra' if present.")

    # If mapped but all mapped are entirely empty:
    if not standardized_df.empty and (standardized_df.replace("", np.nan).isna().all(axis=None)):
        warnings_list.append("mapped_columns_all_empty")
        _warn("Recognizable headers found, but their columns are empty (only 'extra' may have data).")

    return standardized_df, warnings_list

def standardize_vulnerability_sheet(input_path, drop_empty=True) -> pd.DataFrame:
    df, _ = _standardize_and_validate(input_path, drop_empty=drop_empty)
    return df

# ============================================================
# STEP 6: FETCH DESCRIPTIONS & ANALYSIS HELPERS (Pinecone for CVE/CWE)
# ============================================================
def fetch_description(entry: str) -> str:
    if not entry or not _index_ok:
        return ""
    try:
        if entry.upper().startswith("CVE-"):
            resp = index.query(namespace=CVE_NAMESPACE, top_k=1, include_metadata=True, id=entry.upper())
        else:
            resp = index.query(namespace=CWE_NAMESPACE, top_k=1, include_metadata=True, id=entry.lower())
        matches = resp.get("matches", [])
        if matches:
            return matches[0]["metadata"].get("description", "")
    except Exception as e:
        _warn(f"Vector fetch failed for {entry}: {e}")
    return ""

def fetch_top_cwes_for_text(text: str, top_k=3):
    if not text.strip() or not _model_ok or not _index_ok:
        return []
    try:
        emb = model.encode(preprocess_text(text)).tolist()
        resp = index.query(namespace=CWE_NAMESPACE, top_k=top_k, include_metadata=True, vector=emb)
        return [
            {"cwe_id": m["metadata"].get("cwe_id", ""), "description": m["metadata"].get("description", "")}
            for m in resp.get("matches", []) if m.get("score", 0) > 0
        ]
    except Exception as e:
        _warn(f"Error fetching CWEs for text: {e}")
        return []

def fetch_top_cwes_for_cve_description(cve_description: str, top_k=3):
    if not cve_description.strip() or not _model_ok or not _index_ok:
        return []
    try:
        emb = model.encode(preprocess_text(cve_description)).tolist()
        resp = index.query(namespace=CWE_NAMESPACE, top_k=top_k, include_metadata=True, vector=emb)
        return [
            {"cwe_id": m["metadata"].get("cwe_id", ""), "description": m["metadata"].get("description", "")}
            for m in resp.get("matches", []) if m.get("score", 0) > 0
        ]
    except Exception as e:
        _warn(f"Error fetching CWEs for CVE: {e}")
        return []

# ============================================================
# OpenSearch vector search helper for FINAL (vuln-base-namespace)
# ============================================================
def os_vector_search_final(embedding: list[float], top_k: int = 5, min_cosine: float = 0.60) -> list[dict]:
    """
    Query OpenSearch index=OPENSEARCH_INDEX_FINAL using cosineSimilarity on field 'vec'.
    Server-side threshold: min_score = min_cosine + 1.0 (because we add +1 shift in script).
    Returns list of dicts shaped like Pinecone matches:
      { 'id': <_id>, 'score': <cosine in [0..1]>, 'metadata': {...selected _source fields...} }
    """
    if not _os_ok:
        return []

    body = {
        "size": max(1, top_k),
        "track_total_hits": False,
        "min_score": float(min_cosine + 1.0),
        "_source": ["title", "description", "solution", "devseccomments", "source"],
        "query": {
            "script_score": {
                "query": { "match_all": {} },
                "script": {
                    "source": "cosineSimilarity(params.qv, doc['vec']) + 1.0",
                    "params": { "qv": embedding }
                }
            }
        }
    }

    url = f"{OPENSEARCH_URL.rstrip('/')}/{OPENSEARCH_INDEX_FINAL}/_search"
    try:
        r = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(body),
            auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD) if OPENSEARCH_USERNAME else None,
            verify=OPENSEARCH_VERIFY_SSL,
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
    except requests.HTTPError as e:
        _warn(f"OpenSearch HTTP error: {e.response.text if e.response is not None else e}")
        return []
    except Exception as e:
        _warn(f"OpenSearch request failed: {e}")
        return []

    hits = (data.get("hits") or {}).get("hits") or []
    results: list[dict] = []
    for h in hits:
        src = h.get("_source", {}) or {}
        raw_score = float(h.get("_score", 0.0))          # in [0,2] because of +1
        cosine = max(-1.0, min(1.0, raw_score - 1.0))    # back to [-1,1]
        # Pinecone-like shape, using cosine for 'score'
        results.append({
            "id": h.get("_id", ""),
            "score": float(cosine),
            "metadata": {
                "title": src.get("title", ""),
                "description": src.get("description", ""),
                "solution": src.get("solution", ""),
                "devseccomments": src.get("devseccomments", ""),
                "source": src.get("source", "")
            }
        })
    return results

# ============================================================
# STEP 7: ANALYZER CORE (Single Cleaned Sheet File)
# ============================================================
def analyze_clean_sheet_file(working_path, top_k=5, threshold=0.60):
    _info(f"Analyzing cleaned sheet -> {working_path}")

    # Standardize with validation (now includes 'extra')
    df, std_warnings = _standardize_and_validate(working_path, drop_empty=True)
    if df.empty:
        _err("No rows were processed for this sheet. No output files will be created.")
        return (None, None, None)

    df = df.replace([np.nan, np.inf, -np.inf], None)
    processed_rows = []
    skipped_rows = 0

    for idx, row in df.iterrows():
        title = str(row.get("title", "") or "")
        description = str(row.get("description", "") or "")
        solution = str(row.get("solution", "") or "")
        plugin_output = str(row.get("pluginoutput", "") or "")
        devsec = str(row.get("devseccomments", "") or "")
        cve_cwe_raw = str(row.get("cvecwe", "") or "")
        extra = str(row.get("extra", "") or "")

        # if nothing at all, skip
        if not any([title.strip(), description.strip(), solution.strip(), plugin_output.strip(),
                    devsec.strip(), cve_cwe_raw.strip(), extra.strip()]):
            _warn(f"Row {idx+1} skipped: no usable content (including 'extra').")
            skipped_rows += 1
            continue

        is_title_present = "Yes" if title.strip() else "No"
        is_description_present = "Yes" if description.strip() else "No"
        is_solution_present = "Yes" if solution.strip() else "No"

        cves = re.findall(r"CVE-\d{4}-\d+", cve_cwe_raw, flags=re.IGNORECASE)
        cwes = re.findall(r"CWE-\d+", cve_cwe_raw, flags=re.IGNORECASE)
        is_cve_present = "Yes" if cves else "No"
        is_cwe_present = "Yes" if cwes else "No"
        cve_list = sorted(set([c.upper() for c in cves]))
        cwe_list = sorted(set([c.upper() for c in cwes]))

        matched_cve, mismatched_cve, matched_cwe, mismatched_cwe = [], [], [], []
        for cve in cve_list:
            desc = fetch_description(cve)
            if not (title.strip() or description.strip() or solution.strip() or extra.strip() or plugin_output.strip()):
                matched_cve.append(cve)
                continue
            if ask_gpt_yes_no(desc, description or (title + " " + solution + " " + extra + " " + plugin_output)) == "Yes":
                matched_cve.append(cve)
            else:
                mismatched_cve.append(cve)

        for cwe in cwe_list:
            desc = fetch_description(cwe)
            if not (title.strip() or description.strip() or solution.strip() or extra.strip() or plugin_output.strip()):
                matched_cwe.append(cwe)
                continue
            if ask_gpt_yes_no(desc, description or (title + " " + solution + " " + extra + " " + plugin_output)) == "Yes":
                matched_cwe.append(cwe)
            else:
                mismatched_cwe.append(cwe)

        # Use text (including 'extra') to suggest CWEs
        text_for_cwe = description or (title + " " + solution + " " + extra + " " + plugin_output)
        related_cwes_from_text = fetch_top_cwes_for_text(text_for_cwe, top_k=3)
        cwe_from_text = [i.get("cwe_id", "") for i in related_cwes_from_text if i.get("cwe_id")]

        cwe_from_cve_ids, cwe_from_cve_descs = [], []
        for cve in matched_cve:
            cve_desc = fetch_description(cve)
            related_cwes = fetch_top_cwes_for_cve_description(cve_desc)
            for item in related_cwes:
                cwe_id = item.get("cwe_id", ""); desc = item.get("description", "")
                if cwe_id: cwe_from_cve_ids.append(cwe_id)
                if desc:   cwe_from_cve_descs.append(desc)

        # Build combined text (include 'extra' late in order)
        combined_parts = [title, description, solution, plugin_output, devsec, cve_cwe_raw]
        if extra.strip():
            combined_parts.append(extra)

        for cve in matched_cve:
            d = fetch_description(cve)
            if d: combined_parts.append(d)
        for cwe in matched_cwe:
            d = fetch_description(cwe)
            if d: combined_parts.append(d)
        for d in cwe_from_cve_descs:
            combined_parts.append(d)
        for item in related_cwes_from_text:
            if item.get("description", ""):
                combined_parts.append(item["description"])

        # Final combined text
        combined_text = " ".join(filter(None, combined_parts)).strip()

        # Embedding / vector search
        if not _model_ok:
            _warn("Vector model unavailable. This row will not include KB matches.")
            matches = []
        else:
            try:
                # truncate to a safe max length (avoid gigantic extras)
                if len(combined_text) > 10000:
                    combined_text = combined_text[:10000]
                cleaned_text = preprocess_text(combined_text)
                embedding = model.encode(cleaned_text).tolist()  # 384-dim

                # Use OpenSearch for FINAL matches
                matches = os_vector_search_final(embedding, top_k=top_k * 2, min_cosine=0.60)
            except Exception as e:
                _warn(f"Could not compute embeddings/query index for row {idx+1}: {e}")
                matches = []

        # 'matches' is Pinecone-like: each has id, score (cosine), metadata dict
        serialized_matches = []
        for m in matches:
            try:
                if float(m.get("score", 0.0)) >= 0.60:
                    serialized_matches.append({
                        "id": m.get("id", ""),
                        "score": float(m.get("score", 0.0)),
                        "metadata": dict(m.get("metadata", {}))
                    })
            except Exception:
                serialized_matches.append(str(m))
        all_logged_results = json.dumps(serialized_matches, indent=2, ensure_ascii=False)

        all_above_threshold = [
            {
                "id": m.get("id", ""),
                "score": round(float(m.get("score", 0.0)), 4),
                "title": (m.get("metadata") or {}).get("title", ""),
                "description": (m.get("metadata") or {}).get("description", ""),
                "solution": (m.get("metadata") or {}).get("solution", ""),
                "devseccomments": (m.get("metadata") or {}).get("devseccomments", "")
            }
            for m in matches if float(m.get("score", 0.0)) >= 0.60
        ]

        top_display = all_above_threshold[:top_k]
        devsec_summary = "\n".join([
            f"{i+1}. ID: {m['id']} | Score: {m['score']} | Comment: {m.get('devseccomments', '(no comment)')}"
            for i, m in enumerate(top_display)
        ])

        all_cwe_descs = []
        for cwe in (matched_cwe + cwe_from_text + cwe_from_cve_ids):
            d = fetch_description(cwe)
            if d: all_cwe_descs.append(d)

        general_remediation = generate_remediation_summary(all_cwe_descs)

        processed_rows.append({
            "title": title,
            "description": description,
            "solution": solution,
            "plugin_output": plugin_output,
            "devseccomments": devsec,
            "cve_cwe": cve_cwe_raw,
            "extra": extra,
            "is_title_present": is_title_present,
            "is_description_present": is_description_present,
            "is_solution_present": is_solution_present,
            "is_cve_present": is_cve_present,
            "is_cwe_present": is_cwe_present,
            "Cve": ", ".join(cve_list),
            "Cwe": ", ".join(cwe_list),
            "matched_cve": ", ".join(matched_cve),
            "mismatched_cve": ", ".join(mismatched_cve),
            "matched_cwe": ", ".join(matched_cwe),
            "mismatched_cwe": ", ".join(mismatched_cwe),
            "cwe_from_cve": ", ".join(sorted(set(cwe_from_cve_ids))),
            "cwe_from_text": ", ".join(sorted(set(cwe_from_text))),
            "top_devsec_summary": devsec_summary,
            "general_remediation_advice": general_remediation,
            "all_logged_results": all_logged_results
        })

    if not processed_rows:
        _err("No valid rows remained after validation/cleaning. No output files will be created.")
        return (None, None, None)

    if skipped_rows:
        _warn(f"{skipped_rows} row(s) were skipped due to missing content.")

    output_df = pd.DataFrame(processed_rows)

    # ---------- write outputs to short filenames in sheetN/, with clear prefixes ----------
    out_dir = _sheet_folder_for(working_path)

    # Derive ticket, file, and sheet identifiers from path
    parts = os.path.normpath(out_dir).split(os.sep)
    # Expected:
    #  - JIRA:   uploads/<ticket>/<file_name>/sheetN
    #  - Manual: uploads/manual_upload/<file_name>/sheetN
    if len(parts) >= 4 and parts[-4].lower() == "uploads":
        ticket_id = parts[-3]
        file_name = parts[-2]
    else:
        # Fallbacks
        ticket_id = "manual_upload" if "manual_upload" in parts else "ticket"
        file_name = parts[-2] if len(parts) >= 2 else "file"

    sheet_name = os.path.basename(out_dir)  # e.g., sheet1
    base_prefix = f"{ticket_id}_{file_name}_{sheet_name}"

    # 1) processed (detailed results)
    gpt_path = os.path.join(out_dir, f"{base_prefix}_processed.xlsx")
    try:
        output_df.to_excel(gpt_path, index=False)
        _ok(f"Wrote detailed results -> {gpt_path}")
    except Exception as e:
        _err(f"Could not save processed results: {e}")
        gpt_path = None

    # 2) merged (two GPT columns merged into clean.xlsx)
    merged_path = None
    try:
        cleaned_original_df = pd.read_excel(working_path)
        merged = cleaned_original_df.copy()
        for col in ["top_devsec_summary", "general_remediation_advice"]:
            merged[col] = ""
            if col in output_df.columns and not output_df.empty:
                n = min(len(merged), len(output_df[col]))
                if n > 0:
                    merged.loc[: n - 1, col] = output_df[col].iloc[:n].values

        merged_path = os.path.join(out_dir, f"{base_prefix}_merged.xlsx")
        merged.to_excel(merged_path, index=False)
        _ok(f"Wrote merged file -> {merged_path}")
    except Exception as e:
        _err(f"Could not merge into cleaned sheet (row-count/permission issue): {e}")
        merged_path = None

    # 3) missing (only rows without top_devsec_summary)
    missing_path = None
    try:
        if "top_devsec_summary" in output_df.columns:
            missing_summary_df = output_df[output_df["top_devsec_summary"].astype(str).str.strip() == ""]
            if not missing_summary_df.empty:
                missing_path = os.path.join(out_dir, f"{base_prefix}_missing.xlsx")
                missing_summary_df.to_excel(missing_path, index=False)
                _warn(f"Missing DevSec summaries exported -> {missing_path}")
        else:
            _warn("'top_devsec_summary' column absent in results; nothing to export as missing summaries.")
    except Exception as e:
        _warn(f"Failed to export missing-summary file: {e}")
        missing_path = None

    return gpt_path, merged_path, missing_path

# ============================================================
# STEP 8: PIPELINE FOR MANUAL INPUT (split -> clean -> analyze)
# ============================================================
def process_manual_file(input_path: str, top_k=5, threshold=0.60):
    """
    For a manually provided Excel/CSV:
      1) Split into RIGHT/WRONG per sheet under uploads/manual_upload/<FileBase>/
      2) For each RIGHT sheet file:
           - create a cleaned copy (sheetN/clean.xlsx)
           - analyze the cleaned copy and write outputs next to it
             (sheetN/<ticket>_<file>_sheetN_processed.xlsx, merged.xlsx, missing.xlsx)
    """
    _info(f"Manual input: {input_path}")
    right_sheet_paths = split_to_right_wrong_under_manual_upload(input_path)

    if not right_sheet_paths:
        _err("No RIGHT sheets detected. Nothing to analyze.")
        return []

    _ok(f"RIGHT sheets found: {len(right_sheet_paths)}")
    results = []
    for sheet_file in right_sheet_paths:
        _info(f"Preparing sheet: {sheet_file}")
        cleaned = create_clean_copy(sheet_file)
        working = cleaned if os.path.exists(cleaned) else sheet_file
        _info(f"Analyzing: {working}")
        results.append(analyze_clean_sheet_file(working, top_k=top_k, threshold=threshold))
    return results

# ============================================================
# MAIN ENTRY POINT (disabled here; controlled by main.py)
# ============================================================
if __name__ == "__main__":
    excel_path = input(" Enter full path to Excel/CSV file: ").strip()
    if not excel_path or not os.path.exists(excel_path):
        print(" Invalid path. Exiting.")
        sys.exit(0)
    process_manual_file(excel_path)
