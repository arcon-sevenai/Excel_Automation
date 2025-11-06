# import os
# import re
# import io
# import json
# import sys
# import nltk
# import spacy
# import numpy as np
# import pandas as pd
# from nltk.corpus import stopwords
# from sentence_transformers import SentenceTransformer
# from pinecone import Pinecone
# from dotenv import load_dotenv
# from openai import OpenAI
# from datetime import datetime
# import requests

# # ============================================================
# # STEP 1: ENVIRONMENT SETUP
# # ============================================================
# load_dotenv()
# PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
# PINECONE_HOST = os.getenv("PINECONE_HOST")
# OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# CVE_NAMESPACE = "cve-description"
# CWE_NAMESPACE = "vuln-namespace"
# FINAL_NAMESPACE = "vuln-base-namespace"
# UPLOAD_NAMESPACE = "vuln-base-namespace"

# # ============================================================
# # STEP 2: NLP SETUP
# # ============================================================
# nltk.download("stopwords", quiet=True)
# nltk.download("punkt", quiet=True)
# nltk.download("wordnet", quiet=True)
# nltk.download("omw-1.4", quiet=True)

# def load_spacy_model():
#     if getattr(sys, 'frozen', False):
#         base_path = sys._MEIPASS
#         model_path = os.path.join(base_path, "en_core_web_sm")
#         return spacy.load(model_path)
#     else:
#         try:
#             import en_core_web_sm
#             return en_core_web_sm.load()
#         except Exception:
#             return spacy.load("en_core_web_sm")

# spacy_nlp = load_spacy_model()
# stop_words = set(stopwords.words("english"))

# def preprocess_text(text: str) -> str:
#     if not isinstance(text, str):
#         return ""
#     text = text.lower()
#     text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
#     doc = spacy_nlp(text)
#     tokens = [token.lemma_ for token in doc if token.text not in stop_words and not token.is_punct and not token.is_space]
#     return " ".join(tokens)

# # ============================================================
# # STEP 3: INITIALIZE MODEL & PINECONE
# # ============================================================
# print(" Initializing model & Pinecone client...")
# model = SentenceTransformer("all-MiniLM-L6-v2")
# pc = Pinecone(api_key=PINECONE_API_KEY)
# index = pc.Index(host=PINECONE_HOST)
# print(" Connected to Pinecone")

# # ============================================================
# # STEP 4: OPENAI CLIENT
# # ============================================================
# client = OpenAI(api_key=OPENAI_API_KEY)

# def ask_gpt_yes_no(desc_a: str, desc_b: str) -> str:
#     if not desc_a.strip() or not desc_b.strip():
#         return "No"
#     prompt = (
#         "You are a cybersecurity analyst. Determine if the following two descriptions refer to the same "
#         "or overlapping vulnerability. Respond only 'Yes' or 'No'.\n\n"
#         f"Description A:\n{desc_a}\n\nDescription B:\n{desc_b}"
#     )
#     try:
#         response = client.chat.completions.create(
#             model="gpt-4o-mini",
#             messages=[{"role": "user", "content": prompt}],
#             temperature=0.2,
#         )
#         answer = response.choices[0].message.content.strip().lower()
#         return "Yes" if "yes" in answer else "No"
#     except Exception as e:
#         print(f" GPT validation failed: {e}")
#         return "No"

# def generate_remediation_summary(cwe_descriptions):
#     text = " ".join([d for d in cwe_descriptions if isinstance(d, str) and d.strip()])
#     if not text.strip():
#         return ""
#     prompt = (
#         "You are a cybersecurity expert. Based on the following CWE vulnerability descriptions, "
#         "suggest concise, actionable remediation steps.\n\n"
#         f"{text}"
#     )
#     try:
#         response = client.chat.completions.create(
#             model="gpt-4o-mini",
#             messages=[{"role": "user", "content": prompt}],
#             temperature=0.3,
#         )
#         # print(response.choices[0].message.content.strip())
#         return response.choices[0].message.content.strip()
#     except Exception as e:
#         print(f" GPT generation failed: {e}")
#         return ""

# # ============================================================
# # STEP 5: COLUMN MAPPINGS
# # ============================================================
# COLUMN_MAPPINGS = {
#     "title": ["title", "vulnerability name", "vulnerability", "vulnerability title",
#                "plugin name", "name", "name of vulnerability", "vulnerability_name",
#                "observation", "title / vulnerability", "issue","Vulnerability Name (Plugin Name)"],
#     "description": ["impact", "vulnerability description in detail", "likely impact",
#                     "description", "description and impact", "threat",
#                     "description/impact", "observation", "vulnerability description",
#                     "finding description"],
#     "solution": ["recommendation", "prevention", "remediation", "solution",
#                  "steps to remediate", "recommendation/countermeasure",
#                  "vulnerability solution"],
#     "devseccomments": ["devsec comments", "dev comment", "devsec suggestions", "devsec response",
#                        "arcon remarks", "developer comments", "arcon response", "dev sec comments"],
#     "cvecwe": ["cve/cwe", "cve", "cwe", "cwe id", "cvss3.1", "cve id", "cve_cwe"],
#     "pluginoutput": ["plugin_output", "plugin output","Plugin Text"]
# }

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
#                 lambda row: " | ".join([str(x).strip() for x in row if pd.notna(x) and str(x).strip() != "" and str(x).lower() != "nan"]),
#                 axis=1
#             )
#             standardized_df[target_col] = combined_series
#         elif not drop_empty:
#             standardized_df[target_col] = ""
#     if drop_empty:
#         standardized_df = standardized_df.loc[:, (standardized_df != "").any(axis=0)]
#     return standardized_df

# # ============================================================
# # STEP 6: FETCH DESCRIPTIONS & ANALYSIS HELPERS
# # ============================================================
# def fetch_description(entry: str) -> str:
#     if not entry:
#         return ""
#     try:
#         if entry.upper().startswith("CVE-"):
#             resp = index.query(namespace=CVE_NAMESPACE, top_k=1, include_metadata=True, id=entry.upper())
#         else:
#             resp = index.query(namespace=CWE_NAMESPACE, top_k=1, include_metadata=True, id=entry.lower())
#         matches = resp.get("matches", [])
#         if matches:
#             return matches[0]["metadata"].get("description", "")
#     except Exception as e:
#         print(f" Fetch failed for {entry}: {e}")
#     return ""

# def fetch_top_cwes_for_text(text: str, top_k=3):
#     if not text.strip():
#         return []
#     try:
#         emb = model.encode(preprocess_text(text)).tolist()
#         resp = index.query(namespace=CWE_NAMESPACE, top_k=top_k, include_metadata=True, vector=emb)
#         return [
#             {"cwe_id": m["metadata"].get("cwe_id", ""), "description": m["metadata"].get("description", "")}
#             for m in resp.get("matches", []) if m.get("score", 0) > 0
#         ]
#     except Exception as e:
#         print(f" Error fetching CWEs for text: {e}")
#         return []

# def fetch_top_cwes_for_cve_description(cve_description: str, top_k=3):
#     if not cve_description.strip():
#         return []
#     try:
#         emb = model.encode(preprocess_text(cve_description)).tolist()
#         resp = index.query(namespace=CWE_NAMESPACE, top_k=top_k, include_metadata=True, vector=emb)
#         return [
#             {"cwe_id": m["metadata"].get("cwe_id", ""), "description": m["metadata"].get("description", "")}
#             for m in resp.get("matches", []) if m.get("score", 0) > 0
#         ]
#     except Exception as e:
#         print(f" Error fetching CWEs for CVE: {e}")
#         return []

# # ============================================================
# # STEP 7: MAIN ANALYZER (Single Excel File)
# # ============================================================
# def process_excel_file(input_path, top_k=5, threshold=0.60):
#     print(f"\n Reading Excel: {input_path}")
#     df = standardize_vulnerability_sheet(input_path, drop_empty=True)
#     df = df.replace([np.nan, np.inf, -np.inf], None)
#     processed_rows = []

#     for _, row in df.iterrows():
#         title = str(row.get("title", "") or "")
#         description = str(row.get("description", "") or "")
#         solution = str(row.get("solution", "") or "")
#         cve_cwe_raw = str(row.get("cvecwe", "") or "")

#         # Presence flags
#         is_title_present = "Yes" if title.strip() else "No"
#         is_description_present = "Yes" if description.strip() else "No"
#         is_solution_present = "Yes" if solution.strip() else "No"

#         cves = re.findall(r"CVE-\d{4}-\d+", cve_cwe_raw, flags=re.IGNORECASE)
#         cwes = re.findall(r"CWE-\d+", cve_cwe_raw, flags=re.IGNORECASE)
#         is_cve_present = "Yes" if cves else "No"
#         is_cwe_present = "Yes" if cwes else "No"
#         cve_list = sorted(set([c.upper() for c in cves]))
#         cwe_list = sorted(set([c.upper() for c in cwes]))

#         matched_cve, mismatched_cve, matched_cwe, mismatched_cwe = [], [], [], []
#         for cve in cve_list:
#             desc = fetch_description(cve)
#             if not (title.strip() or description.strip() or solution.strip()):
#                 matched_cve.append(cve)
#                 continue
#             if ask_gpt_yes_no(desc, description or (title + " " + solution)) == "Yes":
#                 matched_cve.append(cve)
#             else:
#                 mismatched_cve.append(cve)
#         for cwe in cwe_list:
#             desc = fetch_description(cwe)
#             if not (title.strip() or description.strip() or solution.strip()):
#                 matched_cwe.append(cwe)
#                 continue
#             if ask_gpt_yes_no(desc, description or (title + " " + solution)) == "Yes":
#                 matched_cwe.append(cwe)
#             else:
#                 mismatched_cwe.append(cwe)

#         related_cwes_from_text = fetch_top_cwes_for_text(description or (title + " " + solution), top_k=3)
#         cwe_from_text = [i.get("cwe_id", "") for i in related_cwes_from_text if i.get("cwe_id")]

#         # CWEs inferred from matched CVEs
#         cwe_from_cve_ids = []
#         cwe_from_cve_descs = []
#         for cve in matched_cve:
#             cve_desc = fetch_description(cve)
#             related_cwes = fetch_top_cwes_for_cve_description(cve_desc)
#             for item in related_cwes:
#                 cwe_id = item.get("cwe_id", "")
#                 desc = item.get("description", "")
#                 if cwe_id:
#                     cwe_from_cve_ids.append(cwe_id)
#                 if desc:
#                             cwe_from_cve_descs.append(desc)


#         plugin_output = str(row.get("pluginoutput", "") or "")
#         combined_parts = [title, description, solution, plugin_output]


#         # combined_parts = [title, description, solution]
#         for cve in matched_cve:
#             desc = fetch_description(cve)
#             if desc:
#                 combined_parts.append(desc)
#         for cwe in matched_cwe:
#             desc = fetch_description(cwe)
#             if desc:
#                 combined_parts.append(desc)
#         for desc in cwe_from_cve_descs:
#             combined_parts.append(desc)
#         for item in related_cwes_from_text:
#             if item.get("description", ""):
#                 combined_parts.append(item["description"])

#         combined_text = " ".join(filter(None, combined_parts)).strip()
#         cleaned_text = preprocess_text(combined_text)
#         embedding = model.encode(cleaned_text).tolist()

#         final_resp = index.query(namespace=FINAL_NAMESPACE, top_k=top_k * 2, include_metadata=True, vector=embedding)
#         matches = final_resp.get("matches", [])

#         serialized_matches = []
#         for m in matches:
#             #  Only include results with score >= 0.60
#             if m.get("score", 0) >= 0.60:
#                 try:
#                     serialized_matches.append({
#                         "id": m.get("id", ""),
#                         "score": float(m.get("score", 0)),
#                         "metadata": dict(m.get("metadata", {}))
#                     })
#                 except Exception:
#                     serialized_matches.append(str(m))

#         all_logged_results = json.dumps(serialized_matches, indent=2, ensure_ascii=False)


#         all_above_threshold = [
#             {
#                 "id": m.get("id", ""),
#                 "score": round(m.get("score", 0), 4),
#                 "title": m["metadata"].get("title", ""),
#                 "description": m["metadata"].get("description", ""),
#                 "solution": m["metadata"].get("solution", ""),
#                 "devseccomments": m["metadata"].get("devseccomments", "")
#             }
#             for m in matches if m.get("score", 0) >= threshold
#         ]

#         top_display = all_above_threshold[:top_k]
#         devsec_summary = "\n".join([
#             f"{i+1}. ID: {m['id']} | Score: {m['score']} | Comment: {m.get('devseccomments', '(no comment)')}"
#             for i, m in enumerate(top_display)
#         ])

#         # Combine CWE descriptions from matched CWEs, text CWEs, and CWEs from CVEs
#         all_cwe_descs = []
#         for cwe in (matched_cwe + cwe_from_text + cwe_from_cve_ids):
#             desc = fetch_description(cwe)
#             if desc:
#                 all_cwe_descs.append(desc)

#         general_remediation = generate_remediation_summary(all_cwe_descs)

#         processed_rows.append({
#             "title": title,
#             "description": description,
#             "solution": solution,
#             "cve_cwe": cve_cwe_raw,
#             "plugin_output": plugin_output,
#             "is_title_present": is_title_present,
#             "is_description_present": is_description_present,
#             "is_solution_present": is_solution_present,
#             "is_cve_present": is_cve_present,
#             "is_cwe_present": is_cwe_present,
#             "Cve": ", ".join(cve_list),
#             "Cwe": ", ".join(cwe_list),
#             "matched_cve": ", ".join(matched_cve),
#             "mismatched_cve": ", ".join(mismatched_cve),
#             "matched_cwe": ", ".join(matched_cwe),
#             "mismatched_cwe": ", ".join(mismatched_cwe),
#             "cwe_from_cve": ", ".join(sorted(set(cwe_from_cve_ids))),
#             "cwe_from_text": ", ".join(sorted(set(cwe_from_text))),
#             "top_devsec_summary": devsec_summary,
#             "general_remediation_advice": general_remediation,
#             "all_logged_results": all_logged_results
#         })

#     output_df = pd.DataFrame(processed_rows)
#     base_name = os.path.splitext(os.path.basename(input_path))[0]
#     dir_name = os.path.dirname(input_path)

#     # Save processed GPT results (full)
#     gpt_path = os.path.join(dir_name, f"{base_name}_processed_results_with_gpt.xlsx")
#     output_df.to_excel(gpt_path, index=False)

#     # Merge only 2 GPT columns into original
#     original_df = pd.read_excel(input_path)
#     merged = original_df.copy()
#     merged["top_devsec_summary"] = output_df["top_devsec_summary"]
#     merged["general_remediation_advice"] = output_df["general_remediation_advice"]

#     merged_path = os.path.join(dir_name, f"{base_name}_with_gpt.xlsx")
#     merged.to_excel(merged_path, index=False)

#     # Missing summary export
#     missing_summary_df = output_df[output_df['top_devsec_summary'].astype(str).str.strip() == ""]
#     missing_path = None
#     if not missing_summary_df.empty:
#         missing_path = os.path.join(dir_name, f"{base_name}_missing_devsec_summary.xlsx")
#         missing_summary_df.to_excel(missing_path, index=False)
#         print(f" Missing DevSec summaries exported to: {missing_path}")

#     print(f" Analysis completed for {input_path}\n Saved files:\n - {gpt_path}\n - {merged_path}")
#     if missing_path:
#         print(f" - {missing_path}")

#     return gpt_path, merged_path, missing_path

# # ============================================================
# # MAIN ENTRY POINT
# # ============================================================
# if __name__ == "__main__":
#     excel_path = input(" Enter full path to Excel file: ").strip()
#     if not excel_path or not os.path.exists(excel_path):
#         print(" Invalid path. Exiting.")
#         sys.exit(0)

#     process_excel_file(excel_path)






















# # vuln_analyzer.py
# import os
# import re
# import io
# import json
# import sys
# import nltk
# import spacy
# import unicodedata
# import numpy as np
# import pandas as pd
# from nltk.corpus import stopwords
# from sentence_transformers import SentenceTransformer
# from pinecone import Pinecone
# from dotenv import load_dotenv
# from openai import OpenAI
# from datetime import datetime

# # ============================================================
# # STEP 1: ENVIRONMENT SETUP
# # ============================================================
# load_dotenv()
# PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
# PINECONE_HOST = os.getenv("PINECONE_HOST")
# OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# CVE_NAMESPACE = "cve-description"
# CWE_NAMESPACE = "vuln-namespace"
# FINAL_NAMESPACE = "vuln-base-namespace"
# UPLOAD_NAMESPACE = "vuln-base-namespace"

# # ============================================================
# # STEP 2: NLP SETUP
# # ============================================================
# nltk.download("stopwords", quiet=True)
# nltk.download("punkt", quiet=True)
# nltk.download("wordnet", quiet=True)
# nltk.download("omw-1.4", quiet=True)

# def load_spacy_model():
#     if getattr(sys, "frozen", False):
#         base_path = sys._MEIPASS  # type: ignore[attr-defined]
#         model_path = os.path.join(base_path, "en_core_web_sm")
#         return spacy.load(model_path)
#     else:
#         try:
#             import en_core_web_sm  # type: ignore
#             return en_core_web_sm.load()
#         except Exception:
#             return spacy.load("en_core_web_sm")

# spacy_nlp = load_spacy_model()
# stop_words = set(stopwords.words("english"))

# def preprocess_text(text: str) -> str:
#     if not isinstance(text, str):
#         return ""
#     text = text.lower()
#     text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
#     doc = spacy_nlp(text)
#     tokens = [t.lemma_ for t in doc if t.text not in stop_words and not t.is_punct and not t.is_space]
#     return " ".join(tokens)

# # ============================================================
# # STEP 3: INITIALIZE MODEL & PINECONE
# # ============================================================
# print(" Initializing model & Pinecone client...")
# model = SentenceTransformer("all-MiniLM-L6-v2")
# pc = Pinecone(api_key=PINECONE_API_KEY)
# index = pc.Index(host=PINECONE_HOST)
# print(" Connected to Pinecone")

# # ============================================================
# # STEP 4: OPENAI CLIENT
# # ============================================================
# client = OpenAI(api_key=OPENAI_API_KEY)

# def ask_gpt_yes_no(desc_a: str, desc_b: str) -> str:
#     if not desc_a.strip() or not desc_b.strip():
#         return "No"
#     prompt = (
#         "You are a cybersecurity analyst. Determine if the following two descriptions refer to the same "
#         "or overlapping vulnerability. Respond only 'Yes' or 'No'.\n\n"
#         f"Description A:\n{desc_a}\n\nDescription B:\n{desc_b}"
#     )
#     try:
#         resp = client.chat.completions.create(
#             model="gpt-4o-mini",
#             messages=[{"role": "user", "content": prompt}],
#             temperature=0.2,
#         )
#         answer = resp.choices[0].message.content.strip().lower()
#         return "Yes" if "yes" in answer else "No"
#     except Exception as e:
#         print(f" GPT validation failed: {e}")
#         return "No"

# def generate_remediation_summary(cwe_descriptions):
#     text = " ".join([d for d in cwe_descriptions if isinstance(d, str) and d.strip()])
#     if not text.strip():
#         return ""
#     prompt = (
#         "You are a cybersecurity expert. Based on the following CWE vulnerability descriptions, "
#         "suggest concise, actionable remediation steps.\n\n"
#         f"{text}"
#     )
#     try:
#         resp = client.chat.completions.create(
#             model="gpt-4o-mini",
#             messages=[{"role": "user", "content": prompt}],
#             temperature=0.3,
#         )
#         return resp.choices[0].message.content.strip()
#     except Exception as e:
#         print(f" GPT generation failed: {e}")
#         return ""

# # ============================================================
# # STEP 4.5: MANUAL-UPLOAD SPLIT (per-sheet right/ wrong) + CLEANER
# # ============================================================
# def _safe_name(s: str, fallback: str = "sheet") -> str:
#     if not s:
#         s = fallback
#     s = unicodedata.normalize("NFKD", s)
#     s = re.sub(r'[\\/:*?"<>|]', "_", s)
#     s = re.sub(r"\s+", " ", s).strip()
#     return s or fallback

# def _detect_header_and_data(df_no_header: pd.DataFrame):
#     """
#     Header row = first row with ≥ 2 non-empty cells.
#     Must have at least one non-empty row below header.
#     """
#     header_row_idx = None
#     for i, row in df_no_header.iterrows():
#         if row.count() >= 2:
#             header_row_idx = i
#             break
#     if header_row_idx is None:
#         return None, False
#     below = df_no_header.loc[header_row_idx + 1 :]
#     has_data = below.notna().any(axis=1).any()
#     return header_row_idx, has_data

# def _export_df_to_single_sheet_xlsx(out_xlsx_path: str, df_no_header: pd.DataFrame):
#     os.makedirs(os.path.dirname(out_xlsx_path), exist_ok=True)
#     with pd.ExcelWriter(out_xlsx_path, engine="openpyxl") as writer:
#         df_no_header.to_excel(writer, index=False, header=False, sheet_name="Sheet1")

# def split_to_right_wrong_under_manual_upload(input_path: str) -> list:
#     """
#     For a manually provided Excel/CSV, create:
#       uploads/manual_upload/<FileBase>/
#         <FileBase>__right_sheetK__<Sheet>.xlsx
#         <FileBase>__wrong_sheetM__<Sheet>.xlsx
#         _intake_manifest.json
#     Only return paths of RIGHT files.
#     """
#     base = os.path.splitext(os.path.basename(input_path))[0]
#     parent = os.path.join("uploads", "manual_upload", _safe_name(base))
#     os.makedirs(parent, exist_ok=True)

#     manifest = {"file": os.path.basename(input_path), "sheets": []}
#     right_paths: list[str] = []

#     ext = os.path.splitext(input_path)[1].lower()

#     # CSV -> single "sheet"
#     if ext == ".csv":
#         try:
#             try:
#                 df = pd.read_csv(input_path, header=None, encoding="utf-8")
#             except UnicodeDecodeError:
#                 df = pd.read_csv(input_path, header=None, encoding="latin-1")

#             header_row_idx, has_data = _detect_header_and_data(df)
#             if header_row_idx is not None and has_data:
#                 decision = "right"
#                 reason = "header_found"
#             else:
#                 decision = "wrong"
#                 reason = "no_header_or_data"

#             out_path = os.path.join(
#                 parent, f"{base}__{decision}_sheet1__CSV.xlsx"
#             )
#             _export_df_to_single_sheet_xlsx(out_path, df)
#             if decision == "right":
#                 right_paths.append(out_path)

#             manifest["sheets"].append({
#                 "sheet_index": 1,
#                 "sheet_name": "CSV",
#                 "decision": decision.upper(),
#                 "reason": reason,
#                 "export_path": out_path
#             })

#         except Exception as e:
#             manifest["sheets"].append({
#                 "sheet_index": 1,
#                 "sheet_name": "CSV",
#                 "decision": "SKIP",
#                 "reason": f"csv_load_error: {e}",
#                 "export_path": None
#             })

#         with open(os.path.join(parent, "_intake_manifest.json"), "w", encoding="utf-8") as mf:
#             json.dump(manifest, mf, indent=2, ensure_ascii=False)
#         return right_paths

#     # Excel (xls, xlsx, xlsm)
#     try:
#         xls = pd.ExcelFile(input_path)
#         sheet_names = xls.sheet_names
#     except Exception as e:
#         with open(os.path.join(parent, "_intake_manifest.json"), "w", encoding="utf-8") as mf:
#             json.dump({"error": f"workbook_open_error: {e}"}, mf, indent=2, ensure_ascii=False)
#         return right_paths

#     for idx, sheet in enumerate(sheet_names, start=1):
#         try:
#             df_raw = pd.read_excel(xls, sheet_name=sheet, header=None)
#             header_row_idx, has_data = _detect_header_and_data(df_raw)

#             if header_row_idx is not None and has_data:
#                 decision = "right"
#                 reason = "header_found"
#             else:
#                 decision = "wrong"
#                 reason = "no_header_or_data"

#             out_path = os.path.join(
#                 parent, f"{base}__{decision}_sheet{idx}__{_safe_name(str(sheet))}.xlsx"
#             )
#             _export_df_to_single_sheet_xlsx(out_path, df_raw)
#             if decision == "right":
#                 right_paths.append(out_path)

#             manifest["sheets"].append({
#                 "sheet_index": idx,
#                 "sheet_name": str(sheet),
#                 "decision": decision.upper(),
#                 "reason": reason,
#                 "export_path": out_path
#             })

#         except Exception as e:
#             manifest["sheets"].append({
#                 "sheet_index": idx,
#                 "sheet_name": str(sheet),
#                 "decision": "SKIP",
#                 "reason": f"sheet_load_error: {e}",
#                 "export_path": None
#             })

#     with open(os.path.join(parent, "_intake_manifest.json"), "w", encoding="utf-8") as mf:
#         json.dump(manifest, mf, indent=2, ensure_ascii=False)

#     return right_paths

# def create_clean_copy(original_path: str) -> str:
#     """
#     Make a cleaned Excel (same folder, suffix '_clean.xlsx'):
#       - Trim leading empty rows/cols
#       - Use first non-empty row within trimmed block as header
#     If cleaning fails, returns original_path.
#     """
#     try:
#         df_raw = pd.read_excel(original_path, header=None)

#         non_empty_rows = df_raw.index[df_raw.notna().any(axis=1)]
#         non_empty_cols = df_raw.columns[df_raw.notna().any(axis=0)]
#         if len(non_empty_rows) == 0 or len(non_empty_cols) == 0:
#             print(f"⚠️ File appears empty: {original_path}")
#             return original_path

#         r0, r1 = non_empty_rows.min(), non_empty_rows.max()
#         c0, c1 = non_empty_cols.min(), non_empty_cols.max()
#         block = df_raw.loc[r0:r1, c0:c1].copy()

#         header_idx = None
#         for i in block.index:
#             if block.loc[i].count() >= 2:
#                 header_idx = i
#                 break
#         if header_idx is None:
#             print(f"⚠️ No obvious header row found in: {original_path}")
#             return original_path

#         header_values = block.loc[header_idx].astype(str).tolist()
#         data = block.loc[header_idx + 1 :].reset_index(drop=True)
#         data.columns = [str(h).strip() if str(h).strip() != "" else f"col_{j}" for j, h in enumerate(header_values)]
#         data = data.dropna(axis=1, how="all")

#         base_dir = os.path.dirname(original_path)
#         base_name = os.path.splitext(os.path.basename(original_path))[0]
#         cleaned_path = os.path.join(base_dir, f"{base_name}_clean.xlsx")
#         data.to_excel(cleaned_path, index=False)

#         print(f"🧹 Cleaned copy created → {cleaned_path}")
#         return cleaned_path
#     except Exception as e:
#         print(f"⚠️ Cleaning failed for {original_path}: {e}")
#         return original_path

# # ============================================================
# # STEP 5: COLUMN MAPPINGS
# # ============================================================
# COLUMN_MAPPINGS = {
#     "title": [
#         "title", "vulnerability name", "vulnerability", "vulnerability title",
#         "plugin name", "name", "name of vulnerability", "vulnerability_name",
#         "observation", "title / vulnerability", "issue", "vulnerability name (plugin name)"
#     ],
#     "description": [
#         "impact", "vulnerability description in detail", "likely impact",
#         "description", "description and impact", "threat",
#         "description/impact", "observation", "vulnerability description",
#         "finding description"
#     ],
#     "solution": [
#         "recommendation", "prevention", "remediation", "solution",
#         "steps to remediate", "recommendation/countermeasure",
#         "vulnerability solution"
#     ],
#     "devseccomments": [
#         "devsec comments", "dev comment", "devsec suggestions", "devsec response",
#         "arcon remarks", "developer comments", "arcon response", "dev sec comments"
#     ],
#     "cvecwe": ["cve/cwe", "cve", "cwe", "cwe id", "cvss3.1", "cve id", "cve_cwe"],
#     "pluginoutput": ["plugin_output", "plugin output", "plugin text"]
# }

# def standardize_vulnerability_sheet(input_path, drop_empty=True) -> pd.DataFrame:
#     df = pd.read_excel(input_path)
#     df.columns = [c.strip().lower() for c in df.columns]
#     standardized_df = pd.DataFrame()

#     for target_col, synonyms in COLUMN_MAPPINGS.items():
#         matched_cols = []
#         for synonym in synonyms:
#             s = synonym.strip().lower()
#             for col in df.columns:
#                 if s == col and col not in matched_cols:
#                     matched_cols.append(col)
#         if matched_cols:
#             combined_series = df[matched_cols].apply(
#                 lambda row: " | ".join(
#                     [str(x).strip() for x in row
#                      if pd.notna(x) and str(x).strip() != "" and str(x).lower() != "nan"]
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
# # STEP 6: FETCH DESCRIPTIONS & ANALYSIS HELPERS
# # ============================================================
# def fetch_description(entry: str) -> str:
#     if not entry:
#         return ""
#     try:
#         if entry.upper().startswith("CVE-"):
#             resp = index.query(namespace=CVE_NAMESPACE, top_k=1, include_metadata=True, id=entry.upper())
#         else:
#             resp = index.query(namespace=CWE_NAMESPACE, top_k=1, include_metadata=True, id=entry.lower())
#         matches = resp.get("matches", [])
#         if matches:
#             return matches[0]["metadata"].get("description", "")
#     except Exception as e:
#         print(f" Fetch failed for {entry}: {e}")
#     return ""

# def fetch_top_cwes_for_text(text: str, top_k=3):
#     if not text.strip():
#         return []
#     try:
#         emb = model.encode(preprocess_text(text)).tolist()
#         resp = index.query(namespace=CWE_NAMESPACE, top_k=top_k, include_metadata=True, vector=emb)
#         return [
#             {"cwe_id": m["metadata"].get("cwe_id", ""), "description": m["metadata"].get("description", "")}
#             for m in resp.get("matches", []) if m.get("score", 0) > 0
#         ]
#     except Exception as e:
#         print(f" Error fetching CWEs for text: {e}")
#         return []

# def fetch_top_cwes_for_cve_description(cve_description: str, top_k=3):
#     if not cve_description.strip():
#         return []
#     try:
#         emb = model.encode(preprocess_text(cve_description)).tolist()
#         resp = index.query(namespace=CWE_NAMESPACE, top_k=top_k, include_metadata=True, vector=emb)
#         return [
#             {"cwe_id": m["metadata"].get("cwe_id", ""), "description": m["metadata"].get("description", "")}
#             for m in resp.get("matches", []) if m.get("score", 0) > 0
#         ]
#     except Exception as e:
#         print(f" Error fetching CWEs for CVE: {e}")
#         return []

# # ============================================================
# # STEP 7: ANALYZER CORE (Single Cleaned Sheet File)
# # ============================================================
# def analyze_clean_sheet_file(working_path, top_k=5, threshold=0.60):
#     df = standardize_vulnerability_sheet(working_path, drop_empty=True)
#     df = df.replace([np.nan, np.inf, -np.inf], None)
#     processed_rows = []

#     for _, row in df.iterrows():
#         title = str(row.get("title", "") or "")
#         description = str(row.get("description", "") or "")
#         solution = str(row.get("solution", "") or "")
#         cve_cwe_raw = str(row.get("cvecwe", "") or "")

#         is_title_present = "Yes" if title.strip() else "No"
#         is_description_present = "Yes" if description.strip() else "No"
#         is_solution_present = "Yes" if solution.strip() else "No"

#         cves = re.findall(r"CVE-\d{4}-\d+", cve_cwe_raw, flags=re.IGNORECASE)
#         cwes = re.findall(r"CWE-\d+", cve_cwe_raw, flags=re.IGNORECASE)
#         is_cve_present = "Yes" if cves else "No"
#         is_cwe_present = "Yes" if cwes else "No"
#         cve_list = sorted(set([c.upper() for c in cves]))
#         cwe_list = sorted(set([c.upper() for c in cwes]))

#         matched_cve, mismatched_cve, matched_cwe, mismatched_cwe = [], [], [], []
#         for cve in cve_list:
#             desc = fetch_description(cve)
#             if not (title.strip() or description.strip() or solution.strip()):
#                 matched_cve.append(cve); continue
#             if ask_gpt_yes_no(desc, description or (title + " " + solution)) == "Yes":
#                 matched_cve.append(cve)
#             else:
#                 mismatched_cve.append(cve)

#         for cwe in cwe_list:
#             desc = fetch_description(cwe)
#             if not (title.strip() or description.strip() or solution.strip()):
#                 matched_cwe.append(cwe); continue
#             if ask_gpt_yes_no(desc, description or (title + " " + solution)) == "Yes":
#                 matched_cwe.append(cwe)
#             else:
#                 mismatched_cwe.append(cwe)

#         related_cwes_from_text = fetch_top_cwes_for_text(description or (title + " " + solution), top_k=3)
#         cwe_from_text = [i.get("cwe_id", "") for i in related_cwes_from_text if i.get("cwe_id")]

#         cwe_from_cve_ids, cwe_from_cve_descs = [], []
#         for cve in matched_cve:
#             cve_desc = fetch_description(cve)
#             related_cwes = fetch_top_cwes_for_cve_description(cve_desc)
#             for item in related_cwes:
#                 cwe_id = item.get("cwe_id", ""); desc = item.get("description", "")
#                 if cwe_id: cwe_from_cve_ids.append(cwe_id)
#                 if desc:   cwe_from_cve_descs.append(desc)

#         plugin_output = str(row.get("pluginoutput", "") or "")
#         combined_parts = [title, description, solution, plugin_output]

#         for cve in matched_cve:
#             d = fetch_description(cve)
#             if d: combined_parts.append(d)
#         for cwe in matched_cwe:
#             d = fetch_description(cwe)
#             if d: combined_parts.append(d)
#         for d in cwe_from_cve_descs:
#             combined_parts.append(d)
#         for item in related_cwes_from_text:
#             if item.get("description", ""):
#                 combined_parts.append(item["description"])

#         combined_text = " ".join(filter(None, combined_parts)).strip()
#         cleaned_text = preprocess_text(combined_text)
#         embedding = model.encode(cleaned_text).tolist()

#         final_resp = index.query(namespace=FINAL_NAMESPACE, top_k=top_k * 2, include_metadata=True, vector=embedding)
#         matches = final_resp.get("matches", [])

#         serialized_matches = []
#         for m in matches:
#             if m.get("score", 0) >= 0.60:
#                 try:
#                     serialized_matches.append({
#                         "id": m.get("id", ""),
#                         "score": float(m.get("score", 0)),
#                         "metadata": dict(m.get("metadata", {}))
#                     })
#                 except Exception:
#                     serialized_matches.append(str(m))
#         all_logged_results = json.dumps(serialized_matches, indent=2, ensure_ascii=False)

#         all_above_threshold = [
#             {
#                 "id": m.get("id", ""),
#                 "score": round(m.get("score", 0), 4),
#                 "title": m["metadata"].get("title", ""),
#                 "description": m["metadata"].get("description", ""),
#                 "solution": m["metadata"].get("solution", ""),
#                 "devseccomments": m["metadata"].get("devseccomments", "")
#             }
#             for m in matches if m.get("score", 0) >= threshold
#         ]

#         top_display = all_above_threshold[:top_k]
#         devsec_summary = "\n".join([
#             f"{i+1}. ID: {m['id']} | Score: {m['score']} | Comment: {m.get('devseccomments', '(no comment)')}"
#             for i, m in enumerate(top_display)
#         ])

#         all_cwe_descs = []
#         for cwe in (matched_cwe + cwe_from_text + cwe_from_cve_ids):
#             d = fetch_description(cwe)
#             if d: all_cwe_descs.append(d)

#         general_remediation = generate_remediation_summary(all_cwe_descs)

#         processed_rows.append({
#             "title": title,
#             "description": description,
#             "solution": solution,
#             "cve_cwe": cve_cwe_raw,
#             "plugin_output": plugin_output,
#             "is_title_present": is_title_present,
#             "is_description_present": is_description_present,
#             "is_solution_present": is_solution_present,
#             "is_cve_present": is_cve_present,
#             "is_cwe_present": is_cwe_present,
#             "Cve": ", ".join(cve_list),
#             "Cwe": ", ".join(cwe_list),
#             "matched_cve": ", ".join(matched_cve),
#             "mismatched_cve": ", ".join(mismatched_cve),
#             "matched_cwe": ", ".join(matched_cwe),
#             "mismatched_cwe": ", ".join(mismatched_cwe),
#             "cwe_from_cve": ", ".join(sorted(set(cwe_from_cve_ids))),
#             "cwe_from_text": ", ".join(sorted(set(cwe_from_text))),
#             "top_devsec_summary": devsec_summary,
#             "general_remediation_advice": general_remediation,
#             "all_logged_results": all_logged_results
#         })

#     output_df = pd.DataFrame(processed_rows)

#     # Output names next to the CLEANED sheet file
#     base_name = os.path.splitext(os.path.basename(working_path))[0]
#     dir_name = os.path.dirname(working_path)

#     gpt_path = os.path.join(dir_name, f"{base_name}_processed_results_with_gpt.xlsx")
#     output_df.to_excel(gpt_path, index=False)

#     cleaned_original_df = pd.read_excel(working_path)
#     merged = cleaned_original_df.copy()
#     for col in ["top_devsec_summary", "general_remediation_advice"]:
#         merged[col] = ""
#         if col in output_df.columns:
#             n = min(len(merged), len(output_df[col]))
#             merged.loc[: n - 1, col] = output_df[col].iloc[:n].values

#     merged_path = os.path.join(dir_name, f"{base_name}_with_gpt.xlsx")
#     merged.to_excel(merged_path, index=False)

#     missing_summary_df = output_df[output_df["top_devsec_summary"].astype(str).str.strip() == ""]
#     missing_path = None
#     if not missing_summary_df.empty:
#         missing_path = os.path.join(dir_name, f"{base_name}_missing_devsec_summary.xlsx")
#         missing_summary_df.to_excel(missing_path, index=False)
#         print(f" Missing DevSec summaries exported to: {missing_path}")

#     print(f" Saved files:\n - {gpt_path}\n - {merged_path}")
#     if missing_path:
#         print(f" - {missing_path}")

#     return gpt_path, merged_path, missing_path

# # ============================================================
# # STEP 8: PIPELINE FOR MANUAL INPUT (split → clean → analyze)
# # ============================================================
# def process_manual_file(input_path: str, top_k=5, threshold=0.60):
#     """
#     For a manually provided Excel/CSV:
#       1) Split into RIGHT/WRONG per sheet under uploads/manual_upload/<FileBase>/
#       2) For each RIGHT sheet file:
#            - create a cleaned copy (…_clean.xlsx)
#            - analyze the cleaned copy and write outputs next to it
#     """
#     print(f"\n📂 Manual input: {input_path}")
#     right_sheet_paths = split_to_right_wrong_under_manual_upload(input_path)

#     if not right_sheet_paths:
#         print("⚠️ No RIGHT sheets detected. Nothing to analyze.")
#         return []

#     print(f"✅ RIGHT sheets found: {len(right_sheet_paths)}")
#     results = []
#     for sheet_file in right_sheet_paths:
#         print(f"\n🔧 Preparing sheet: {sheet_file}")
#         cleaned = create_clean_copy(sheet_file)
#         working = cleaned if os.path.exists(cleaned) else sheet_file
#         print(f"🚀 Analyzing: {working}")
#         results.append(analyze_clean_sheet_file(working, top_k=top_k, threshold=threshold))
#     return results

# # ============================================================
# # MAIN ENTRY POINT
# # ============================================================
# # if __name__ == "__main__":
# #     excel_path = input(" Enter full path to Excel/CSV file: ").strip()
# #     if not excel_path or not os.path.exists(excel_path):
# #         print(" Invalid path. Exiting.")
# #         sys.exit(0)

# #     # Full manual pipeline (split per sheet under uploads/manual_upload/)
# #     process_manual_file(excel_path)














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
from nltk.corpus import stopwords
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone
from dotenv import load_dotenv
from openai import OpenAI
from datetime import datetime

# ============================================================
# STEP 0: LIGHTWEIGHT LOGGER
# ============================================================
def _info(msg: str): print(f"ℹ️ {msg}")
def _ok(msg: str): print(f"✅ {msg}")
def _warn(msg: str): print(f"⚠️ {msg}")
def _err(msg: str): print(f"❌ {msg}")

# ============================================================
# STEP 1: ENVIRONMENT SETUP
# ============================================================
load_dotenv()
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_HOST = os.getenv("PINECONE_HOST")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

CVE_NAMESPACE = "cve-description"
CWE_NAMESPACE = "vuln-namespace"
FINAL_NAMESPACE = "vuln-base-namespace"
UPLOAD_NAMESPACE = "vuln-base-namespace"

_missing_env = []
if not PINECONE_API_KEY: _missing_env.append("PINECONE_API_KEY")
if not PINECONE_HOST: _missing_env.append("PINECONE_HOST")
if not OPENAI_API_KEY: _missing_env.append("OPENAI_API_KEY")
if _missing_env:
    _err(f"Required configuration missing: {', '.join(_missing_env)}")
    _warn("Some features may not work (vector search / GPT). Continue at your own risk.")

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
        _warn("Pinecone not configured; vector queries will be skipped.")
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
    Header row = first row with ≥ 2 non-empty cells.
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
    os.makedirs(os.path.dirname(out_xlsx_path), exist_ok=True
               )
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

def create_clean_copy(original_path: str) -> str:
    """
    Make a cleaned Excel (same folder, suffix '_clean.xlsx'):
      - Trim leading empty rows/cols
      - Use first non-empty row within trimmed block as header
    If cleaning fails, returns original_path.
    """
    try:
        df_raw = pd.read_excel(original_path, header=None)

        # all-empty?
        if df_raw.isna().all(axis=None):
            _warn(f"Nothing to process: the sheet is empty after reading → {original_path}")
            return original_path

        non_empty_rows = df_raw.index[df_raw.notna().any(axis=1)]
        non_empty_cols = df_raw.columns[df_raw.notna().any(axis=0)]
        if len(non_empty_rows) == 0 or len(non_empty_cols) == 0:
            _warn(f"Nothing to process: the sheet is empty after trimming → {original_path}")
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
            _warn(f"Couldn’t find a header row (first non-empty row should contain column names) → {original_path}")
            return original_path

        # must have rows below header
        if header_idx == block.index.max():
            _warn(f"Found headers but no data rows below → {original_path}")
            return original_path

        header_values = [str(x).strip() for x in block.loc[header_idx].tolist()]
        if all((not h or h.lower().startswith("unnamed")) for h in header_values):
            _warn(f"Invalid headers: all empty/'Unnamed' → {original_path}")
            return original_path

        data = block.loc[header_idx + 1 :].reset_index(drop=True)
        # fill headers; create placeholders for blanks
        data.columns = [h if h else f"col_{j}" for j, h in enumerate(header_values)]
        data = data.dropna(axis=1, how="all")

        base_dir = os.path.dirname(original_path)
        base_name = os.path.splitext(os.path.basename(original_path))[0]
        cleaned_path = os.path.join(base_dir, f"{base_name}_clean.xlsx")
        data.to_excel(cleaned_path, index=False)

        _ok(f"Cleaned copy created → {cleaned_path}")
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

def _standardize_and_validate(input_path, drop_empty=True):
    """
    Wraps standardize_vulnerability_sheet with descriptive checks.
    Returns (standardized_df, warnings_list)
    """
    warnings = []
    try:
        df = pd.read_excel(input_path)
    except Exception as e:
        _err(f"File isn’t a valid Excel sheet or is corrupted: {e}")
        return pd.DataFrame(), ["workbook_open_error"]

    if df.empty or df.isna().all(axis=None):
        warnings.append("sheet_empty")
        _warn("The cleaned sheet is empty. Nothing to process.")
        return pd.DataFrame(), warnings

    # detect if all headers unnamed/blank
    raw_headers = [str(h).strip().lower() for h in df.columns]
    if all((not h or h.startswith("unnamed")) for h in raw_headers):
        warnings.append("invalid_headers")
        _warn("Invalid headers: column names are empty/'Unnamed'.")

    # normal standardization
    df.columns = [c.strip().lower() for c in df.columns]
    standardized_df = pd.DataFrame()

    for target_col, synonyms in COLUMN_MAPPINGS.items():
        matched_cols = []
        for synonym in synonyms:
            s = synonym.strip().lower()
            for col in df.columns:
                if s == col and col not in matched_cols:
                    matched_cols.append(col)
        if matched_cols:
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

    if drop_empty and not standardized_df.empty:
        standardized_df = standardized_df.loc[:, (standardized_df != "").any(axis=0)]

    # If nothing mapped at all:
    if standardized_df.empty:
        warnings.append("no_recognizable_columns")
        _warn("No recognizable columns found. Expected any of: Title, Description, Solution, CVE/CWE.")

    # If mapped but all mapped are entirely empty:
    if not standardized_df.empty and (standardized_df.replace("", np.nan).isna().all(axis=None)):
        warnings.append("mapped_columns_all_empty")
        _warn("Recognizable headers found, but their columns are empty.")

    return standardized_df, warnings

def standardize_vulnerability_sheet(input_path, drop_empty=True) -> pd.DataFrame:
    # Kept for backward compatibility; used by analyzer.
    df, _ = _standardize_and_validate(input_path, drop_empty=drop_empty)
    return df

# ============================================================
# STEP 6: FETCH DESCRIPTIONS & ANALYSIS HELPERS
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
# STEP 7: ANALYZER CORE (Single Cleaned Sheet File)
# ============================================================
def analyze_clean_sheet_file(working_path, top_k=5, threshold=0.60):
    _info(f"Analyzing cleaned sheet → {working_path}")

    # Standardize with validation
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
        cve_cwe_raw = str(row.get("cvecwe", "") or "")

        # if nothing at all, skip
        if not any([title.strip(), description.strip(), solution.strip(), cve_cwe_raw.strip()]):
            _warn(f"Row {idx+1} skipped: no Title/Description/Solution and no CVE/CWE to analyze.")
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
            if not (title.strip() or description.strip() or solution.strip()):
                # No context to compare, accept CVE as-is but mark info
                matched_cve.append(cve)
                continue
            if ask_gpt_yes_no(desc, description or (title + " " + solution)) == "Yes":
                matched_cve.append(cve)
            else:
                mismatched_cve.append(cve)

        for cwe in cwe_list:
            desc = fetch_description(cwe)
            if not (title.strip() or description.strip() or solution.strip()):
                matched_cwe.append(cwe)
                continue
            if ask_gpt_yes_no(desc, description or (title + " " + solution)) == "Yes":
                matched_cwe.append(cwe)
            else:
                mismatched_cwe.append(cwe)

        related_cwes_from_text = fetch_top_cwes_for_text(description or (title + " " + solution), top_k=3)
        cwe_from_text = [i.get("cwe_id", "") for i in related_cwes_from_text if i.get("cwe_id")]

        cwe_from_cve_ids, cwe_from_cve_descs = [], []
        for cve in matched_cve:
            cve_desc = fetch_description(cve)
            related_cwes = fetch_top_cwes_for_cve_description(cve_desc)
            for item in related_cwes:
                cwe_id = item.get("cwe_id", ""); desc = item.get("description", "")
                if cwe_id: cwe_from_cve_ids.append(cwe_id)
                if desc:   cwe_from_cve_descs.append(desc)

        plugin_output = str(row.get("pluginoutput", "") or "")
        combined_parts = [title, description, solution, plugin_output]

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

        combined_text = " ".join(filter(None, combined_parts)).strip()

        # Embedding safety
        if not _model_ok or not _index_ok:
            _warn("Vector search disabled (model/index unavailable). This row will not include KB matches.")
            matches = []
        else:
            try:
                cleaned_text = preprocess_text(combined_text)
                embedding = model.encode(cleaned_text).tolist()
                final_resp = index.query(namespace=FINAL_NAMESPACE, top_k=top_k * 2, include_metadata=True, vector=embedding)
                matches = final_resp.get("matches", [])
            except Exception as e:
                _warn(f"Couldn’t compute embeddings/query index for row {idx+1}: {e}")
                matches = []

        serialized_matches = []
        for m in matches:
            if m.get("score", 0) >= 0.60:
                try:
                    serialized_matches.append({
                        "id": m.get("id", ""),
                        "score": float(m.get("score", 0)),
                        "metadata": dict(m.get("metadata", {}))
                    })
                except Exception:
                    serialized_matches.append(str(m))
        all_logged_results = json.dumps(serialized_matches, indent=2, ensure_ascii=False)

        all_above_threshold = [
            {
                "id": m.get("id", ""),
                "score": round(m.get("score", 0), 4),
                "title": m["metadata"].get("title", ""),
                "description": m["metadata"].get("description", ""),
                "solution": m["metadata"].get("solution", ""),
                "devseccomments": m["metadata"].get("devseccomments", "")
            }
            for m in matches if m.get("score", 0) >= threshold
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
            "cve_cwe": cve_cwe_raw,
            "plugin_output": plugin_output,
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

    # Output names next to the CLEANED sheet file
    base_name = os.path.splitext(os.path.basename(working_path))[0]
    dir_name = os.path.dirname(working_path)

    # Try writing processed results
    gpt_path = os.path.join(dir_name, f"{base_name}_processed_results_with_gpt.xlsx")
    try:
        output_df.to_excel(gpt_path, index=False)
        _ok(f"Wrote detailed results → {gpt_path}")
    except Exception as e:
        _err(f"Couldn’t save processed results (path/permission issue): {e}")
        gpt_path = None

    # Merge only 2 GPT columns into the CLEANED file (not the raw original)
    merged_path = None
    try:
        cleaned_original_df = pd.read_excel(working_path)
        merged = cleaned_original_df.copy()
        # Always create columns, even if output_df lacks them
        for col in ["top_devsec_summary", "general_remediation_advice"]:
            merged[col] = ""
            if col in output_df.columns and not output_df.empty:
                n = min(len(merged), len(output_df[col]))
                if n > 0:
                    merged.loc[: n - 1, col] = output_df[col].iloc[:n].values

        merged_path = os.path.join(dir_name, f"{base_name}_with_gpt.xlsx")
        merged.to_excel(merged_path, index=False)
        _ok(f"Wrote merged file → {merged_path}")
    except Exception as e:
        _err(f"Couldn’t merge into cleaned sheet (row-count/permission issue): {e}")
        merged_path = None

    # Missing summary export (from processed rows)
    missing_path = None
    try:
        if "top_devsec_summary" in output_df.columns:
            missing_summary_df = output_df[output_df["top_devsec_summary"].astype(str).str.strip() == ""]
            if not missing_summary_df.empty:
                missing_path = os.path.join(dir_name, f"{base_name}_missing_devsec_summary.xlsx")
                missing_summary_df.to_excel(missing_path, index=False)
                _warn(f"Missing DevSec summaries exported → {missing_path}")
        else:
            _warn("‘top_devsec_summary’ column absent in results; nothing to export as missing summaries.")
    except Exception as e:
        _warn(f"Failed to export missing-summary file: {e}")
        missing_path = None

    return gpt_path, merged_path, missing_path

# ============================================================
# STEP 8: PIPELINE FOR MANUAL INPUT (split → clean → analyze)
# ============================================================
def process_manual_file(input_path: str, top_k=5, threshold=0.60):
    """
    For a manually provided Excel/CSV:
      1) Split into RIGHT/WRONG per sheet under uploads/manual_upload/<FileBase>/
      2) For each RIGHT sheet file:
           - create a cleaned copy (…_clean.xlsx)
           - analyze the cleaned copy and write outputs next to it
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
# if __name__ == "__main__":
#     excel_path = input(" Enter full path to Excel/CSV file: ").strip()
#     if not excel_path or not os.path.exists(excel_path):
#         print(" Invalid path. Exiting.")
#         sys.exit(0)
#     process_manual_file(excel_path)
