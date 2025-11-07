




# # ============================================================
# # server.py — Vulnerability Analyzer & Uploader API
# # (structured logging + exact terminal output in API responses)
# # ============================================================
# from fastapi import FastAPI, File, UploadFile, Form, Query, Request
# from fastapi.responses import FileResponse, JSONResponse
# from fastapi.middleware.cors import CORSMiddleware
# from datetime import datetime
# import os
# import shutil
# import json
# import logging
# import uuid
# import time
# import traceback
# import io
# from contextlib import redirect_stdout, redirect_stderr
# from logging.handlers import RotatingFileHandler
# from typing import List, Optional, Tuple, Callable, Any

# from uploader import push_to_pinecone
# from jira_excel_fetcher import fetch_excel_from_jira
# from vuln_analyzer import (
#     process_manual_file,        # full pipeline for manual uploads (split → clean → analyze)
#     create_clean_copy,          # (used in JIRA flow) clean a single per-sheet file
#     analyze_clean_sheet_file    # (used in JIRA flow) analyze a cleaned single-sheet file
# )

# # ============================================================
# # FASTAPI SETUP
# # ============================================================
# app = FastAPI(title="Vulnerability Uploader & Analyzer API")

# # CORS (adjust if needed)
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# UPLOAD_DIR = "uploads"
# os.makedirs(UPLOAD_DIR, exist_ok=True)

# # Base URL for link generation (defaults to localhost:8001 to match your run)
# BASE_URL = os.getenv("BASE_URL", "http://localhost:8001")

# # Logs dir
# LOGS_DIR = "logs"
# os.makedirs(LOGS_DIR, exist_ok=True)

# # ============================================================
# # LOGGING SETUP (app-level persistent)
# # ============================================================
# LOGGER_NAME = "va_api"
# logger = logging.getLogger(LOGGER_NAME)
# logger.setLevel(logging.INFO)
# logger.propagate = False  # avoid duplicate logs if root has handlers

# # Console handler
# _console = logging.StreamHandler()
# _console.setLevel(logging.INFO)
# _console.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
# logger.addHandler(_console)

# # Rotating file handler
# _file = RotatingFileHandler(
#     os.path.join(LOGS_DIR, "app.log"), maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
# )
# _file.setLevel(logging.INFO)
# _file.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
# logger.addHandler(_file)


# # ============================================================
# # PER-REQUEST LOG CAPTURE (logger + terminal prints)
# # ============================================================
# class ListHandler(logging.Handler):
#     """Collects formatted log messages into a list."""
#     def __init__(self, sink: List[str], request_id: str):
#         super().__init__()
#         self.sink = sink
#         self.request_id = request_id
#         self.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))

#     def emit(self, record: logging.LogRecord) -> None:
#         try:
#             line = self.format(record)
#             self.sink.append(f"{line} | req={self.request_id}")
#         except Exception:
#             pass


# def attach_request_logger(request_id: str) -> Tuple[List[str], ListHandler]:
#     buf: List[str] = []
#     h = ListHandler(buf, request_id=request_id)
#     h.setLevel(logging.INFO)
#     logger.addHandler(h)
#     return buf, h


# def detach_request_logger(h: ListHandler) -> None:
#     try:
#         logger.removeHandler(h)
#     except Exception:
#         pass


# def capture_terminal(func: Callable[..., Any], *args, **kwargs) -> Tuple[Any, str]:
#     """
#     Run a callable while capturing stdout/stderr (all `print()` from called code).
#     Returns (result, terminal_text).
#     """
#     buf = io.StringIO()
#     with redirect_stdout(buf), redirect_stderr(buf):
#         result = func(*args, **kwargs)
#     return result, buf.getvalue()


# def summarize_logs(lines: List[str]) -> dict:
#     """Return lightweight counts; not the lines themselves."""
#     levels = {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
#     for ln in lines:
#         if " | INFO | " in ln:
#             levels["INFO"] += 1
#         elif " | WARNING | " in ln:
#             levels["WARNING"] += 1
#         elif " | ERROR | " in ln:
#             levels["ERROR"] += 1
#         elif " | CRITICAL | " in ln:
#             levels["CRITICAL"] += 1
#     return levels


# def read_intake_diagnostics(ticket_folder: str) -> List[dict]:
#     """
#     Collect per-attachment intake info from _intake_manifest.json files under uploads/<ticket_id>/**/.
#     """
#     results = []
#     if not os.path.isdir(ticket_folder):
#         return results

#     for root, _, files in os.walk(ticket_folder):
#         if "_intake_manifest.json" in files:
#             try:
#                 manifest_path = os.path.join(root, "_intake_manifest.json")
#                 with open(manifest_path, "r", encoding="utf-8") as f:
#                     mf = json.load(f)
#                 attachment = mf.get("attachment")
#                 for s in mf.get("sheets", []):
#                     results.append({
#                         "attachment": attachment,
#                         "sheet_index": s.get("sheet_index"),
#                         "sheet_name": s.get("sheet_name"),
#                         "decision": s.get("decision"),
#                         "reason": s.get("reason"),
#                         "reason_detail": s.get("reason_detail"),
#                         "header_row_guess": s.get("header_row_guess"),
#                         "export_path": s.get("export_path"),
#                     })
#             except Exception:
#                 continue
#     return results


# def download_link(path: Optional[str]) -> Optional[str]:
#     """Returns a /download link only if a filename exists; otherwise None."""
#     if not path:
#         return None
#     return f"{BASE_URL}/download/{os.path.basename(path)}"


# def clip_lines(s: str, max_lines: int = 1000) -> List[str]:
#     """Clip multi-line terminal text to the last N lines."""
#     lines = s.splitlines()
#     if len(lines) > max_lines:
#         return lines[-max_lines:]
#     return lines


# # ============================================================
# # ROUTE 1: UPLOAD TO PINECONE
# # ============================================================
# @app.post("/upload")
# async def upload_to_pinecone_api(
#     request: Request,
#     file: UploadFile = File(...),
#     include_logs: bool = Query(False, description="Include per-request logs and terminal output in response"),
# ):
#     req_id = uuid.uuid4().hex
#     logs, lh = attach_request_logger(req_id)
#     t0 = time.perf_counter()
#     terminal_all: List[str] = []
#     try:
#         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         filename = f"{timestamp}_{file.filename}"
#         file_path = os.path.join(UPLOAD_DIR, filename)

#         # Save the uploaded file
#         with open(file_path, "wb") as buffer:
#             shutil.copyfileobj(file.file, buffer)

#         logger.info(f"Uploading to Pinecone: saved file as {file_path}")

#         # Capture terminal output from the uploader
#         _, term = capture_terminal(push_to_pinecone, file_path)
#         terminal_all.extend(clip_lines(term))

#         elapsed = round((time.perf_counter() - t0) * 1000)
#         body = {
#             "status": "success",
#             "message": f"{file.filename} uploaded to Pinecone successfully.",
#             "saved_as": filename,
#             "diagnostics": {
#                 "request_id": req_id,
#                 "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
#             },
#         }
#         if include_logs:
#             body["diagnostics"]["logs"] = logs[-1000:]
#             body["diagnostics"]["terminal"] = terminal_all
#         return JSONResponse(body, status_code=200)

#     except Exception as e:
#         logger.error(f"Upload failed: {e}\n{traceback.format_exc()}")
#         elapsed = round((time.perf_counter() - t0) * 1000)
#         body = {
#             "status": "error",
#             "message": f"Pinecone upload failed: {str(e)}",
#             "diagnostics": {
#                 "request_id": req_id,
#                 "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
#             },
#         }
#         if include_logs:
#             body["diagnostics"]["logs"] = logs[-1000:]
#             body["diagnostics"]["terminal"] = terminal_all
#         return JSONResponse(body, status_code=500)
#     finally:
#         detach_request_logger(lh)


# # ============================================================
# # ROUTE 2: ANALYZE FILE (Manual Upload — split → clean → analyze)
# # ============================================================
# @app.post("/analyze")
# async def analyze_file(
#     request: Request,
#     file: UploadFile = File(...),
#     include_logs: bool = Query(False, description="Include per-request logs and terminal output in response"),
# ):
#     """
#     Accepts a local file upload that may contain multiple sheets.
#     Runs process_manual_file() which:
#       - splits into RIGHT/WRONG per-sheet under uploads/manual_upload/<FileBase>/
#       - cleans each RIGHT sheet
#       - analyzes each cleaned RIGHT sheet
#     Returns ONLY the per-sheet analysis result links (processed & merged; missing if present).
#     """
#     req_id = uuid.uuid4().hex
#     logs, lh = attach_request_logger(req_id)
#     t0 = time.perf_counter()
#     terminal_all: List[str] = []
#     try:
#         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         filename = f"{timestamp}_{file.filename}"
#         upload_path = os.path.join(UPLOAD_DIR, filename)

#         with open(upload_path, "wb") as buffer:
#             shutil.copyfileobj(file.file, buffer)

#         logger.info(f"Saved uploaded file to {upload_path}. Starting manual pipeline...")

#         # Capture terminal from the full manual pipeline
#         results, term = capture_terminal(process_manual_file, upload_path)
#         terminal_all.extend(clip_lines(term))

#         if not results:
#             elapsed = round((time.perf_counter() - t0) * 1000)
#             body = {
#                 "status": "error",
#                 "message": "No RIGHT sheets detected after inspection. "
#                            "Check if the workbook has at least one sheet with header+data.",
#                 "diagnostics": {
#                     "request_id": req_id,
#                     "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
#                 },
#             }
#             if include_logs:
#                 body["diagnostics"]["logs"] = logs[-1000:]
#                 body["diagnostics"]["terminal"] = terminal_all
#             return JSONResponse(body, status_code=400)

#         # Build sheet info + determine status
#         sheets_info = []
#         successes = 0
#         failures = 0

#         for (gpt_path, merged_path, missing_path) in results:
#             ok = bool(gpt_path or merged_path)
#             if ok:
#                 successes += 1
#             else:
#                 failures += 1

#             sheets_info.append(
#                 {
#                     "processed_results": download_link(gpt_path),
#                     "merged_results": download_link(merged_path),
#                     "missing_summary": download_link(missing_path) if missing_path else None,
#                 }
#             )

#         # Decide status code
#         if successes == 0:
#             status_code = 400
#             status_txt = "error"
#             message = "Analysis produced no outputs for any sheet. See diagnostics/terminal logs."
#         elif failures > 0:
#             status_code = 207  # Multi-Status
#             status_txt = "partial_success"
#             message = f"Analysis completed with some errors. Successful sheets: {successes}; failed: {failures}."
#         else:
#             status_code = 200
#             status_txt = "success"
#             message = f"Analysis complete for {file.filename}."

#         elapsed = round((time.perf_counter() - t0) * 1000)
#         body = {
#             "status": status_txt,
#             "message": message,
#             "sheets": sheets_info,
#             "diagnostics": {
#                 "request_id": req_id,
#                 "summary": {
#                     "elapsed_ms": elapsed,
#                     "sheets_total": len(results),
#                     "right_sheets": len(results),   # results are RIGHT sheets
#                     "skipped_sheets": 0,
#                     **summarize_logs(logs),
#                 },
#             },
#         }
#         if include_logs:
#             body["diagnostics"]["logs"] = logs[-1000:]
#             body["diagnostics"]["terminal"] = terminal_all
#         return JSONResponse(body, status_code=status_code)

#     except Exception as e:
#         logger.error(f"Analysis failed: {e}\n{traceback.format_exc()}")
#         elapsed = round((time.perf_counter() - t0) * 1000)
#         body = {
#             "status": "error",
#             "message": f"Analysis failed: {str(e)}",
#             "diagnostics": {
#                 "request_id": req_id,
#                 "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
#             },
#         }
#         if include_logs:
#             body["diagnostics"]["logs"] = logs[-1000:]
#             body["diagnostics"]["terminal"] = terminal_all
#         return JSONResponse(body, status_code=500)
#     finally:
#         detach_request_logger(lh)


# # ============================================================
# # ROUTE 3: FETCH FROM JIRA + ANALYZE (Step 1 + Step 2)
# # ============================================================
# @app.post("/fetch-and-analyze")
# async def fetch_and_analyze(
#     request: Request,
#     ticket_id: str = Form(...),
#     include_logs: bool = Query(False, description="Include per-request logs and terminal output in response"),
# ):
#     """
#     Fetches attachments from JIRA, splits each workbook into per-sheet RIGHT/WRONG files,
#     then for each RIGHT file: clean → analyze. Returns per-sheet analysis links only.
#     """
#     req_id = uuid.uuid4().hex
#     logs, lh = attach_request_logger(req_id)
#     t0 = time.perf_counter()
#     terminal_all: List[str] = []
#     try:
#         logger.info(f"Fetching attachments for ticket {ticket_id} ...")

#         # Capture terminal from the fetch step
#         right_sheet_files, term_fetch = capture_terminal(fetch_excel_from_jira, ticket_id)
#         terminal_all.extend(clip_lines(term_fetch))

#         if not right_sheet_files:
#             elapsed = round((time.perf_counter() - t0) * 1000)
#             # Intake diagnostics (maybe only WRONG sheets)
#             intake = read_intake_diagnostics(os.path.join(UPLOAD_DIR, ticket_id))
#             body = {
#                 "status": "error",
#                 "message": f"No valid sheets found for ticket {ticket_id}. Either there were no Excel/CSV "
#                            f"attachments, or all sheets failed validation (images-only / no header+data / unreadable).",
#                 "diagnostics": {
#                     "request_id": req_id,
#                     "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
#                     "intake": intake,
#                 },
#             }
#             if include_logs:
#                 body["diagnostics"]["logs"] = logs[-1000:]
#                 body["diagnostics"]["terminal"] = terminal_all
#             return JSONResponse(body, status_code=400)

#         analyzed_files = []
#         errors = []
#         successes = 0
#         failures = 0

#         for sheet_path in right_sheet_files:
#             try:
#                 # Capture terminal from clean + analyze step for each sheet
#                 def _clean_and_analyze(p: str):
#                     cleaned = create_clean_copy(p)
#                     working = cleaned if os.path.exists(cleaned) else p
#                     return analyze_clean_sheet_file(working)

#                 (gpt_path, merged_path, missing_path), term_sheet = capture_terminal(_clean_and_analyze, sheet_path)
#                 terminal_all.extend(clip_lines(term_sheet))

#                 ok = bool(gpt_path or merged_path)
#                 if ok:
#                     successes += 1
#                 else:
#                     failures += 1

#                 analyzed_files.append(
#                     {
#                         "input_file": os.path.basename(sheet_path),
#                         "processed_results": download_link(gpt_path),
#                         "merged_results": download_link(merged_path),
#                         "missing_summary": download_link(missing_path) if missing_path else None,
#                     }
#                 )
#             except Exception as e:
#                 failures += 1
#                 err_msg = f"Sheet analysis failed: {e}"
#                 logger.error(err_msg)
#                 errors.append(
#                     {
#                         "input_file": os.path.basename(sheet_path),
#                         "error": err_msg,
#                     }
#                 )

#         # Intake diagnostics across attachments for this ticket
#         intake = read_intake_diagnostics(os.path.join(UPLOAD_DIR, ticket_id))

#         if successes > 0 and failures == 0:
#             status = "success"
#             status_code = 200
#             message = f"Completed fetch + analysis for ticket {ticket_id}."
#         elif successes > 0 and failures > 0:
#             status = "partial_success"
#             status_code = 207
#             message = f"Completed with some errors for ticket {ticket_id}. Successful sheets: {successes}; failed: {failures}."
#         else:
#             status = "error"
#             status_code = 500
#             message = f"All sheets failed to analyze for ticket {ticket_id}."

#         elapsed = round((time.perf_counter() - t0) * 1000)
#         body = {
#             "status": status,
#             "message": message,
#             "files": analyzed_files,
#             "errors": errors if errors else None,
#             "diagnostics": {
#                 "request_id": req_id,
#                 "summary": {
#                     "elapsed_ms": elapsed,
#                     "sheets_total": len(right_sheet_files),
#                     "right_sheets": len(right_sheet_files),
#                     "skipped_sheets": 0,
#                     **summarize_logs(logs),
#                 },
#                 "intake": intake,
#             },
#         }
#         if include_logs:
#             body["diagnostics"]["logs"] = logs[-1000:]
#             body["diagnostics"]["terminal"] = terminal_all
#         return JSONResponse(body, status_code=status_code)

#     except Exception as e:
#         logger.error(f"Fetch + analyze failed: {e}\n{traceback.format_exc()}")
#         elapsed = round((time.perf_counter() - t0) * 1000)
#         body = {
#             "status": "error",
#             "message": f"Fetch + analyze failed: {str(e)}",
#             "diagnostics": {
#                 "request_id": req_id,
#                 "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
#             },
#         }
#         if include_logs:
#             body["diagnostics"]["logs"] = logs[-1000:]
#             body["diagnostics"]["terminal"] = terminal_all
#         return JSONResponse(body, status_code=500)
#     finally:
#         detach_request_logger(lh)


# # ============================================================
# # ROUTE 4: DOWNLOAD FILES (Recursive Search)
# # ============================================================
# @app.get("/download/{filename}")
# async def download_file(filename: str):
#     for root, _, files in os.walk(UPLOAD_DIR):
#         if filename in files:
#             file_path = os.path.join(root, filename)
#             return FileResponse(file_path, filename=filename, status_code=200)

#     return JSONResponse(
#         {"status": "error", "message": "File not found."}, status_code=404
#     )


# # ============================================================
# # ROOT ENDPOINT
# # ============================================================
# @app.get("/")
# async def root():
#     return JSONResponse(
#         {"message": "Welcome to Vulnerability Uploader & Analyzer API"},
#         status_code=200,
#     )














# ============================================================
# server.py — Vulnerability Analyzer & Uploader API
# (structured logging + exact terminal output in API responses)
# ============================================================
from fastapi import FastAPI, File, UploadFile, Form, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import os
import shutil
import json
import logging
import uuid
import time
import traceback
import io
from contextlib import redirect_stdout, redirect_stderr
from logging.handlers import RotatingFileHandler
from typing import List, Optional, Tuple, Callable, Any

# CHANGED: use OpenSearch uploader
from opensearch_uploader import push_to_opensearch

from jira_excel_fetcher import fetch_excel_from_jira
from opensearch_vuln_analyzer import (
    process_manual_file,        # full pipeline for manual uploads (split → clean → analyze)
    create_clean_copy,          # (used in JIRA flow) clean a single per-sheet file
    analyze_clean_sheet_file    # (used in JIRA flow) analyze a cleaned single-sheet file
)

# ============================================================
# FASTAPI SETUP
# ============================================================
app = FastAPI(title="Vulnerability Uploader & Analyzer API")

# CORS (adjust if needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Base URL for link generation (defaults to localhost:8001 to match your run)
BASE_URL = os.getenv("BASE_URL", "http://localhost:8001")

# Logs dir
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# ============================================================
# LOGGING SETUP (app-level persistent)
# ============================================================
LOGGER_NAME = "va_api"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.INFO)
logger.propagate = False  # avoid duplicate logs if root has handlers

# Console handler
_console = logging.StreamHandler()
_console.setLevel(logging.INFO)
_console.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(_console)

# Rotating file handler
_file = RotatingFileHandler(
    os.path.join(LOGS_DIR, "app.log"), maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
_file.setLevel(logging.INFO)
_file.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(_file)


# ============================================================
# PER-REQUEST LOG CAPTURE (logger + terminal prints)
# ============================================================
class ListHandler(logging.Handler):
    """Collects formatted log messages into a list."""
    def __init__(self, sink: List[str], request_id: str):
        super().__init__()
        self.sink = sink
        self.request_id = request_id
        self.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record)
            self.sink.append(f"{line} | req={self.request_id}")
        except Exception:
            pass


def attach_request_logger(request_id: str) -> Tuple[List[str], ListHandler]:
    buf: List[str] = []
    h = ListHandler(buf, request_id=request_id)
    h.setLevel(logging.INFO)
    logger.addHandler(h)
    return buf, h


def detach_request_logger(h: ListHandler) -> None:
    try:
        logger.removeHandler(h)
    except Exception:
        pass


def capture_terminal(func: Callable[..., Any], *args, **kwargs) -> Tuple[Any, str]:
    """
    Run a callable while capturing stdout/stderr (all `print()` from called code).
    Returns (result, terminal_text).
    """
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        result = func(*args, **kwargs)
    return result, buf.getvalue()


def summarize_logs(lines: List[str]) -> dict:
    """Return lightweight counts; not the lines themselves."""
    levels = {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
    for ln in lines:
        if " | INFO | " in ln:
            levels["INFO"] += 1
        elif " | WARNING | " in ln:
            levels["WARNING"] += 1
        elif " | ERROR | " in ln:
            levels["ERROR"] += 1
        elif " | CRITICAL | " in ln:
            levels["CRITICAL"] += 1
    return levels


def read_intake_diagnostics(ticket_folder: str) -> List[dict]:
    """
    Collect per-attachment intake info from _intake_manifest.json files under uploads/<ticket_id>/**/.
    """
    results = []
    if not os.path.isdir(ticket_folder):
        return results

    for root, _, files in os.walk(ticket_folder):
        if "_intake_manifest.json" in files:
            try:
                manifest_path = os.path.join(root, "_intake_manifest.json")
                with open(manifest_path, "r", encoding="utf-8") as f:
                    mf = json.load(f)
                attachment = mf.get("attachment")
                for s in mf.get("sheets", []):
                    results.append({
                        "attachment": attachment,
                        "sheet_index": s.get("sheet_index"),
                        "sheet_name": s.get("sheet_name"),
                        "decision": s.get("decision"),
                        "reason": s.get("reason"),
                        "reason_detail": s.get("reason_detail"),
                        "header_row_guess": s.get("header_row_guess"),
                        "export_path": s.get("export_path"),
                    })
            except Exception:
                continue
    return results


def download_link(path: Optional[str]) -> Optional[str]:
    """Returns a /download link only if a filename exists; otherwise None."""
    if not path:
        return None
    return f"{BASE_URL}/download/{os.path.basename(path)}"


def clip_lines(s: str, max_lines: int = 1000) -> List[str]:
    """Clip multi-line terminal text to the last N lines."""
    lines = s.splitlines()
    if len(lines) > max_lines:
        return lines[-max_lines:]
    return lines


# ============================================================
# ROUTE 1: UPLOAD TO OPENSEARCH
# ============================================================
@app.post("/upload")
async def upload_to_opensearch_api(
    request: Request,
    file: UploadFile = File(...),
    include_logs: bool = Query(False, description="Include per-request logs and terminal output in response"),
):
    req_id = uuid.uuid4().hex
    logs, lh = attach_request_logger(req_id)
    t0 = time.perf_counter()
    terminal_all: List[str] = []
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}_{file.filename}"
        file_path = os.path.join(UPLOAD_DIR, filename)

        # Save the uploaded file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        logger.info(f"Uploading to OpenSearch: saved file as {file_path}")

        # Capture terminal output from the uploader
        _, term = capture_terminal(push_to_opensearch, file_path)
        terminal_all.extend(clip_lines(term))

        elapsed = round((time.perf_counter() - t0) * 1000)
        body = {
            "status": "success",
            "message": f"{file.filename} uploaded to OpenSearch successfully.",
            "saved_as": filename,
            "diagnostics": {
                "request_id": req_id,
                "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
            },
        }
        if include_logs:
            body["diagnostics"]["logs"] = logs[-1000:]
            body["diagnostics"]["terminal"] = terminal_all
        return JSONResponse(body, status_code=200)

    except Exception as e:
        logger.error(f"Upload failed: {e}\n{traceback.format_exc()}")
        elapsed = round((time.perf_counter() - t0) * 1000)
        body = {
            "status": "error",
            "message": f"OpenSearch upload failed: {str(e)}",
            "diagnostics": {
                "request_id": req_id,
                "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
            },
        }
        if include_logs:
            body["diagnostics"]["logs"] = logs[-1000:]
            body["diagnostics"]["terminal"] = terminal_all
        return JSONResponse(body, status_code=500)
    finally:
        detach_request_logger(lh)


# ============================================================
# ROUTE 2: ANALYZE FILE (Manual Upload — split → clean → analyze)
# ============================================================
@app.post("/analyze")
async def analyze_file(
    request: Request,
    file: UploadFile = File(...),
    include_logs: bool = Query(False, description="Include per-request logs and terminal output in response"),
):
    """
    Accepts a local file upload that may contain multiple sheets.
    Runs process_manual_file() which:
      - splits into RIGHT/WRONG per-sheet under uploads/manual_upload/<FileBase>/
      - cleans each RIGHT sheet
      - analyzes each cleaned RIGHT sheet
    Returns ONLY the per-sheet analysis result links (processed & merged; missing if present).
    """
    req_id = uuid.uuid4().hex
    logs, lh = attach_request_logger(req_id)
    t0 = time.perf_counter()
    terminal_all: List[str] = []
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}_{file.filename}"
        upload_path = os.path.join(UPLOAD_DIR, filename)

        with open(upload_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        logger.info(f"Saved uploaded file to {upload_path}. Starting manual pipeline...")

        # Capture terminal from the full manual pipeline
        results, term = capture_terminal(process_manual_file, upload_path)
        terminal_all.extend(clip_lines(term))

        if not results:
            elapsed = round((time.perf_counter() - t0) * 1000)
            body = {
                "status": "error",
                "message": "No RIGHT sheets detected after inspection. "
                           "Check if the workbook has at least one sheet with header+data.",
                "diagnostics": {
                    "request_id": req_id,
                    "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
                },
            }
            if include_logs:
                body["diagnostics"]["logs"] = logs[-1000:]
                body["diagnostics"]["terminal"] = terminal_all
            return JSONResponse(body, status_code=400)

        # Build sheet info + determine status
        sheets_info = []
        successes = 0
        failures = 0

        for (gpt_path, merged_path, missing_path) in results:
            ok = bool(gpt_path or merged_path)
            if ok:
                successes += 1
            else:
                failures += 1

            sheets_info.append(
                {
                    "processed_results": download_link(gpt_path),
                    "merged_results": download_link(merged_path),
                    "missing_summary": download_link(missing_path) if missing_path else None,
                }
            )

        # Decide status code
        if successes == 0:
            status_code = 400
            status_txt = "error"
            message = "Analysis produced no outputs for any sheet. See diagnostics/terminal logs."
        elif failures > 0:
            status_code = 207  # Multi-Status
            status_txt = "partial_success"
            message = f"Analysis completed with some errors. Successful sheets: {successes}; failed: {failures}."
        else:
            status_code = 200
            status_txt = "success"
            message = f"Analysis complete for {file.filename}."

        elapsed = round((time.perf_counter() - t0) * 1000)
        body = {
            "status": status_txt,
            "message": message,
            "sheets": sheets_info,
            "diagnostics": {
                "request_id": req_id,
                "summary": {
                    "elapsed_ms": elapsed,
                    "sheets_total": len(results),
                    "right_sheets": len(results),   # results are RIGHT sheets
                    "skipped_sheets": 0,
                    **summarize_logs(logs),
                },
            },
        }
        if include_logs:
            body["diagnostics"]["logs"] = logs[-1000:]
            body["diagnostics"]["terminal"] = terminal_all
        return JSONResponse(body, status_code=status_code)

    except Exception as e:
        logger.error(f"Analysis failed: {e}\n{traceback.format_exc()}")
        elapsed = round((time.perf_counter() - t0) * 1000)
        body = {
            "status": "error",
            "message": f"Analysis failed: {str(e)}",
            "diagnostics": {
                "request_id": req_id,
                "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
            },
        }
        if include_logs:
            body["diagnostics"]["logs"] = logs[-1000:]
            body["diagnostics"]["terminal"] = terminal_all
        return JSONResponse(body, status_code=500)
    finally:
        detach_request_logger(lh)


# ============================================================
# ROUTE 3: FETCH FROM JIRA + ANALYZE (Step 1 + Step 2)
# ============================================================
@app.post("/fetch-and-analyze")
async def fetch_and_analyze(
    request: Request,
    ticket_id: str = Form(...),
    include_logs: bool = Query(False, description="Include per-request logs and terminal output in response"),
):
    """
    Fetches attachments from JIRA, splits each workbook into per-sheet RIGHT/WRONG files,
    then for each RIGHT file: clean → analyze. Returns per-sheet analysis links only.
    """
    req_id = uuid.uuid4().hex
    logs, lh = attach_request_logger(req_id)
    t0 = time.perf_counter()
    terminal_all: List[str] = []
    try:
        logger.info(f"Fetching attachments for ticket {ticket_id} ...")

        # Capture terminal from the fetch step
        right_sheet_files, term_fetch = capture_terminal(fetch_excel_from_jira, ticket_id)
        terminal_all.extend(clip_lines(term_fetch))

        if not right_sheet_files:
            elapsed = round((time.perf_counter() - t0) * 1000)
            # Intake diagnostics (maybe only WRONG sheets)
            intake = read_intake_diagnostics(os.path.join(UPLOAD_DIR, ticket_id))
            body = {
                "status": "error",
                "message": f"No valid sheets found for ticket {ticket_id}. Either there were no Excel/CSV "
                           f"attachments, or all sheets failed validation (images-only / no header+data / unreadable).",
                "diagnostics": {
                    "request_id": req_id,
                    "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
                    "intake": intake,
                },
            }
            if include_logs:
                body["diagnostics"]["logs"] = logs[-1000:]
                body["diagnostics"]["terminal"] = terminal_all
            return JSONResponse(body, status_code=400)

        analyzed_files = []
        errors = []
        successes = 0
        failures = 0

        for sheet_path in right_sheet_files:
            try:
                # Capture terminal from clean + analyze step for each sheet
                def _clean_and_analyze(p: str):
                    cleaned = create_clean_copy(p)
                    working = cleaned if os.path.exists(cleaned) else p
                    return analyze_clean_sheet_file(working)

                (gpt_path, merged_path, missing_path), term_sheet = capture_terminal(_clean_and_analyze, sheet_path)
                terminal_all.extend(clip_lines(term_sheet))

                ok = bool(gpt_path or merged_path)
                if ok:
                    successes += 1
                else:
                    failures += 1

                analyzed_files.append(
                    {
                        "input_file": os.path.basename(sheet_path),
                        "processed_results": download_link(gpt_path),
                        "merged_results": download_link(merged_path),
                        "missing_summary": download_link(missing_path) if missing_path else None,
                    }
                )
            except Exception as e:
                failures += 1
                err_msg = f"Sheet analysis failed: {e}"
                logger.error(err_msg)
                errors.append(
                    {
                        "input_file": os.path.basename(sheet_path),
                        "error": err_msg,
                    }
                )

        # Intake diagnostics across attachments for this ticket
        intake = read_intake_diagnostics(os.path.join(UPLOAD_DIR, ticket_id))

        if successes > 0 and failures == 0:
            status = "success"
            status_code = 200
            message = f"Completed fetch + analysis for ticket {ticket_id}."
        elif successes > 0 and failures > 0:
            status = "partial_success"
            status_code = 207
            message = f"Completed with some errors for ticket {ticket_id}. Successful sheets: {successes}; failed: {failures}."
        else:
            status = "error"
            status_code = 500
            message = f"All sheets failed to analyze for ticket {ticket_id}."

        elapsed = round((time.perf_counter() - t0) * 1000)
        body = {
            "status": status,
            "message": message,
            "files": analyzed_files,
            "errors": errors if errors else None,
            "diagnostics": {
                "request_id": req_id,
                "summary": {
                    "elapsed_ms": elapsed,
                    "sheets_total": len(right_sheet_files),
                    "right_sheets": len(right_sheet_files),
                    "skipped_sheets": 0,
                    **summarize_logs(logs),
                },
                "intake": intake,
            },
        }
        if include_logs:
            body["diagnostics"]["logs"] = logs[-1000:]
            body["diagnostics"]["terminal"] = terminal_all
        return JSONResponse(body, status_code=status_code)

    except Exception as e:
        logger.error(f"Fetch + analyze failed: {e}\n{traceback.format_exc()}")
        elapsed = round((time.perf_counter() - t0) * 1000)
        body = {
            "status": "error",
            "message": f"Fetch + analyze failed: {str(e)}",
            "diagnostics": {
                "request_id": req_id,
                "summary": {"elapsed_ms": elapsed, **summarize_logs(logs)},
            },
        }
        if include_logs:
            body["diagnostics"]["logs"] = logs[-1000:]
            body["diagnostics"]["terminal"] = terminal_all
        return JSONResponse(body, status_code=500)
    finally:
        detach_request_logger(lh)


# ============================================================
# ROUTE 4: DOWNLOAD FILES (Recursive Search)
# ============================================================
@app.get("/download/{filename}")
async def download_file(filename: str):
    for root, _, files in os.walk(UPLOAD_DIR):
        if filename in files:
            file_path = os.path.join(root, filename)
            return FileResponse(file_path, filename=filename, status_code=200)

    return JSONResponse(
        {"status": "error", "message": "File not found."}, status_code=404
    )


# ============================================================
# ROOT ENDPOINT
# ============================================================
@app.get("/")
async def root():
    return JSONResponse(
        {"message": "Welcome to Vulnerability Uploader & Analyzer API"},
        status_code=200,
    )
