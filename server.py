

# # ============================================================
# # server.py — Vulnerability Analyzer & Uploader API
# # ============================================================
# from fastapi import FastAPI, File, UploadFile, Form
# from fastapi.responses import FileResponse, JSONResponse
# from datetime import datetime
# import os
# import shutil
# from uploader import push_to_pinecone
# from vuln_analyzer import process_excel_file
# from jira_excel_fetcher import fetch_excel_from_jira   # ← added

# # ============================================================
# # FASTAPI SETUP
# # ============================================================
# app = FastAPI(title="Vulnerability Uploader & Analyzer API")
# UPLOAD_DIR = "uploads"
# os.makedirs(UPLOAD_DIR, exist_ok=True)


# # ============================================================
# # ROUTE 1: UPLOAD TO PINECONE
# # ============================================================
# @app.post("/upload")
# async def upload_to_pinecone_api(file: UploadFile = File(...)):
#     try:
#         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         filename = f"{timestamp}_{file.filename}"
#         file_path = os.path.join(UPLOAD_DIR, filename)

#         with open(file_path, "wb") as buffer:
#             shutil.copyfileobj(file.file, buffer)

#         push_to_pinecone(file_path)

#         return {
#             "status": "success",
#             "message": f" {file.filename} uploaded to Pinecone successfully.",
#             "saved_as": filename
#         }
#     except Exception as e:
#         return {"status": "error", "message": str(e)}


# # ============================================================
# # ROUTE 2: ANALYZE FILE
# # ============================================================
# @app.post("/analyze")
# async def analyze_file(file: UploadFile = File(...)):
#     try:
#         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         filename = f"{timestamp}_{file.filename}"
#         upload_path = os.path.join(UPLOAD_DIR, filename)

#         with open(upload_path, "wb") as buffer:
#             shutil.copyfileobj(file.file, buffer)

#         gpt_path, merged_path, missing_path = process_excel_file(upload_path)

#         base_url = "http://localhost:8000"
#         files_info = {
#             "processed_results": f"{base_url}/download/{os.path.basename(gpt_path)}",
#             "merged_results": f"{base_url}/download/{os.path.basename(merged_path)}",
#             "missing_summary": (
#                 f"{base_url}/download/{os.path.basename(missing_path)}" if missing_path else None
#             )
#         }

#         return JSONResponse({
#             "status": "success",
#             "message": f" Analysis complete for {file.filename}.",
#             "files": files_info
#         })
#     except Exception as e:
#         return JSONResponse({"status": "error", "message": str(e)})


# # ============================================================
# # ROUTE 3: FETCH FROM JIRA + ANALYZE (Step 1 + 2)
# # ============================================================
# @app.post("/fetch-and-analyze")
# async def fetch_and_analyze(ticket_id: str = Form(...)):
#     try:
#         # Step 1: Fetch Excel files from JIRA
#         excel_files = fetch_excel_from_jira(ticket_id)
#         if not excel_files:
#             return JSONResponse({
#                 "status": "error",
#                 "message": f" No valid Excel files found for ticket {ticket_id}."
#             })

#         analyzed_files = []
#         for excel_path in excel_files:
#             gpt_path, merged_path, missing_path = process_excel_file(excel_path)
#             base_url = "http://localhost:8000"
#             analyzed_files.append({
#                 "input_file": os.path.basename(excel_path),
#                 "processed_results": f"{base_url}/download/{os.path.basename(gpt_path)}",
#                 "merged_results": f"{base_url}/download/{os.path.basename(merged_path)}",
#                 "missing_summary": (
#                     f"{base_url}/download/{os.path.basename(missing_path)}" if missing_path else None
#                 )
#             })

#         return JSONResponse({
#             "status": "success",
#             "message": f" Completed fetch + analysis for ticket {ticket_id}.",
#             "files": analyzed_files
#         })
#     except Exception as e:
#         return JSONResponse({"status": "error", "message": str(e)})


# # ============================================================
# # ROUTE 4: DOWNLOAD FILES
# # ============================================================
# @app.get("/download/{filename}")
# async def download_file(filename: str):
#     file_path = os.path.join(UPLOAD_DIR, filename)
#     if os.path.exists(file_path):
#         return FileResponse(file_path, filename=filename)
#     return JSONResponse({"status": "error", "message": "File not found."})


# # ============================================================
# # ROOT ENDPOINT
# # ============================================================
# @app.get("/")
# async def root():
#     return {"message": "Welcome to Vulnerability Uploader & Analyzer API"}











# # ============================================================
# # server.py — Vulnerability Analyzer & Uploader API (recursive download)
# # ============================================================
# from fastapi import FastAPI, File, UploadFile, Form
# from fastapi.responses import FileResponse, JSONResponse
# from datetime import datetime
# import os
# import shutil
# from uploader import push_to_pinecone
# from vuln_analyzer import process_excel_file
# from jira_excel_fetcher import fetch_excel_from_jira

# # ============================================================
# # FASTAPI SETUP
# # ============================================================
# app = FastAPI(title="Vulnerability Uploader & Analyzer API")

# UPLOAD_DIR = "uploads"
# os.makedirs(UPLOAD_DIR, exist_ok=True)


# # ============================================================
# # ROUTE 1: UPLOAD TO PINECONE
# # ============================================================
# @app.post("/upload")
# async def upload_to_pinecone_api(file: UploadFile = File(...)):
#     try:
#         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         filename = f"{timestamp}_{file.filename}"
#         file_path = os.path.join(UPLOAD_DIR, filename)

#         with open(file_path, "wb") as buffer:
#             shutil.copyfileobj(file.file, buffer)

#         push_to_pinecone(file_path)

#         return {
#             "status": "success",
#             "message": f"{file.filename} uploaded to Pinecone successfully.",
#             "saved_as": filename
#         }

#     except Exception as e:
#         return {"status": "error", "message": str(e)}


# # ============================================================
# # ROUTE 2: ANALYZE FILE (Manual Upload)
# # ============================================================
# @app.post("/analyze")
# async def analyze_file(file: UploadFile = File(...)):
#     try:
#         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         filename = f"{timestamp}_{file.filename}"
#         upload_path = os.path.join(UPLOAD_DIR, filename)

#         with open(upload_path, "wb") as buffer:
#             shutil.copyfileobj(file.file, buffer)

#         gpt_path, merged_path, missing_path = process_excel_file(upload_path)

#         base_url = "http://localhost:8000"
#         files_info = {
#             "processed_results": f"{base_url}/download/{os.path.basename(gpt_path)}",
#             "merged_results": f"{base_url}/download/{os.path.basename(merged_path)}",
#             "missing_summary": (
#                 f"{base_url}/download/{os.path.basename(missing_path)}" if missing_path else None
#             )
#         }

#         return JSONResponse({
#             "status": "success",
#             "message": f"Analysis complete for {file.filename}.",
#             "files": files_info
#         })

#     except Exception as e:
#         return JSONResponse({"status": "error", "message": str(e)})


# # ============================================================
# # ROUTE 3: FETCH FROM JIRA + ANALYZE (Step 1 + Step 2)
# # ============================================================
# @app.post("/fetch-and-analyze")
# async def fetch_and_analyze(ticket_id: str = Form(...)):
#     try:
#         excel_files = fetch_excel_from_jira(ticket_id)
#         if not excel_files:
#             return JSONResponse({
#                 "status": "error",
#                 "message": f"No valid Excel files found for ticket {ticket_id}."
#             })

#         analyzed_files = []
#         for excel_path in excel_files:
#             gpt_path, merged_path, missing_path = process_excel_file(excel_path)
#             base_url = "http://localhost:8000"

#             analyzed_files.append({
#                 "input_file": os.path.basename(excel_path),
#                 "processed_results": f"{base_url}/download/{os.path.basename(gpt_path)}",
#                 "merged_results": f"{base_url}/download/{os.path.basename(merged_path)}",
#                 "missing_summary": (
#                     f"{base_url}/download/{os.path.basename(missing_path)}" if missing_path else None
#                 )
#             })

#         return JSONResponse({
#             "status": "success",
#             "message": f"Completed fetch + analysis for ticket {ticket_id}.",
#             "files": analyzed_files
#         })

#     except Exception as e:
#         return JSONResponse({"status": "error", "message": str(e)})


# # ============================================================
# # ROUTE 4: DOWNLOAD FILES (Recursive Search)
# # ============================================================
# @app.get("/download/{filename}")
# async def download_file(filename: str):
#     for root, _, files in os.walk(UPLOAD_DIR):
#         if filename in files:
#             file_path = os.path.join(root, filename)
#             return FileResponse(file_path, filename=filename)

#     return JSONResponse({"status": "error", "message": "File not found."})


# # ============================================================
# # ROOT ENDPOINT
# # ============================================================
# @app.get("/")
# async def root():
#     return {"message": "Welcome to Vulnerability Uploader & Analyzer API"}










# ============================================================
# server.py — Vulnerability Analyzer & Uploader API (with proper status codes)
# ============================================================
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import FileResponse, JSONResponse
from datetime import datetime
import os
import shutil
from uploader import push_to_pinecone
from vuln_analyzer import process_excel_file
from jira_excel_fetcher import fetch_excel_from_jira

# ============================================================
# FASTAPI SETUP
# ============================================================
app = FastAPI(title="Vulnerability Uploader & Analyzer API")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============================================================
# ROUTE 1: UPLOAD TO PINECONE
# ============================================================
@app.post("/upload")
async def upload_to_pinecone_api(file: UploadFile = File(...)):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}_{file.filename}"
        file_path = os.path.join(UPLOAD_DIR, filename)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        push_to_pinecone(file_path)

        return JSONResponse(
            {
                "status": "success",
                "message": f"{file.filename} uploaded to Pinecone successfully.",
                "saved_as": filename,
            },
            status_code=200,
        )

    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


# ============================================================
# ROUTE 2: ANALYZE FILE (Manual Upload)
# ============================================================
@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}_{file.filename}"
        upload_path = os.path.join(UPLOAD_DIR, filename)

        with open(upload_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        gpt_path, merged_path, missing_path = process_excel_file(upload_path)

        base_url = "10.10.1.172:8000"
        files_info = {
            "processed_results": f"{base_url}/download/{os.path.basename(gpt_path)}",
            "merged_results": f"{base_url}/download/{os.path.basename(merged_path)}",
            "missing_summary": (
                f"{base_url}/download/{os.path.basename(missing_path)}"
                if missing_path
                else None
            ),
        }

        return JSONResponse(
            {
                "status": "success",
                "message": f"Analysis complete for {file.filename}.",
                "files": files_info,
            },
            status_code=200,
        )

    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


# ============================================================
# ROUTE 3: FETCH FROM JIRA + ANALYZE (Step 1 + Step 2)
# ============================================================
@app.post("/fetch-and-analyze")
async def fetch_and_analyze(ticket_id: str = Form(...)):
    try:
        excel_files = fetch_excel_from_jira(ticket_id)
        if not excel_files:
            return JSONResponse(
                {
                    "status": "error",
                    "message": f"No valid Excel files found for ticket {ticket_id}.",
                },
                status_code=400,
            )

        analyzed_files = []
        for excel_path in excel_files:
            gpt_path, merged_path, missing_path = process_excel_file(excel_path)
            base_url = "http://localhost:8000"

            analyzed_files.append(
                {
                    "input_file": os.path.basename(excel_path),
                    "processed_results": f"{base_url}/download/{os.path.basename(gpt_path)}",
                    "merged_results": f"{base_url}/download/{os.path.basename(merged_path)}",
                    "missing_summary": (
                        f"{base_url}/download/{os.path.basename(missing_path)}"
                        if missing_path
                        else None
                    ),
                }
            )

        return JSONResponse(
            {
                "status": "success",
                "message": f"Completed fetch + analysis for ticket {ticket_id}.",
                "files": analyzed_files,
            },
            status_code=200,
        )

    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


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
        {"message": "Welcome to Vulnerability Uploader & Analyzer API"}, status_code=200
    )
