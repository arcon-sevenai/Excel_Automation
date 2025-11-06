# # ============================================================
# # server.py — Vulnerability Analyzer & Uploader API (with timestamped uploads)
# # ============================================================
# from fastapi import FastAPI, File, UploadFile
# from fastapi.responses import FileResponse, JSONResponse
# from datetime import datetime
# import os
# import shutil
# from uploader import push_to_pinecone        # Module 3
# from vuln_analyzer import process_excel_file # Module 2

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
# async def upload_to_pinecone(file: UploadFile = File(...)):
#     try:
#         #  Generate timestamped filename
#         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         filename = f"{timestamp}_{file.filename}"
#         file_path = os.path.join(UPLOAD_DIR, filename)

#         # Save file locally
#         with open(file_path, "wb") as buffer:
#             shutil.copyfileobj(file.file, buffer)

#         # Run uploader
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
#         #  Generate timestamped filename
#         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         filename = f"{timestamp}_{file.filename}"
#         upload_path = os.path.join(UPLOAD_DIR, filename)

#         # Save uploaded Excel file
#         with open(upload_path, "wb") as buffer:
#             shutil.copyfileobj(file.file, buffer)

#         # Run analyzer
#         gpt_path, merged_path, missing_path = process_excel_file(upload_path)

#         #  Build public download URLs (Swagger friendly)
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
# # ROUTE 3: DOWNLOAD GENERATED FILES
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




