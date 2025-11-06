# # ============================================================
# # main.py — Unified Vulnerability Automation Controller
# # ============================================================
# import os
# import sys
# from pathlib import Path
# from pprint import pprint

# # Import your existing modules
# from jira_excel_fetcher import fetch_excel_from_jira       # Module 1
# from vuln_analyzer import process_excel_file             # Module 2
# from uploader import push_to_pinecone               # Module 3

# # ============================================================
# # MAIN MENU
# # =========================================================
# def main():
#     while True:
#         print("""
#         ===============================================
#         🔧 Vulnerability Automation Menu
#         ===============================================
#         1️⃣  Fetch Excel sheets from JIRA and process automatically
#         2️⃣  Analyze Excel sheets manually (local files)
#         3️⃣  Upload analyzed Excel data to Pinecone
#         0️⃣  Exit
#         ===============================================
#         """)

#         choice = input("👉 Enter your choice (1/2/3/0): ").strip()

#         # ------------------------------------------------------------
#         # OPTION 1: Fetch from JIRA and run analyzer automatically
#         # ------------------------------------------------------------
#         if choice == "1":
#             ticket_id = input("\n🎫 Enter JIRA Ticket ID (e.g., PAM-1234): ").strip()
#             if not ticket_id:
#                 print("❌ No ticket ID provided. Returning to main menu.")
#                 continue

#             print(f"\n🚀 Fetching Excel attachments for {ticket_id} ...")
#             excel_files = fetch_excel_from_jira(ticket_id)

#             if not excel_files:
#                 print("⚠️ No valid Excel files found for this ticket.")
#                 continue

#             # Capture only original files before analysis (to avoid new ones later)
#             original_excel_paths = list(excel_files)
#             print(f"📂 Found {len(original_excel_paths)} original Excel file(s):")
#             pprint(original_excel_paths)

#             # Process each original file sequentially
#             for excel_path in original_excel_paths:
#                 try:
#                     print(f"\n🔍 Starting analysis for: {excel_path}")
#                     process_excel_file(excel_path)
#                     print(f"✅ Completed analysis for: {excel_path}")
#                 except Exception as e:
#                     print(f"❌ Error analyzing {excel_path}: {e}")

#             print(f"\n🎉 All fetched Excel files for {ticket_id} have been processed successfully!")

#         # ------------------------------------------------------------
#         # OPTION 2: Analyze Excel manually (provide local paths)
#         # ------------------------------------------------------------
#         elif choice == "2":
#             print("\n📄 Provide one or more Excel file paths (comma separated):")
#             paths = input("👉 Paths: ").strip()

#             if not paths:
#                 print("❌ No paths provided. Returning to menu.")
#                 continue

#             excel_paths = [p.strip('" ').replace("\\", "/") for p in paths.split(",") if p.strip()]
#             for excel_path in excel_paths:
#                 if not os.path.exists(excel_path):
#                     print(f"❌ File not found: {excel_path}")
#                     continue
#                 try:
#                     print(f"\n⚙️ Running analyzer for: {excel_path}")
#                     process_excel_file(excel_path)
#                     print(f"✅ Finished processing {excel_path}")
#                 except Exception as e:
#                     print(f"❌ Error analyzing {excel_path}: {e}")

#         # ------------------------------------------------------------
#         # OPTION 3: Upload analyzed Excel data to Pinecone
#         # ------------------------------------------------------------
#         elif choice == "3":
#             print("\n📂 Provide the path to the completed Excel (e.g., missing_devsec_summary.xlsx):")
#             excel_path = input("👉 Path: ").strip()

#             if not excel_path or not os.path.exists(excel_path):
#                 print("❌ Invalid file path. Returning to menu.")
#                 continue

#             try:
#                 print(f"\n🚀 Uploading {excel_path} to Pinecone ...")
#                 push_to_pinecone(excel_path)
#                 print(f"✅ Upload completed successfully for {excel_path}")
#             except Exception as e:
#                 print(f"❌ Upload failed for {excel_path}: {e}")

#         # ------------------------------------------------------------
#         # OPTION 0: Exit
#         # ------------------------------------------------------------
#         elif choice == "0":
#             print("\n👋 Exiting Vulnerability Automation. Goodbye!")
#             sys.exit(0)

#         else:
#             print("❌ Invalid choice. Please select 1, 2, 3, or 0.")

# # ============================================================
# # RUN
# # ============================================================
# if __name__ == "__main__":
#     main()







# ============================================================
# main.py — Unified Vulnerability Automation Controller
# ============================================================
import os
import sys
from pprint import pprint

# Module 1: JIRA fetcher (returns RIGHT-sheet file paths already saved under uploads/<ticket>/<attachment>/...)
from jira_excel_fetcher import fetch_excel_from_jira

# Module 2: Analyzer
# - process_manual_file(input_path): splits per-sheet under uploads/manual_upload/<FileBase>/, cleans, analyzes
# - create_clean_copy(path): trims leading blank rows/cols, sets header, writes <name>_clean.xlsx next to input
# - analyze_clean_sheet_file(path): runs the analyzer on a single cleaned sheet file and writes outputs next to it
from vuln_analyzer import process_manual_file, create_clean_copy, analyze_clean_sheet_file

# Module 3: Uploader (push finished *_with_gpt.xlsx into Pinecone)
from uploader import push_to_pinecone


# ============================================================
# MAIN MENU
# ============================================================
def main():
    while True:
        print("""
        ===============================================
        🔧 Vulnerability Automation Menu
        ===============================================
        1️⃣  Fetch Excel sheets from JIRA and process automatically
        2️⃣  Analyze Excel sheets manually (local files)
        3️⃣  Upload analyzed Excel data to Pinecone
        0️⃣  Exit
        ===============================================
        """)

        choice = input("👉 Enter your choice (1/2/3/0): ").strip()

        # ------------------------------------------------------------
        # OPTION 1: Fetch from JIRA → (no splitting here) clean+analyze each RIGHT-sheet file
        # ------------------------------------------------------------
        if choice == "1":
            ticket_id = input("\n🎫 Enter JIRA Ticket ID (e.g., PAM-1234): ").strip()
            if not ticket_id:
                print("❌ No ticket ID provided. Returning to main menu.")
                continue

            print(f"\n🚀 Fetching attachments and exporting per-sheet for {ticket_id} ...")
            right_sheet_paths = fetch_excel_from_jira(ticket_id)

            if not right_sheet_paths:
                print("⚠️ No valid RIGHT sheets found for this ticket.")
                continue

            print(f"📂 RIGHT sheets to analyze: {len(right_sheet_paths)}")
            pprint(right_sheet_paths)

            # For each RIGHT-sheet file, only clean + analyze (do NOT re-create subfolders or split again)
            for sheet_path in right_sheet_paths:
                try:
                    print(f"\n🔧 Cleaning sheet file: {sheet_path}")
                    cleaned_path = create_clean_copy(sheet_path)
                    working = cleaned_path if os.path.exists(cleaned_path) else sheet_path

                    print(f"🚀 Analyzing: {working}")
                    analyze_clean_sheet_file(working)
                    print(f"✅ Completed analysis for: {working}")
                except Exception as e:
                    print(f"❌ Error analyzing {sheet_path}: {e}")

            print(f"\n🎉 All RIGHT sheets for {ticket_id} have been processed successfully!")

        # ------------------------------------------------------------
        # OPTION 2: Manual analysis → split per sheet under uploads/manual_upload/, then clean+analyze
        # ------------------------------------------------------------
        elif choice == "2":
            print("\n📄 Provide one or more Excel/CSV file paths (comma separated):")
            paths = input("👉 Paths: ").strip()

            if not paths:
                print("❌ No paths provided. Returning to menu.")
                continue

            input_paths = [p.strip('" ').replace("\\", "/") for p in paths.split(",") if p.strip()]
            for input_path in input_paths:
                if not os.path.exists(input_path):
                    print(f"❌ File not found: {input_path}")
                    continue
                try:
                    print(f"\n⚙️ Running full manual pipeline (split → clean → analyze) for: {input_path}")
                    process_manual_file(input_path)
                    print(f"✅ Finished processing {input_path}")
                except Exception as e:
                    print(f"❌ Error processing {input_path}: {e}")

        # ------------------------------------------------------------
        # OPTION 3: Upload analyzed Excel data to Pinecone
        # ------------------------------------------------------------
        elif choice == "3":
            print("\n📂 Provide the path to the completed Excel (e.g., *_with_gpt.xlsx):")
            excel_path = input("👉 Path: ").strip()

            if not excel_path or not os.path.exists(excel_path):
                print("❌ Invalid file path. Returning to menu.")
                continue

            try:
                print(f"\n🚀 Uploading {excel_path} to Pinecone ...")
                push_to_pinecone(excel_path)
                print(f"✅ Upload completed successfully for {excel_path}")
            except Exception as e:
                print(f"❌ Upload failed for {excel_path}: {e}")

        # ------------------------------------------------------------
        # OPTION 0: Exit
        # ------------------------------------------------------------
        elif choice == "0":
            print("\n👋 Exiting Vulnerability Automation. Goodbye!")
            sys.exit(0)

        else:
            print("❌ Invalid choice. Please select 1, 2, 3, or 0.")


# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    main()
