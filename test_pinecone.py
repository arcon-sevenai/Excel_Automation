# query_pinecone.py
import os
import sys
import json
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone

# -----------------------------
# 1) Setup
# -----------------------------
load_dotenv()

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_HOST = os.getenv("PINECONE_HOST")  # e.g. "https://your-index-yourproj.svc.aped-xyz.pinecone.io"
PINECONE_NAMESPACE = os.getenv("PINECONE_NAMESPACE", "")  # optional

if not PINECONE_API_KEY or not PINECONE_HOST:
    print("❌ Missing env vars. Please set PINECONE_API_KEY and PINECONE_HOST (and optionally PINECONE_NAMESPACE).")
    sys.exit(1)

print("ℹ️ Loading 384-dim embedding model (all-MiniLM-L6-v2)...")
model = SentenceTransformer("all-MiniLM-L6-v2")  # output dim = 384

print("ℹ️ Connecting to Pinecone index...")
pc = Pinecone(api_key=PINECONE_API_KEY)
index = pc.Index(host=PINECONE_HOST)

# -----------------------------
# 2) Read input text
# -----------------------------
if len(sys.argv) > 1:
    query_text = " ".join(sys.argv[1:]).strip()
else:
    query_text = input("Enter your search text: ").strip()

if not query_text:
    print("⚠️ Empty input. Exiting.")
    sys.exit(0)

# -----------------------------
# 3) Embed & Query
# -----------------------------
print("ℹ️ Computing embedding...")
embedding = model.encode(query_text).tolist()  # 384-dim

print("ℹ️ Querying Pinecone (top_k=5)...")
resp = index.query(
    vector=embedding,
    top_k=5,
    include_metadata=True,
    namespace=PINECONE_NAMESPACE if PINECONE_NAMESPACE else None
)

matches = resp.get("matches", []) or []
if not matches:
    print("⚠️ No results.")
    sys.exit(0)

# -----------------------------
# 4) Pretty print results
# -----------------------------
def safe(md, key, default=""):
    try:
        return md.get(key, default)
    except Exception:
        return default

print("\n✅ Top 5 results:")
for i, m in enumerate(matches, start=1):
    mid = m.get("id", "")
    score = m.get("score", 0)
    md = m.get("metadata", {}) or {}
    title = safe(md, "title")
    description = safe(md, "description")
    print("-" * 80)
    print(f"{i}. ID: {mid}")
    print(f"   Score: {score:.4f}")
    if title:
        print(f"   Title: {title}")
    if description:
        # keep the print tidy
        short_desc = (description[:240] + "…") if len(description) > 240 else description
        print(f"   Description: {short_desc}")

# If you want raw JSON, uncomment:
# print(json.dumps(resp, indent=2, ensure_ascii=False))