# os_recreate_index.py — Delete and recreate an OpenSearch index with kNN mapping
import os
import sys
import json
from dotenv import load_dotenv
from opensearchpy import OpenSearch, RequestsHttpConnection

load_dotenv()

OS_HOST   = os.getenv("OPENSEARCH_HOST", "https://10.10.3.25:9200")
OS_USER   = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS   = os.getenv("OPENSEARCH_PASS", "admin")
INDEX     = os.getenv("OPENSEARCH_INDEX", "final")
VERIFY    = os.getenv("VERIFY_CERTS", "false").lower() in ("1", "true", "yes")
TIMEOUT   = int(os.getenv("OS_REQUEST_TIMEOUT", "60"))

# ---- your desired index body (exactly as provided) ----
INDEX_BODY = {
    "settings": { "index": { "knn": True } },
    "mappings": {
        "properties": {
            "vec": {
                "type": "knn_vector",
                "dimension": 384,
                "method": {
                    "name": "hnsw",
                    "engine": "lucene",
                    "space_type": "cosinesimil",
                    "parameters": { "m": 24, "ef_construction": 128 }
                }
            },
            "title": { "type": "text" },
            "description": { "type": "text" },
            "solution": { "type": "text" },
            "devseccomments": { "type": "text" },
            "plugin_output": { "type": "text" },
            "cve_cwe": { "type": "keyword" },
            "cves": { "type": "keyword" },
            "cwes": { "type": "keyword" },
            "extra": { "type": "text" },
            "created_at": { "type": "date" },
            "source": { "type": "keyword" }
        }
    }
}

# optionally mute HTTPS warnings when VERIFY_CERTS=false
if not VERIFY:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def client() -> OpenSearch:
    c = OpenSearch(
        hosts=[OS_HOST],
        http_auth=(OS_USER, OS_PASS),
        verify_certs=VERIFY,
        timeout=TIMEOUT,
        connection_class=RequestsHttpConnection,
    )
    if not c.ping():
        print("❌ OpenSearch ping failed. Check host/credentials/SSL.")
        sys.exit(1)
    return c

def recreate_index():
    c = client()
    # delete if exists
    if c.indices.exists(index=INDEX):
        print(f"🗑️  Deleting index '{INDEX}' ...")
        c.indices.delete(index=INDEX, ignore=[404])
    # create fresh
    print(f"🆕 Creating index '{INDEX}' with kNN mapping ...")
    c.indices.create(index=INDEX, body=INDEX_BODY)
    print("✅ Done.")

if __name__ == "__main__":
    recreate_index()
