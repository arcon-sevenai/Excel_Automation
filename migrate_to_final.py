# migrate_to_final.py
# Copy vectors (id, values, metadata) from Pinecone -> OpenSearch (Basic Auth)
# Deps: pinecone>=5,<6, opensearch-py>=2.6, python-dotenv, tqdm

import os
import sys
from typing import Iterable, Dict, Any, List

from dotenv import load_dotenv
from tqdm import tqdm
from opensearchpy import OpenSearch, helpers, RequestsHttpConnection

# Pinecone (modern SDK v5)
from pinecone import Pinecone

# ================================
# Env + Config
# ================================
load_dotenv()

# Pinecone
PINECONE_API_KEY     = os.getenv("PINECONE_API_KEY")
PINECONE_HOST        = os.getenv("PINECONE_HOST")                 # e.g. https://your-index-xxxxx.pinecone.io
PINECONE_INDEX_NAME  = os.getenv("PINECONE_INDEX_NAME")           # optional if HOST provided
PINECONE_NAMESPACE   = os.getenv("PINECONE_NAMESPACE", "vuln-base-namespace")

# OpenSearch (Basic Auth)
OPENSEARCH_HOST      = os.getenv("OPENSEARCH_HOST", "https://10.10.3.25:9200")
OPENSEARCH_USER      = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS      = os.getenv("OPENSEARCH_PASS", "admin")
OPENSEARCH_INDEX     = os.getenv("OPENSEARCH_INDEX", "final")

# Controls
PAGE_LIMIT_ENV       = int(os.getenv("PAGE_LIMIT", "100"))  # will be clamped to 1..99 below
BATCH_SIZE           = int(os.getenv("BATCH_SIZE", "500"))
VERIFY_CERTS         = os.getenv("VERIFY_CERTS", "false").lower() in ("1", "true", "yes")
REQUEST_TIMEOUT      = int(os.getenv("OS_REQUEST_TIMEOUT", "60"))

# Optionally mute HTTPS warnings when VERIFY_CERTS is false
if not VERIFY_CERTS:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================================
# Pinecone helpers
# ================================
def get_pinecone_index():
    if not PINECONE_API_KEY:
        print("Missing PINECONE_API_KEY")
        sys.exit(1)

    pc = Pinecone(api_key=PINECONE_API_KEY)

    # Prefer host if provided; else use index name
    if PINECONE_HOST:
        idx = pc.Index(host=PINECONE_HOST)
    elif PINECONE_INDEX_NAME:
        idx = pc.Index(PINECONE_INDEX_NAME)
    else:
        print("Provide either PINECONE_HOST or PINECONE_INDEX_NAME")
        sys.exit(1)

    return idx

def iter_namespace_vectors(index, namespace: str, page_limit: int = 100) -> Iterable[Dict[str, Any]]:
    """
    Iterate all vectors in a namespace.
    Pinecone v5 enforces 1–99 for 'limit'. We clamp accordingly.
    index.list(...) yields lists of IDs (batches).
    """
    print(f"📦 Scanning Pinecone namespace '{namespace}' ...")
    total = 0

    # clamp to Pinecone limits
    limit = max(1, min(page_limit, 99))

    # index.list yields batches of IDs (list[str])
    for ids in index.list(namespace=namespace, limit=limit):
        if not ids:
            continue

        fetched = index.fetch(ids=ids, namespace=namespace)
        vec_map = (fetched or {}).get("vectors") or {}
        for vid, rec in vec_map.items():
            total += 1
            yield {
                "id": vid,
                "values": rec.get("values", []) or [],
                "metadata": rec.get("metadata", {}) or {}
            }

        if total and total % (limit * 10) == 0:
            print(f"→ scanned {total} vectors so far...")

    print(f"✅ Completed scan. Total vectors: {total}")

# ================================
# OpenSearch helpers (Basic Auth)
# ================================
def get_opensearch_client():
    print(f"🔗 Connecting to OpenSearch at {OPENSEARCH_HOST} ...")
    client = OpenSearch(
        hosts=[OPENSEARCH_HOST],                    # URL string is fine
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        verify_certs=VERIFY_CERTS,
        timeout=REQUEST_TIMEOUT,
        connection_class=RequestsHttpConnection
    )
    if not client.ping():
        print("❌ OpenSearch ping failed. Check host/credentials/SSL.")
        sys.exit(1)
    print("✅ Connected to OpenSearch")
    return client

def ensure_index(client: OpenSearch, index_name: str):
    """
    Create index if missing. Keep mapping dynamic so we can just store metadata and 'vec'.
    If you need k-NN later, define a proper dense_vector mapping with dims.
    """
    if client.indices.exists(index=index_name):
        return
    client.indices.create(index=index_name)
    print(f"🆕 Created index '{index_name}'")

def bulk_upload_vectors(os_client, index_name: str, vectors_iter: Iterable[Dict[str, Any]],
                        batch_size: int = 500):
    """
    Streams upload to OpenSearch in batches.
    Each doc: { "_index": index_name, "_id": id, "_source": {"vec": values, **metadata} }
    """
    print(f"📤 Streaming upload to OpenSearch index '{index_name}'...")
    actions: List[Dict[str, Any]] = []
    total = 0

    for v in tqdm(vectors_iter):
        src = {"vec": v["values"]}
        if v.get("metadata"):
            src.update(v["metadata"])

        actions.append({
            "_index": index_name,
            "_id": v["id"],
            "_source": src
        })
        if len(actions) >= batch_size:
            helpers.bulk(os_client, actions)
            total += len(actions)
            actions = []

    if actions:
        helpers.bulk(os_client, actions)
        total += len(actions)

    print(f"✅ Upload complete: {total} docs to '{index_name}'")

# ================================
# Main
# ================================
def main():
    pinecone_index = get_pinecone_index()
    os_client = get_opensearch_client()
    ensure_index(os_client, OPENSEARCH_INDEX)

    vectors = iter_namespace_vectors(pinecone_index, PINECONE_NAMESPACE, page_limit=PAGE_LIMIT_ENV)
    bulk_upload_vectors(os_client, OPENSEARCH_INDEX, vectors, batch_size=BATCH_SIZE)

if __name__ == "__main__":
    main()
