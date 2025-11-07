# search_opensearch_vec.py
import json
import warnings
import requests
from sentence_transformers import SentenceTransformer

# ---- CONFIG ----
OPENSEARCH_URL = "https://10.10.3.25:9200"
INDEX = "final"
USERNAME = "admin"          # <-- change if needed
PASSWORD = "admin"          # <-- change if needed
VERIFY_SSL = False          # self-signed certs on 10.10.3.25

# ----------------
if not VERIFY_SSL:
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

model = SentenceTransformer("all-MiniLM-L6-v2")

def vector_search(query_text: str, size: int = 5):
    # 1) embed
    qv = model.encode(query_text, normalize_embeddings=False).tolist()

    # 2) script_score with cosineSimilarity over doc['vec']
    body = {
        "size": size,
        "track_total_hits": False,
        "min_score": 1.0,  # because we add +1.0 below
        "_source": ["title", "description", "solution", "devseccomments", "source"],
        "query": {
            "script_score": {
                "query": {"match_all": {}},
                "script": {
                    "source": "cosineSimilarity(params.qv, doc['vec']) + 1.0",
                    "params": {"qv": qv}
                }
            }
        }
    }

    url = f"{OPENSEARCH_URL}/{INDEX}/_search"
    resp = requests.post(
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_SSL,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    hits = data.get("hits", {}).get("hits", [])
    results = []
    for h in hits:
        src = h.get("_source", {})
        score = float(h.get("_score", 0.0))
        cosine = score - 1.0  # undo the +1.0 shift
        results.append({
            "id": h.get("_id"),
            "score": round(score, 4),
            "cosine": round(cosine, 4),
            "title": src.get("title", ""),
            "source": src.get("source", ""),
            "devseccomments": src.get("devseccomments", ""),
        })
    return results

if __name__ == "__main__":
    text = input("Enter search text: ").strip()
    if not text:
        print("No query text provided.")
        raise SystemExit(0)

    try:
        results = vector_search(text, size=5)
        for i, r in enumerate(results, 1):
            print(f"\n#{i}  ID={r['id']}")
            print(f"    score={r['score']}  (cosine≈{r['cosine']})")
            print(f"    title: {r['title']}")
            if r['source']:
                print(f"    source: {r['source']}")
            if r['devseccomments']:
                print(f"    devsec: {r['devseccomments'][:200]}{'...' if len(r['devseccomments'])>200 else ''}")
    except requests.HTTPError as e:
        print("OpenSearch error:", e.response.text)
    except Exception as e:
        print("Error:", str(e))
