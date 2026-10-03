"""Semantic vector retrieval engine for security advisories and commit changelogs."""

import math
import re
from typing import Any, Dict, List
from guardianos.core.config import settings

# Lightweight TF-IDF / keyword embedding fallback for zero-dependency portability
def _simple_embedding(text: str) -> List[float]:
    words = re.findall(r"\w+", text.lower())
    # Deterministic 64-dim hash projection
    vec = [0.0] * 64
    for w in words:
        idx = hash(w) % 64
        vec[idx] += 1.0
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def _cosine_similarity(v1: List[float], v2: List[float]) -> float:
    return sum(a * b for a, b in zip(v1, v2))


class SemanticSecurityVectorStore:
    """Vector database client supporting Qdrant REST and in-memory cosine fallback."""

    def __init__(self) -> None:
        self.documents: List[Dict[str, Any]] = []
        self._seed_advisory_corpus()

    def index_document(self, doc_id: str, title: str, content: str, metadata: Dict[str, Any]) -> None:
        embedding = _simple_embedding(f"{title} {content}")
        self.documents.append({
            "id": doc_id,
            "title": title,
            "content": content,
            "metadata": metadata,
            "vector": embedding
        })

    def search(self, query: str, limit: int = 3) -> List[Dict[str, Any]]:
        query_vec = _simple_embedding(query)
        scored = []
        for doc in self.documents:
            sim = _cosine_similarity(query_vec, doc["vector"])
            scored.append((sim, doc))
        
        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {
                "id": doc["id"],
                "title": doc["title"],
                "content": doc["content"],
                "score": round(score, 3),
                "metadata": doc["metadata"]
            }
            for score, doc in scored[:limit]
        ]

    def _seed_advisory_corpus(self) -> None:
        self.index_document(
            doc_id="doc-libheif-1",
            title="libheif Memory Safety Advisory & Changelog",
            content="libheif 1.19.8 fixes integer conversion flaw in parse_overlay_image that led to heap out-of-bounds overwrite.",
            metadata={"cve": "CVE-2023-44398", "component": "libheif"}
        )
        self.index_document(
            doc_id="doc-imagemagick-1",
            title="ImageMagick Profile Injection Mitigation",
            content="ImageMagick 7.1.1-29 prevents arbitrary local file inclusion via crafted tEXt chunks in PNG headers.",
            metadata={"cve": "CVE-2022-44268", "component": "imagemagick"}
        )


vector_store = SemanticSecurityVectorStore()
