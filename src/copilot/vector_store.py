from __future__ import annotations

import hashlib
import math
from typing import Dict, List

import chromadb

from .utils import data_path, project_root, read_json


class LocalHasherEmbedding:
    def __init__(self, dims: int = 256) -> None:
        self.dims = dims

    def embed(self, text: str) -> List[float]:
        vec = [0.0] * self.dims
        tokens = [t.strip().lower() for t in text.replace("_", " ").replace("-", " ").split() if t.strip()]
        if not tokens:
            return vec
        for tok in tokens:
            h = int(hashlib.sha256(tok.encode("utf-8")).hexdigest(), 16)
            idx = h % self.dims
            vec[idx] += 1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


class ChromaStore:
    def __init__(self) -> None:
        self.path = project_root() / ".state" / "chroma"
        self.path.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=str(self.path))
        self.embedder = LocalHasherEmbedding(dims=256)
        self._init_collections()

    def _init_collections(self) -> None:
        self.runbooks = self.client.get_or_create_collection("runbooks")
        self.historical = self.client.get_or_create_collection("historical_incidents")
        if self.runbooks.count() == 0 or self.historical.count() == 0:
            self.rebuild()

    def rebuild(self) -> None:
        runbooks = read_json(data_path("runbooks.json"))
        historical = read_json(data_path("historical_incidents.json"))

        try:
            self.client.delete_collection("runbooks")
        except Exception:  # noqa: BLE001
            pass
        try:
            self.client.delete_collection("historical_incidents")
        except Exception:  # noqa: BLE001
            pass

        self.runbooks = self.client.get_or_create_collection("runbooks")
        self.historical = self.client.get_or_create_collection("historical_incidents")

        rb_ids, rb_docs, rb_meta, rb_emb = [], [], [], []
        for rb in runbooks:
            doc = f"{rb.get('title','')} {rb.get('content','')} {' '.join(rb.get('symptoms', []))} {' '.join(rb.get('categories', []))}"
            rb_ids.append(rb["id"])
            rb_docs.append(doc)
            rb_meta.append(
                {
                    "service": rb.get("service", ""),
                    "categories": ",".join(rb.get("categories", [])),
                    "source_id": rb.get("id", ""),
                    "title": rb.get("title", ""),
                    "content": rb.get("content", ""),
                }
            )
            rb_emb.append(self.embedder.embed(doc))

        hs_ids, hs_docs, hs_meta, hs_emb = [], [], [], []
        for hs in historical:
            doc = f"{hs.get('summary','')} {hs.get('root_cause','')} {' '.join(hs.get('symptoms', []))}"
            hs_ids.append(hs["id"])
            hs_docs.append(doc)
            hs_meta.append(
                {
                    "service": hs.get("service", ""),
                    "source_id": hs.get("id", ""),
                    "summary": hs.get("summary", ""),
                    "root_cause": hs.get("root_cause", ""),
                }
            )
            hs_emb.append(self.embedder.embed(doc))

        if rb_ids:
            self.runbooks.add(ids=rb_ids, documents=rb_docs, metadatas=rb_meta, embeddings=rb_emb)
        if hs_ids:
            self.historical.add(ids=hs_ids, documents=hs_docs, metadatas=hs_meta, embeddings=hs_emb)

    def query_runbooks(self, query: str, top_k: int = 3, service: str | None = None) -> Dict:
        q = self.embedder.embed(query)
        result = self.runbooks.query(query_embeddings=[q], n_results=top_k * 3)
        ids = result.get("ids", [[]])[0]
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]

        rows = []
        for i, source_id in enumerate(ids):
            meta = metas[i] if i < len(metas) else {}
            if service and meta.get("service") != service:
                continue
            dist = distances[i] if i < len(distances) else 1.0
            score = max(0.0, 1.0 - float(dist))
            rows.append(
                {
                    "source_id": source_id,
                    "title": meta.get("title", ""),
                    "snippet": meta.get("content", "")[:180] or (docs[i][:180] if i < len(docs) else ""),
                    "score": round(score, 3),
                    "reason": "vector similarity over runbook corpus",
                    "service": meta.get("service", ""),
                    "categories": meta.get("categories", ""),
                }
            )
        return {"rows": rows[:top_k]}

    def query_historical(self, query: str, top_k: int = 3, service: str | None = None) -> Dict:
        q = self.embedder.embed(query)
        result = self.historical.query(query_embeddings=[q], n_results=top_k * 3)
        ids = result.get("ids", [[]])[0]
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]

        rows = []
        for i, source_id in enumerate(ids):
            meta = metas[i] if i < len(metas) else {}
            if service and meta.get("service") != service:
                continue
            dist = distances[i] if i < len(distances) else 1.0
            score = max(0.0, 1.0 - float(dist))
            rows.append(
                {
                    "source_id": source_id,
                    "snippet": meta.get("summary", "") or (docs[i][:180] if i < len(docs) else ""),
                    "score": round(score, 3),
                    "root_cause": meta.get("root_cause", "unknown"),
                    "reason": "vector similarity over historical incident corpus",
                    "service": meta.get("service", ""),
                }
            )
        return {"rows": rows[:top_k]}
