from __future__ import annotations

import os
from typing import Dict, List

from .utils import data_path, read_json
from .vector_store import ChromaStore


class Retriever:
    def __init__(self) -> None:
        self.store = ChromaStore()
        self.manifest = read_json(data_path("manifest.json"))

    def _manifest_filter_runbooks(self, rows: List[Dict], service: str) -> List[Dict]:
        hints = self.manifest.get("service_hints", {}).get(service, {})
        categories = set(hints.get("categories", []))
        out = []
        for row in rows:
            row_categories = set([c for c in row.get("categories", "").split(",") if c])
            if row.get("service") == service or categories.intersection(row_categories):
                boosted = dict(row)
                if row.get("service") == service:
                    boosted["score"] = round(min(1.0, row.get("score", 0.0) + 0.15), 3)
                boosted["reason"] = "manifest prefilter + vector similarity"
                out.append(boosted)
        return out or rows

    def _manifest_filter_historical(self, rows: List[Dict], service: str) -> List[Dict]:
        out = [r for r in rows if r.get("service") == service]
        if out:
            for row in out:
                row["score"] = round(min(1.0, row.get("score", 0.0) + 0.1), 3)
                row["reason"] = "service prefilter + vector similarity"
        return out or rows

    def search_runbooks(self, query: str, service: str, severity: str, mode: str = "vector", top_k: int = 3) -> List[Dict]:
        del severity
        rows = self.store.query_runbooks(query=query, top_k=max(6, top_k), service=None).get("rows", [])
        if mode == "manifest_vector":
            rows = self._manifest_filter_runbooks(rows, service)
        rows.sort(key=lambda x: x.get("score", 0.0), reverse=True)
        return rows[:top_k]

    def search_historical(self, query: str, service: str, severity: str, mode: str = "vector", top_k: int = 3) -> List[Dict]:
        del severity
        rows = self.store.query_historical(query=query, top_k=max(6, top_k), service=None).get("rows", [])
        if mode == "manifest_vector":
            rows = self._manifest_filter_historical(rows, service)
        rows.sort(key=lambda x: x.get("score", 0.0), reverse=True)
        return rows[:top_k]

    @staticmethod
    def default_mode() -> str:
        return os.getenv("RETRIEVAL_MODE", "vector").strip().lower()
