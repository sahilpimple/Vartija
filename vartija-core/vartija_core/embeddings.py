"""Embedding functions for ``HybridRetriever(embed=...)``.

    VARTIJA_RETRIEVER=hybrid VARTIJA_EMBED=ollama VARTIJA_EMBED_MODEL=nomic-embed-text

``ollama pull nomic-embed-text`` first. Any failure (Ollama not running, model missing)
is reported by ``make_embedder`` and the retriever runs without embeddings rather than
crashing the API. Vectors are computed once at start-up for the whole corpus.
"""

from __future__ import annotations

from typing import Callable

import httpx

from .settings import Settings

Embedder = Callable[[list[str]], list[list[float]]]


class EmbeddingError(Exception):
    pass


def ollama_embedder(base_url: str, model: str, timeout: float = 60.0, batch: int = 32) -> Embedder:
    url = base_url.rstrip("/") + "/api/embed"

    def embed(texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), batch):
            try:
                r = httpx.post(url, json={"model": model, "input": texts[i:i + batch]}, timeout=timeout)
                r.raise_for_status()
                out += r.json()["embeddings"]
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                raise EmbeddingError(f"ollama embeddings failed: {exc}") from exc
        return out

    return embed


def openai_embedder(base_url: str, model: str, api_key: str, timeout: float = 60.0, batch: int = 64) -> Embedder:
    url = base_url.rstrip("/") + "/embeddings"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    def embed(texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), batch):
            try:
                r = httpx.post(url, json={"model": model, "input": texts[i:i + batch]}, headers=headers,
                               timeout=timeout)
                r.raise_for_status()
                out += [d["embedding"] for d in sorted(r.json()["data"], key=lambda d: d["index"])]
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                raise EmbeddingError(f"embeddings call failed: {exc}") from exc
        return out

    return embed


def make_embedder(settings: Settings) -> tuple[Embedder | None, str]:
    """(embedder or None, status message). Probes once so a dead backend is caught at start-up."""
    kind = settings.embed_backend.lower()
    if kind in {"", "none", "off"}:
        return None, "embeddings off"
    if kind == "ollama":
        fn = ollama_embedder(settings.llm_base_url, settings.embed_model, settings.llm_timeout_seconds)
    elif kind == "openai":
        fn = openai_embedder(settings.llm_base_url, settings.embed_model, settings.llm_api_key,
                             settings.llm_timeout_seconds)
    else:
        return None, f"unknown VARTIJA_EMBED '{kind}', embeddings off"
    try:
        fn(["probe"])
    except EmbeddingError as exc:
        return None, f"embeddings unavailable, continuing without: {exc}"
    return fn, f"embeddings {kind}:{settings.embed_model}"
