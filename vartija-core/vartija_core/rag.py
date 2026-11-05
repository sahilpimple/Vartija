"""Retrieval with citations, no external services.

Corpus format (``corpus/*.md``)::

    tags: nis2

    ## [nis2:art23-3] Article 23(3): what makes an incident significant
    Text of the passage...

Each ``## [id] Title`` section is one citable chunk. The ID in brackets is what the
agents must cite; any citation not in the retrieved set is rejected (see agents.py).

Search is TF-IDF cosine similarity: small, deterministic and good enough for a corpus
of a few hundred passages. Swap ``Retriever.search`` for pgvector embeddings at the
event if you need semantic matching.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_HEADING = re.compile(r"^##\s+\[(?P<id>[^\]]+)\]\s*(?P<title>.*)$")
_TOKEN = re.compile(r"[a-z0-9äöå]+")
_STOP = set("""a an and are as at be by for from has have if in into is it its of on or that the
their this to was were will with within which who whom whose not no any all may must shall""".split())


@dataclass(frozen=True)
class Chunk:
    id: str
    title: str
    text: str
    source: str
    tags: tuple[str, ...]


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


def load_corpus(corpus_dir: Path) -> list[Chunk]:
    chunks: list[Chunk] = []
    for path in sorted(Path(corpus_dir).glob("*.md")):
        lines = path.read_text(encoding="utf-8").splitlines()
        tags: tuple[str, ...] = ()
        current: dict | None = None
        body: list[str] = []

        def flush() -> None:
            if current is not None:
                chunks.append(Chunk(current["id"], current["title"], "\n".join(body).strip(), path.name, tags))

        for line in lines:
            if line.lower().startswith("tags:") and current is None:
                tags = tuple(t.strip() for t in line.split(":", 1)[1].split(",") if t.strip())
                continue
            m = _HEADING.match(line)
            if m:
                flush()
                current, body = {"id": m["id"].strip(), "title": m["title"].strip()}, []
            elif current is not None:
                body.append(line)
        flush()
    ids = [c.id for c in chunks]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate chunk ids in corpus: {sorted(dupes)}")
    return chunks


class Retriever:
    def __init__(self, chunks: list[Chunk]) -> None:
        self.chunks = chunks
        self._tf = [Counter(tokenize(c.title + " " + c.title + " " + c.text)) for c in chunks]
        df: Counter = Counter()
        for tf in self._tf:
            df.update(tf.keys())
        n = max(len(chunks), 1)
        self._idf = {t: math.log((n + 1) / (d + 1)) + 1 for t, d in df.items()}
        self._norm = [self._vec_norm(tf) for tf in self._tf]

    def _vec_norm(self, tf: Counter) -> float:
        return math.sqrt(sum((v * self._idf.get(t, 0)) ** 2 for t, v in tf.items())) or 1.0

    def search(self, query: str, k: int = 5, tags: set[str] | None = None) -> list[tuple[Chunk, float]]:
        q = Counter(tokenize(query))
        q_norm = self._vec_norm(q)
        scored = []
        for chunk, tf, norm in zip(self.chunks, self._tf, self._norm):
            if tags and not (set(chunk.tags) & tags):
                continue
            dot = sum(qv * self._idf.get(t, 0) * tf.get(t, 0) * self._idf.get(t, 0) for t, qv in q.items())
            if dot > 0:
                scored.append((chunk, dot / (norm * q_norm)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    def get(self, chunk_id: str) -> Chunk | None:
        return next((c for c in self.chunks if c.id == chunk_id), None)


# --- Code-aware BM25 and hybrid retrieval ----------------------------------------------
#
# Rule and standards text is full of identifiers that plain word tokenisation breaks up:
# "A-60", "II-2/9.2.3", "E26", "Pt.4 Ch.8", "IEC 62443-4-2". ``code_tokenize`` keeps each
# compound identifier as one token *and* emits its parts, so an exact code match scores
# high while partial matches still count.

_CODE = re.compile(r"[a-z0-9äöå]+(?:[-/.:][a-z0-9äöå]+)+")


def code_tokenize(text: str) -> list[str]:
    low = text.lower()
    tokens = tokenize(low)
    tokens += [m.group(0).strip(".") for m in _CODE.finditer(low)]
    # short codes like "e26" are already kept by tokenize (len > 1); single letters are not
    return tokens


class BM25Retriever:
    """Okapi BM25 over title+text with code-aware tokens. Same interface as Retriever."""

    def __init__(self, chunks: list[Chunk], k1: float = 1.4, b: float = 0.75) -> None:
        self.chunks, self.k1, self.b = chunks, k1, b
        self._tf = [Counter(code_tokenize(c.title + " " + c.title + " " + c.text)) for c in chunks]
        self._len = [sum(tf.values()) for tf in self._tf]
        self._avg = (sum(self._len) / len(self._len)) if self._len else 1.0
        df: Counter = Counter()
        for tf in self._tf:
            df.update(tf.keys())
        n = len(chunks)
        self._idf = {t: math.log(1 + (n - d + 0.5) / (d + 0.5)) for t, d in df.items()}
        self._by_id = {c.id: c for c in chunks}

    def search(self, query: str, k: int = 5, tags: set[str] | None = None) -> list[tuple[Chunk, float]]:
        q = set(code_tokenize(query))
        scored = []
        for chunk, tf, dl in zip(self.chunks, self._tf, self._len):
            if tags and not (set(chunk.tags) & tags):
                continue
            s = 0.0
            for t in q:
                f = tf.get(t, 0)
                if f:
                    s += self._idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / self._avg))
            if s > 0:
                scored.append((chunk, s))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    def get(self, chunk_id: str) -> Chunk | None:
        return self._by_id.get(chunk_id)





class HybridRetriever:
    """Reciprocal-rank fusion of BM25 (exact terms and codes), TF-IDF, and optionally
    dense embeddings (meaning). Pass ``embed`` = a function mapping a list of strings to
    vectors (Ollama, OpenAI-compatible, sentence-transformers, or pgvector lookups).

    ``refs`` maps a chunk id to the ids it cross-references; ``search(..., expand=1)``
    appends referenced chunks after the direct hits, so "see Regulation 9.2" is followed.
    """

    def __init__(self, chunks: list[Chunk], embed=None, refs: dict[str, list[str]] | None = None,
                 rrf_k: int = 60) -> None:
        self.chunks = chunks
        self.bm25 = BM25Retriever(chunks)
        self.tfidf = Retriever(chunks)
        self.embed, self.rrf_k = embed, rrf_k
        self.refs = refs or {}
        self._by_id = {c.id: c for c in chunks}
        self._vecs = embed([c.title + "\n" + c.text for c in chunks]) if (embed and chunks) else None

    @staticmethod
    def _cos(a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a)) or 1.0
        nb = math.sqrt(sum(y * y for y in b)) or 1.0
        return dot / (na * nb)

    def _dense(self, query: str, tags: set[str] | None, k: int) -> list[tuple[Chunk, float]]:
        if not self._vecs:
            return []
        qv = self.embed([query])[0]
        scored = [(c, self._cos(qv, v)) for c, v in zip(self.chunks, self._vecs)
                  if not tags or (set(c.tags) & tags)]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    def search(self, query: str, k: int = 5, tags: set[str] | None = None,
               expand: int = 0) -> list[tuple[Chunk, float]]:
        pool = max(k * 4, 20)
        fused: dict[str, float] = {}
        for ranking in (self.bm25.search(query, pool, tags), self.tfidf.search(query, pool, tags),
                        self._dense(query, tags, pool)):
            for rank, (chunk, _) in enumerate(ranking):
                fused[chunk.id] = fused.get(chunk.id, 0.0) + 1.0 / (self.rrf_k + rank + 1)
        hits = sorted(fused.items(), key=lambda x: x[1], reverse=True)[:k]
        out = [(self._by_id[cid], s) for cid, s in hits]
        if expand:
            seen = {c.id for c, _ in out}
            frontier = [c.id for c, _ in out]
            for _ in range(expand):
                nxt = []
                for cid in frontier:
                    for ref in self.refs.get(cid, []):
                        if ref in self._by_id and ref not in seen:
                            seen.add(ref)
                            nxt.append(ref)
                            out.append((self._by_id[ref], 0.0))  # score 0 = reached by reference
                frontier = nxt
        return out

    def get(self, chunk_id: str) -> Chunk | None:
        return self._by_id.get(chunk_id)


def make_retriever(chunks: list[Chunk], kind: str | None = None, embed=None,
                   refs: dict[str, list[str]] | None = None):
    """``kind`` = tfidf (default, original behaviour) | bm25 | hybrid. Env: VARTIJA_RETRIEVER."""
    import os

    kind = (kind or os.getenv("VARTIJA_RETRIEVER", "tfidf")).lower()
    if kind == "tfidf":
        return Retriever(chunks)
    if kind == "bm25":
        return BM25Retriever(chunks)
    if kind == "hybrid":
        return HybridRetriever(chunks, embed=embed, refs=refs)
    raise ValueError(f"unknown retriever '{kind}' (tfidf|bm25|hybrid)")
