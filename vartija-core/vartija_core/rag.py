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
