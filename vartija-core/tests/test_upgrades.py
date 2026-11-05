"""Tests for the pre-event upgrades: code-aware/hybrid retrieval, document ingestion with
cross-references, quote verification and deterministic quantity checks."""

from pathlib import Path

import pytest

from vartija_core.citations import quote_in_text, verify_citations
from vartija_core.docingest import extract_refs, load_refs, read_document, split_numbered, write_corpus
from vartija_core.quantities import check_requirement, parse_quantity
from vartija_core.rag import BM25Retriever, Chunk, HybridRetriever, Retriever, code_tokenize, load_corpus, make_retriever

DOC = """Example Safety Standard  Page 1 of 3
Introductory text about scope.
Section 4 General requirements
Equipment shall be protected as required by Section 4.2.
Example Safety Standard  Page 2 of 3
4.1 Insulation
Boundaries shall be insulated to class A-60, with a rating of not less than 60 min.
4.2 Access
Doors shall have a clear width of at least 800 mm. See also paragraph 4.1.
Article 23(4) Reporting
Within 24 hours an early warning shall be sent.
Example Safety Standard  Page 3 of 3
"""


@pytest.fixture
def paras():
    return split_numbered(DOC, prefix="ess")


def test_split_keeps_document_numbering(paras):
    ids = [p.id for p in paras]
    assert ids == ["ess:preamble", "ess:4", "ess:4.1", "ess:4.2", "ess:23(4)"]
    assert next(p for p in paras if p.id == "ess:4.1").parent == "ess:4"
    assert all("Page" not in p.text for p in paras)  # repeated page headers stripped


def test_cross_references(paras):
    refs = extract_refs(paras)
    assert refs["ess:4"] == ["ess:4.2"]
    assert set(refs["ess:4.2"]) == {"ess:4.1", "ess:4"}  # explicit ref + parent


def test_duplicate_numbers_are_flagged_not_merged():
    paras = split_numbered("4.1 First\na\n4.1 Second\nb\n", prefix="x")
    assert [p.id for p in paras] == ["x:4.1", "x:4.1~2"]


def test_write_and_reload_corpus(tmp_path, paras):
    out = write_corpus(paras, tmp_path / "ess.md", ["ess"], extract_refs(paras))
    chunks = load_corpus(tmp_path)
    assert {c.id for c in chunks} == {p.id for p in paras}
    assert load_refs(tmp_path)["ess:4.2"]
    assert read_document(out).startswith("tags: ess")


def test_html_reading(tmp_path):
    f = tmp_path / "a.html"
    f.write_text("<html><style>x{}</style><p>4.1 Title</p><p>Body &amp; more</p></html>")
    assert "Body & more" in read_document(f)


def test_code_tokens_survive():
    toks = code_tokenize("Class A-60 per Reg. II-2/9.2.3 and IEC 62443-4-2")
    assert {"a-60", "ii-2/9.2.3", "62443-4-2"} <= set(toks)


def _chunks():
    return [Chunk("s:1", "Fire integrity", "Boundaries shall be A-60 insulated.", "s", ("s",)),
            Chunk("s:2", "Fire doors", "Doors in A-0 boundaries close automatically.", "s", ("s",)),
            Chunk("s:3", "Ventilation", "Ducts passing boundaries need dampers. See s:1.", "s", ("s",))]


def test_bm25_prefers_exact_code():
    hits = BM25Retriever(_chunks()).search("A-60 boundary", k=2)
    assert hits[0][0].id == "s:1"


def test_hybrid_fuses_and_follows_refs():
    r = HybridRetriever(_chunks(), refs={"s:3": ["s:1"]})
    hits = r.search("duct dampers", k=1, expand=1)
    assert [c.id for c, _ in hits] == ["s:3", "s:1"]
    assert r.get("s:2").title == "Fire doors"


def test_hybrid_with_embeddings():
    vocab = ["fire", "door", "duct"]

    def embed(texts):
        return [[t.lower().count(w) for w in vocab] for t in texts]

    hits = HybridRetriever(_chunks(), embed=embed).search("door", k=1)
    assert hits[0][0].id == "s:2"


def test_make_retriever_kinds():
    assert isinstance(make_retriever(_chunks(), "tfidf"), Retriever)
    assert isinstance(make_retriever(_chunks(), "bm25"), BM25Retriever)
    assert isinstance(make_retriever(_chunks(), "hybrid"), HybridRetriever)
    with pytest.raises(ValueError):
        make_retriever(_chunks(), "nope")


def test_quote_verification():
    text = "Boundaries shall be insulated to class A-60, with a rating of not less than 60 min."
    assert quote_in_text("insulated to class A-60", text) == (True, 1.0)
    assert quote_in_text("insulated  to Class A–60", text)[0]          # spacing, case, en dash
    assert not quote_in_text("insulated to class A-30", text)[0]        # changed number


def test_verify_citations_reasons():
    r = BM25Retriever(_chunks())
    ok, bad = verify_citations(
        ["s:1", {"id": "s:2", "quote": "close automatically"}, {"id": "s:2", "quote": "open manually"},
         "s:99", "s:3"], r, retrieved_ids={"s:1", "s:2"})
    assert [c.id for c in ok] == ["s:1", "s:2"]
    assert [c.reason for c in bad] == ["quoted text not found in the passage", "unknown passage id",
                                       "passage was not in the retrieved context"]


@pytest.mark.parametrize("req, actual, expected", [
    ("not less than 60 min", "45 min", False),
    ("not less than 60 min", "1 h", True),
    ("at least 800 mm", "0.8 m", True),
    ("at least 1.5 m", "1200 mm", False),
    ("not more than 4,5 mm/s", "3.2 mm/s", True),
    ("maximum 10 bar", "1.2 MPa", False),
    ("≥ 20 kN", "20000 N", True),
    ("less than 24 hours", "1 day", False),
])
def test_quantity_checks(req, actual, expected):
    assert check_requirement(req, actual).ok is expected


def test_quantity_messages_and_undecidable():
    c = check_requirement("at least 1.5 m", "1200 mm")
    assert c.message == "1200 mm (1.2 m) does not meet >= 1.5 m"
    assert check_requirement("at least 1.5 m", "30 min").ok is None
    assert check_requirement("at least 1.5 parsecs", "1 m").ok is None
    assert parse_quantity("1 200,5 kg").value == 1200.5
    assert check_requirement("60 min.", "60 min").ok is True  # trailing dot is not "minimum"
