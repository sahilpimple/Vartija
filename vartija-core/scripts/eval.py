"""Evaluate the significance assessor against labelled scenarios.

    python scripts/eval.py                       # rule engine
    VARTIJA_LLM=ollama python scripts/eval.py    # local model
    python scripts/eval.py --json results.json   # save details for the pitch

Prints per-flag precision/recall, exact-match accuracy, citation coverage and latency.
The exact-match accuracy is the number to put on the finals slide, with the scenario count.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vartija_core.agents import KNOWN_FLAGS, Assessor  # noqa: E402
from vartija_core.config import load_config  # noqa: E402
from vartija_core.grc import YamlGrcProvider  # noqa: E402
from vartija_core.llm import make_llm  # noqa: E402
from vartija_core.models import Case, Event  # noqa: E402
from vartija_core.rag import Retriever, load_corpus  # noqa: E402
from vartija_core.settings import get_settings  # noqa: E402


def build(scn: dict) -> tuple[Case, list[Event]]:
    now = datetime.now(timezone.utc)
    case = Case(id=scn["id"], correlation_id=scn["id"], title=scn["id"], sector=scn["sector"],
                asset_id=scn["events"][0].get("asset_id"), detected_at=now, flags={}, milestones={})
    events = [Event(event_id=f"{scn['id']}-{i}", case_id=case.id, schema_version="1.0", source="eval",
                    event_type=e["event_type"], occurred_at=now, severity=e["severity"],
                    confidence=e["confidence"], summary=e["summary"], attributes=e.get("attributes", {}),
                    evidence_refs=[], payload_sha256="0" * 64)
              for i, e in enumerate(scn["events"])]
    return case, events


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenarios", default=str(ROOT / "scenarios" / "scenarios.yaml"))
    parser.add_argument("--json", help="write per-scenario results to this file")
    parser.add_argument("--min-accuracy", type=float, default=0.0, help="exit 1 if exact-match accuracy is lower")
    args = parser.parse_args()

    settings = get_settings()
    config = load_config(settings.config_dir)
    assessor = Assessor(config, Retriever(load_corpus(settings.corpus_dir)), make_llm(settings),
                        settings.config_dir / "prompts")
    grc = YamlGrcProvider(settings.seed_dir / "grc.yaml")
    scenarios = yaml.safe_load(Path(args.scenarios).read_text(encoding="utf-8"))["scenarios"]

    tally = {f: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for f in KNOWN_FLAGS}
    exact, cited, latencies, rows = 0, 0, [], []
    for scn in scenarios:
        case, events = build(scn)
        t0 = time.perf_counter()
        result = assessor.assess(case, events, grc.context_for(case.asset_id))
        latencies.append(time.perf_counter() - t0)
        expected = {f: bool(scn["expected"].get(f, False)) for f in KNOWN_FLAGS}
        got = {f: bool(result.flags.get(f, False)) for f in KNOWN_FLAGS}
        for f in KNOWN_FLAGS:
            key = ("t" if expected[f] == got[f] else "f") + ("p" if got[f] else "n")
            tally[f][key] += 1
        match = expected == got
        exact += match
        cited += bool(result.citations) or not any(got.values())
        rows.append({"id": scn["id"], "match": match, "expected": expected, "got": got,
                     "confidence": result.confidence, "engine": result.engine, "citations": result.citations,
                     "rejected_citations": result.rejected_citations, "rationale": result.rationale})
        mark = "PASS" if match else "FAIL"
        print(f"[{mark}] {scn['id']:<40} conf={result.confidence:.2f} engine={result.engine}")
        if not match:
            diff = {f: f"expected {expected[f]}, got {got[f]}" for f in KNOWN_FLAGS if expected[f] != got[f]}
            print(f"       {diff}")

    n = len(scenarios)
    print("\nPer flag            precision  recall")
    for f, t in tally.items():
        p = t["tp"] / (t["tp"] + t["fp"]) if t["tp"] + t["fp"] else 1.0
        r = t["tp"] / (t["tp"] + t["fn"]) if t["tp"] + t["fn"] else 1.0
        print(f"  {f:<22} {p:6.2f}   {r:6.2f}")
    accuracy = exact / n if n else 0.0
    print(f"\nExact match: {exact}/{n} = {accuracy:.0%}")
    print(f"Positive verdicts with a citation: {cited}/{n}")
    print(f"Latency: median {statistics.median(latencies) * 1000:.0f} ms, max {max(latencies) * 1000:.0f} ms")
    if args.json:
        Path(args.json).write_text(json.dumps({"accuracy": accuracy, "n": n, "results": rows}, indent=2))
    return 0 if accuracy >= args.min_accuracy else 1


if __name__ == "__main__":
    raise SystemExit(main())
