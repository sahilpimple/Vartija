"""AI agents: significance assessment and report drafting.

Design rules (these are the product's trust story, keep them):
  1. Every model output is validated: unknown flags dropped, citations not in the
     retrieved context rejected and recorded, actions outside policy removed.
  2. If the model fails or is not configured, a deterministic rule engine answers
     instead and the assessment says so. The demo never dies on stage.
  3. The model only ever sees redacted text.
  4. Agents recommend; ``approvals.py`` decides what may happen.

At the event, the challenge-specific work goes into the prompts (config/prompts),
the corpus, the sector hints and the rule functions below.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config, Regime, Sector
from .conflicts import detect as detect_conflicts
from .llm import LLM, LLMError, NoLLM, parse_json_object
from .models import Case, Event, as_utc
from .rag import Chunk, Retriever
from .redact import Redactor, redact_text

KNOWN_FLAGS = ("nis2_significant", "cra_reportable", "personal_data_breach")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Passages the rule engine cites when they exist in the corpus.
RULE_CITATIONS = {
    "nis2_significant": ["nis2:art23-3", "fi-cyberact:reporting"],
    "cra_reportable": ["cra:art14-1", "cra:art14-2", "cra:art14-3", "cra:art14-5"],
    "personal_data_breach": ["gdpr:art33-1"],
}


def load_prompt(path: Path) -> tuple[str, str]:
    """Prompt files start with ``version: <id>`` then a ``---`` line."""
    raw = Path(path).read_text(encoding="utf-8")
    header, _, body = raw.partition("---")
    version = header.split(":", 1)[1].strip() if ":" in header else "unversioned"
    return version, body.strip()


@dataclass
class AssessmentResult:
    engine: str
    prompt_version: str
    flags: dict
    confidence: float
    rationale: str
    citations: list[str]
    rejected_citations: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    conflicts: list[dict] = field(default_factory=list)
    needs_human_review: bool = True
    context_ids: list[str] = field(default_factory=list)


def _attrs(events: list[Event]) -> dict:
    """Merge event attributes; numbers take the max, booleans OR, lists union."""
    merged: dict = {}
    for e in events:
        for k, v in (e.attributes or {}).items():
            if isinstance(v, bool):
                merged[k] = merged.get(k, False) or v
            elif isinstance(v, (int, float)):
                merged[k] = max(merged.get(k, v), v)
            elif isinstance(v, list):
                merged[k] = sorted(set(merged.get(k, [])) | set(map(str, v)))
            else:
                merged.setdefault(k, v)
    return merged


def _incident_text(case: Case, events: list[Event]) -> str:
    lines = [f"Case: {case.title}", f"Detected at: {as_utc(case.detected_at).isoformat()}"]
    for e in events:
        lines.append(f"- [{e.event_id}] {e.event_type} severity={e.severity} confidence={e.confidence:.2f}: "
                     f"{e.summary} attributes={json.dumps(e.attributes, ensure_ascii=False, sort_keys=True)}")
    return "\n".join(lines)


class Assessor:
    def __init__(self, config: Config, retriever: Retriever, llm: LLM, prompts_dir: Path) -> None:
        self.config, self.retriever, self.llm = config, retriever, llm
        self.prompt_version, self.prompt = load_prompt(Path(prompts_dir) / "significance.md")
        self.allowed_actions = sorted(config.policy.get("actions", {}))

    # -- retrieval ---------------------------------------------------------------
    def _context(self, sector: Sector, events: list[Event], k: int = 6) -> list[Chunk]:
        regimes = self.config.regimes_for(sector.id)
        tags = {t for r in regimes for t in r.corpus_tags}
        query = " ".join([e.event_type.replace(".", " ") + " " + e.summary for e in events])
        query += " significant incident reporting obligation " + " ".join(sector.significance_hints.get("keywords", []))
        found = [c for c, _ in self.retriever.search(query, k=k, tags=tags or None)]
        # Always include the passages the rules depend on, so both engines see the same law.
        for ids in RULE_CITATIONS.values():
            for cid in ids:
                chunk = self.retriever.get(cid)
                if chunk and chunk not in found and (not tags or set(chunk.tags) & tags):
                    found.append(chunk)
        return found

    # -- deterministic engine ----------------------------------------------------
    def _rules(self, sector: Sector, events: list[Event], grc: dict, context_ids: set[str]) -> AssessmentResult:
        a = _attrs(events)
        regimes = {r.id for r in self.config.regimes_for(sector.id)}
        hints = sector.significance_hints
        top = max((SEVERITY_RANK[e.severity] for e in events), default=0)
        text = " ".join(e.summary.lower() + " " + e.event_type.lower() for e in events)
        keyword_hits = [k for k in hints.get("keywords", []) if k in text]
        reasons: list[str] = []
        flags = {f: False for f in KNOWN_FLAGS}
        wanted_citations: list[str] = []

        if "nis2_fi" in regimes:
            users = a.get("users_affected", 0)
            outage = a.get("outage_minutes", 0)
            big_users = users >= hints.get("users_affected_threshold", 10**9)
            long_outage = outage >= hints.get("outage_minutes_threshold", 10**9)
            loss = a.get("financial_loss_eur", 0) >= 100_000
            severe_and_malicious = top >= 3 and a.get("malicious", False) and a.get("cross_border", False)
            if ((top >= 3 and (big_users or long_outage or loss))
                    or severe_and_malicious
                    or (top == 4 and keyword_hits)):
                flags["nis2_significant"] = True
                why = []
                if big_users:
                    why.append(f"{users} users affected")
                if long_outage:
                    why.append(f"{outage} min service disruption")
                if loss:
                    why.append("material financial loss")
                if severe_and_malicious:
                    why.append("severe, malicious and cross-border")
                if not why:
                    why.append(f"critical severity with sector signals ({', '.join(keyword_hits)})")
                reasons.append("Likely a significant NIS2 incident: " + "; ".join(why) + ".")
                wanted_citations += RULE_CITATIONS["nis2_significant"]
        if "cra" in regimes:
            if a.get("actively_exploited") and a.get("product_affected"):
                flags["cra_reportable"] = True
                reasons.append("An actively exploited vulnerability affects a product placed on the EU market (CRA Art. 14).")
                wanted_citations += ["cra:art14-1", "cra:art14-2"]
            elif a.get("product_affected") and top == 4:
                flags["cra_reportable"] = True
                reasons.append("A severe incident affects the security of a product with digital elements (CRA Art. 14).")
                wanted_citations += ["cra:art14-3", "cra:art14-5"]
        if "gdpr" in regimes and a.get("personal_data"):
            flags["personal_data_breach"] = True
            reasons.append("Personal data may be affected; a GDPR breach assessment is needed.")
            wanted_citations += RULE_CITATIONS["personal_data_breach"]

        signals = sum(k in a for k in ("users_affected", "outage_minutes", "malicious", "cross_border",
                                        "actively_exploited", "personal_data"))
        mean_conf = sum(e.confidence for e in events) / max(len(events), 1)
        confidence = round(min(0.95, 0.4 + 0.1 * signals) * (0.5 + 0.5 * mean_conf), 2)
        if not reasons:
            reasons.append("No reporting threshold is clearly met by the available signals. Re-assess as facts arrive.")

        citations = list(dict.fromkeys(c for c in wanted_citations if c in context_ids))
        actions = self._rule_actions(events, a, flags)
        risks = ", ".join(r["id"] for r in grc.get("risks", []))
        if risks:
            reasons.append(f"Linked risks in the register: {risks}.")
        return AssessmentResult(engine="rules", prompt_version="rules-v1", flags=flags, confidence=confidence,
                                rationale=" ".join(reasons), citations=citations, recommended_actions=actions)

    def _rule_actions(self, events: list[Event], a: dict, flags: dict) -> list[str]:
        text = " ".join(e.event_type + " " + e.summary for e in events).lower()
        actions: list[str] = []
        if any(w in text for w in ("credential", "password", "login", "account takeover")):
            actions += ["rotate_credentials", "block_ip_range"]
        if any(w in text for w in ("ransomware", "exploit", "malware", "compromis", "firmware")):
            actions += ["contain_host"]
        if any(w in text for w in ("ddos", "flood", "volumetric")):
            actions += ["block_ip_range"]
        if any(flags.values()):
            actions += ["submit_report", "open_corrective_action"]
        if flags.get("personal_data_breach"):
            actions += ["notify_customers"]
        seen: list[str] = []
        for act in actions:
            if act in self.allowed_actions and act not in seen:
                seen.append(act)
        return seen

    # -- model engine -------------------------------------------------------------
    def _llm(self, case: Case, sector: Sector, events: list[Event], grc: dict, context: list[Chunk]) -> AssessmentResult:
        red = Redactor()
        context_block = "\n\n".join(f"[{c.id}] {c.title}\n{c.text}" for c in context)
        governance = {"asset": grc.get("asset"), "risks": [r.get("title") for r in grc.get("risks", [])],
                      "controls": [c.get("id") for c in grc.get("controls", [])]}
        user = (f"SECTOR: {sector.name} ({sector.entity_class} entity). Regimes in scope: "
                f"{', '.join(sector.regimes)}.\nSECTOR HINTS: {json.dumps(sector.significance_hints)}\n\n"
                f"CONTEXT:\n{context_block}\n\nGOVERNANCE CONTEXT:\n{json.dumps(governance, ensure_ascii=False)}\n\n"
                f"<INCIDENT>\n{red.redact(_incident_text(case, events))}\n</INCIDENT>")
        system = self.prompt.replace("ALLOWED_ACTIONS", ", ".join(self.allowed_actions))
        raw = parse_json_object(self.llm.complete(system, user, json_mode=True))

        flags = {f: bool((raw.get("flags") or {}).get(f, False)) for f in KNOWN_FLAGS}
        try:
            confidence = max(0.0, min(1.0, float(raw.get("confidence", 0))))
        except (TypeError, ValueError):
            confidence = 0.0
        context_ids = {c.id for c in context}
        cited = [str(c).strip("[] ") for c in raw.get("citations", []) if isinstance(c, (str, int))]
        citations = [c for c in cited if c in context_ids]
        rejected = [c for c in cited if c not in context_ids]
        actions = [a for a in raw.get("recommended_actions", []) if a in self.allowed_actions]
        return AssessmentResult(engine=self.llm.name, prompt_version=self.prompt_version, flags=flags,
                                confidence=round(confidence, 2),
                                rationale=red.restore(str(raw.get("rationale", "")))[:2000],
                                citations=citations, rejected_citations=rejected, recommended_actions=actions)

    # -- public -------------------------------------------------------------------
    def assess(self, case: Case, events: list[Event], grc: dict) -> AssessmentResult:
        sector = self.config.sector(case.sector)
        context = self._context(sector, events)
        context_ids = [c.id for c in context]
        if isinstance(self.llm, NoLLM):
            result = self._rules(sector, events, grc, set(context_ids))
        else:
            try:
                result = self._llm(case, sector, events, grc, context)
            except LLMError as exc:
                result = self._rules(sector, events, grc, set(context_ids))
                result.engine = f"rules (fallback: {exc})"[:64]
        result.context_ids = context_ids
        result.conflicts = detect_conflicts(self.config, actions=result.recommended_actions, flags=result.flags)
        # Unsupported claims or low confidence always go to a human. So does any positive flag.
        result.needs_human_review = (result.confidence < 0.8 or bool(result.rejected_citations)
                                     or any(result.flags.values()) or not result.citations)
        return result


# =============================================================================
# Report drafting
# =============================================================================

class ReportDrafter:
    def __init__(self, config: Config, llm: LLM, prompts_dir: Path) -> None:
        self.config, self.llm = config, llm
        self.prompt_version, self.prompt = load_prompt(Path(prompts_dir) / "report_field.md")

    def draft(self, *, case: Case, events: list[Event], grc: dict, regime: Regime, stage: str,
              citations: list[str], language: str = "en") -> tuple[list[dict], float, str]:
        template = regime.report_templates.get(stage)
        if not template:
            raise ValueError(f"no template for {regime.id}/{stage}")
        sector = self.config.sector(case.sector)
        a = _attrs(events)
        event_ids = [e.event_id for e in events]
        evidence_refs = sorted({r for e in events for r in (e.evidence_refs or [])})
        fields: list[dict] = []
        llm_keys: list[dict] = []

        for spec in template:
            src, value = spec["source"], None
            if src.startswith("org."):
                v = sector.org.get(src[4:])
                value = ", ".join(v) if isinstance(v, list) else v
            elif src == "case.detected_at":
                value = as_utc(case.detected_at).isoformat()
            elif src == "grc.asset":
                asset = grc.get("asset") or {}
                value = f"{asset.get('name')} ({asset.get('service')})" if asset.get("known") else None
            elif src == "events.iocs":
                value = ", ".join(a.get("iocs", [])) or None
            elif src == "llm":
                llm_keys.append(spec)
                continue
            fields.append({"key": spec["key"], "label": spec["label"], "value": value, "source": src,
                           "filled": value not in (None, ""), "evidence": event_ids if src.startswith("events") else []})

        engine = "rules"
        generated: dict[str, str] = {}
        if llm_keys and not isinstance(self.llm, NoLLM):
            red = Redactor()
            try:
                user = (f"FIELDS TO WRITE: {json.dumps({s['key']: s['label'] + ('. ' + s['hint'] if s.get('hint') else '') for s in llm_keys}, ensure_ascii=False)}\n"
                        f"LANGUAGE: {language}\n\nGOVERNANCE CONTEXT: "
                        f"{json.dumps({'asset': grc.get('asset'), 'risks': [r.get('title') for r in grc.get('risks', [])]}, ensure_ascii=False)}\n\n"
                        f"<INCIDENT>\n{red.redact(_incident_text(case, events))}\n</INCIDENT>")
                raw = parse_json_object(self.llm.complete(self.prompt, user, json_mode=True))
                # Placeholders stay in the draft on purpose (data minimisation); a human
                # restores a detail only if the authority actually needs it.
                generated = {s["key"]: str(raw.get(s["key"], "")).strip() for s in llm_keys}
                engine = self.llm.name
            except LLMError:
                generated, engine = {}, "rules (llm unavailable)"
        if not generated:
            generated = self._rule_fields(llm_keys, events, a)

        for spec in llm_keys:
            value = generated.get(spec["key"]) or None
            fields.append({"key": spec["key"], "label": spec["label"], "value": value,
                           "source": "ai-draft" if engine.startswith(("ollama", "openai")) else "rules",
                           "filled": bool(value), "evidence": event_ids + evidence_refs + citations})

        order = {s["key"]: i for i, s in enumerate(template)}
        fields.sort(key=lambda f: order[f["key"]])
        completeness = round(sum(f["filled"] for f in fields) / len(fields), 2)
        return fields, completeness, engine

    @staticmethod
    def _rule_fields(specs: list[dict], events: list[Event], a: dict) -> dict:
        def yn(key: str) -> str:
            if key not in a:
                return "Unknown at time of reporting"
            return "Yes" if a[key] else "No"

        # Data minimisation: a regulator needs the facts, not customers' contact details.
        summary = redact_text(" ".join(e.summary.rstrip(".") + "." for e in events[:3]))
        canned = {
            "summary": summary,
            "update": summary,
            "description": summary,
            "malicious": yn("malicious"),
            "cross_border": yn("cross_border"),
            "severity_impact": (f"Highest severity reported: {max((e.severity for e in events), key=SEVERITY_RANK.get)}. "
                                f"Users affected: {a.get('users_affected', 'unknown')}. "
                                f"Service disruption: {a.get('outage_minutes', 'unknown')} minutes."),
        }
        return {s["key"]: canned[s["key"]] for s in specs if s["key"] in canned}
