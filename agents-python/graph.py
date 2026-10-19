"""
The SOCGPT LangGraph workflow (the AI half of the pipeline):

    ingest -> investigate --(ok)-----> generate_remediation -> END
                          \\--(failed)-> END

Human approval, saving to the database, audit logging and recovery all
happen in the Java backend, not here. This graph only does the reasoning
steps that need an LLM and returns a structured result for Java to store.

Context the Java backend may attach to the incident:
  chain            - the incident is one stage of a multi-stage attack (same IP, several tactics)
  similarIncidents - similar past incidents found by RAG, with what analysts approved / rejected
"""

import json
from typing import Optional, TypedDict

from langgraph.graph import END, StateGraph

import llm
from prompts import (
    CHAIN_INTRO,
    CHAIN_OUTRO,
    INVESTIGATION_PROMPT,
    REMEDIATION_PROMPT,
    SIMILAR_INTRO,
)

PLAN_STAGES = ["Containment", "Eradication", "Recovery", "Validation", "Prevention"]


class IncidentState(TypedDict, total=False):
    # input (sent by Java)
    incident: dict

    # produced by `investigate`
    report: dict
    # produced by `generate_remediation`
    remediation_plan: list

    # control
    status: str            # OPEN -> READY_FOR_APPROVAL, or FAILED
    error: Optional[str]


def _val(incident: dict, key: str) -> str:
    """Prompt-friendly value: missing/None becomes 'unknown'."""
    value = incident.get(key)
    return "unknown" if value in (None, "") else str(value)


def _clip(value, limit: int = 400) -> str:
    text = "" if value is None else str(value).strip()
    return text if len(text) <= limit else text[:limit] + "..."


def chain_block(incident: dict) -> str:
    """Prompt text describing the multi-stage attack this incident belongs to ('' if none)."""
    chain = incident.get("chain")
    if not isinstance(chain, dict):
        return ""
    stages = [s for s in (chain.get("stages") or []) if isinstance(s, dict)]
    if len(stages) < 2:
        return ""
    lines = []
    for n, s in enumerate(stages, start=1):
        lines.append(
            f"  {n}. {_clip(s.get('tactic'), 60)} / {_clip(s.get('eventType'), 40)} "
            f"({_clip(s.get('mitreId'), 12)}, incident #{s.get('incidentId')}, "
            f"severity {_clip(s.get('severity'), 12)}) at {_clip(s.get('detectedAt'), 40)}"
        )
    intro = CHAIN_INTRO.format(
        source_ip=_clip(chain.get("sourceIp"), 45) or "unknown",
        stage_count=chain.get("stageCount") or len(stages),
    )
    return intro + "\n".join(lines) + "\n" + CHAIN_OUTRO


def _steps_from(raw) -> list:
    """The Java side passes an approved plan as JSON text; turn it into [(stage, action), ...]."""
    if not raw:
        return []
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [(str(s.get("stage", "")), str(s.get("action", ""))) for s in data if isinstance(s, dict)]


def similar_block(incident: dict) -> str:
    """Prompt text for RAG hits ('' if there are none)."""
    hits = incident.get("similarIncidents")
    if not isinstance(hits, list) or not hits:
        return ""
    parts = []
    for hit in hits[:5]:
        if not isinstance(hit, dict):
            continue
        sim = hit.get("similarity")
        lines = [
            f"- Incident #{hit.get('incidentId')} (similarity "
            f"{sim if sim is not None else '?'}): {_clip(hit.get('classification'), 80) or 'unclassified'}, "
            f"severity {_clip(hit.get('severity'), 12)}, plan outcome {_clip(hit.get('planOutcome'), 20) or 'none'}"
        ]
        if hit.get("summary"):
            lines.append(f"  What happened: {_clip(hit.get('summary'), 300)}")
        steps = _steps_from(hit.get("approvedSteps"))
        if steps:
            lines.append("  APPROVED plan: " + " | ".join(f"{s}: {_clip(a, 140)}" for s, a in steps))
        if hit.get("rejected"):
            reason = _clip(hit.get("rejectionReason"), 240)
            lines.append("  A plan for this was REJECTED" + (f" by an analyst. Reason: {reason}" if reason else "."))
        parts.append("\n".join(lines))
    if not parts:
        return ""
    return SIMILAR_INTRO + "\n".join(parts) + "\n"


def ingest(state: IncidentState) -> dict:
    """Entry node. Marks the incident open. Placeholder for future
    enrichment (GeoIP lookup, threat-intel checks)."""
    return {"status": "OPEN", "error": None}


def investigate(state: IncidentState) -> dict:
    """Ask Gemini for a structured investigation report."""
    inc = state["incident"]
    prompt = INVESTIGATION_PROMPT.format(
        incident_id=_val(inc, "incidentId"),
        event_type=_val(inc, "eventType"),
        source_ip=_val(inc, "sourceIp"),
        severity=_val(inc, "severity"),
        risk_score=_val(inc, "riskScore"),
        mitre_id=_val(inc, "mitreId"),
        technique_name=_val(inc, "techniqueName"),
        tactic=_val(inc, "tactic"),
        csf_function=_val(inc, "csfFunction"),
        csf_description=_val(inc, "csfDescription"),
        chain_block=chain_block(inc),
        similar_block=similar_block(inc),
    )
    try:
        report = llm.complete_json(prompt)
    except RuntimeError as e:
        return {"status": "FAILED", "error": str(e)}

    if not isinstance(report, dict) or not report.get("summary"):
        return {"status": "FAILED", "error": "Gemini returned an investigation report without a summary"}

    # Keep confidence inside the 0..1 range our database column expects.
    try:
        report["confidence"] = max(0.0, min(1.0, float(report.get("confidence", 0.5))))
    except (TypeError, ValueError):
        report["confidence"] = 0.5
    # The evidence must be a list of strings (Java stores it as JSON text).
    evidence = report.get("evidence")
    report["evidence"] = [str(e) for e in evidence] if isinstance(evidence, list) else []
    # The classification column holds 50 characters.
    report["classification"] = str(report.get("classification") or "Unclassified")[:50]
    return {"report": report}


def route_after_investigate(state: IncidentState) -> str:
    """Conditional edge: don't plan remediation from a failed investigation."""
    return "stop" if state.get("status") == "FAILED" else "continue"


def generate_remediation(state: IncidentState) -> dict:
    """Ask Gemini for an attack-specific five-stage remediation plan."""
    inc = state["incident"]
    report = state["report"]
    prompt = REMEDIATION_PROMPT.format(
        summary=report.get("summary", "unknown"),
        classification=report.get("classification", "unknown"),
        impact=report.get("impact", "unknown"),
        severity=_val(inc, "severity"),
        mitre_id=_val(inc, "mitreId"),
        technique_name=_val(inc, "techniqueName"),
        tactic=_val(inc, "tactic"),
        csf_function=_val(inc, "csfFunction"),
        chain_block=chain_block(inc),
        similar_block=similar_block(inc),
    )
    try:
        plan = llm.complete_json(prompt)
    except RuntimeError as e:
        return {"status": "FAILED", "error": str(e)}

    raw_steps = plan.get("steps", []) if isinstance(plan, dict) else []
    steps = [
        {"stage": str(s.get("stage", "")).strip(), "action": str(s.get("action", "")).strip()}
        for s in raw_steps
        if isinstance(s, dict) and str(s.get("action", "")).strip()
    ]
    if not steps:
        return {"status": "FAILED", "error": "Gemini returned an empty remediation plan"}

    # Present the stages in the standard order whatever order the model used.
    order = {name: i for i, name in enumerate(PLAN_STAGES)}
    steps.sort(key=lambda s: order.get(s["stage"], len(PLAN_STAGES)))
    return {"remediation_plan": steps, "status": "READY_FOR_APPROVAL"}


def build_graph():
    graph = StateGraph(IncidentState)

    graph.add_node("ingest", ingest)
    graph.add_node("investigate", investigate)
    graph.add_node("generate_remediation", generate_remediation)

    graph.set_entry_point("ingest")
    graph.add_edge("ingest", "investigate")
    graph.add_conditional_edges(
        "investigate",
        route_after_investigate,
        {"continue": "generate_remediation", "stop": END},
    )
    graph.add_edge("generate_remediation", END)

    return graph.compile()


# Built once at startup and reused for every incident.
incident_graph = build_graph()
