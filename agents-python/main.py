"""
SOCGPT Agent Service (FastAPI).
Java calls POST /investigate the instant an incident is created; this service
runs the LangGraph workflow and returns a structured report + remediation plan.
Java also calls POST /embed to turn incident text into vectors for RAG.
"""

import json
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import embeddings
import llm
from graph import incident_graph

app = FastAPI(title="SOCGPT Agent Service")


class IncidentRequest(BaseModel):
    incidentId: int
    severity: str
    riskScore: int
    # Everything below is optional so older callers keep working.
    eventId: Optional[int] = None
    eventType: Optional[str] = None
    sourceIp: Optional[str] = None
    mitreId: Optional[str] = None
    techniqueName: Optional[str] = None
    tactic: Optional[str] = None
    csfFunction: Optional[str] = None
    csfDescription: Optional[str] = None
    # multi-stage attack this incident belongs to: {chainId, stageCount, sourceIp, stages[...]}
    chain: Optional[Dict[str, Any]] = None
    # RAG: similar past incidents with their outcomes
    similarIncidents: Optional[List[Dict[str, Any]]] = None


class EmbedRequest(BaseModel):
    text: str
    kind: str = "document"    # "query" or "document"; informational


@app.post("/investigate")
def investigate(incident: IncidentRequest):
    final_state = incident_graph.invoke({"incident": incident.model_dump()})

    report = final_state.get("report")
    plan = final_state.get("remediation_plan")

    return {
        "incidentId": incident.incidentId,
        "status": final_state.get("status", "FAILED"),
        "report": report,
        "remediationPlan": plan,
        # The two lists again as ready-made JSON text, so the Java backend can
        # store them in its TEXT columns as-is without needing a JSON library.
        "evidenceJson": json.dumps(report.get("evidence", [])) if report else None,
        "remediationPlanJson": json.dumps(plan) if plan else None,
        "error": final_state.get("error"),
    }


@app.post("/embed")
def embed(request: EmbedRequest):
    text = request.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="text must not be empty")
    try:
        vector = llm.embed(text[:8000])
    except RuntimeError as e:
        # Java treats any failure here as "no RAG context" and carries on.
        raise HTTPException(status_code=503, detail=str(e))
    return {
        "embedding": vector,
        "dimensions": len(vector),
        "provider": embeddings.provider(),
        "model": embeddings.model_name(),
    }


@app.get("/health")
def health():
    return {"status": "ok", "embedProvider": embeddings.provider(), "model": llm.MODEL_NAME}
