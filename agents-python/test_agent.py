"""Offline tests for the agent (Gemini is mocked). Run:  python -m pytest -q"""
import json
import os

os.environ["EMBED_PROVIDER"] = "local"
os.environ.setdefault("GEMINI_API_KEY", "test-key")

from fastapi.testclient import TestClient  # noqa: E402

import graph  # noqa: E402
import llm  # noqa: E402
from main import app  # noqa: E402

client = TestClient(app)
PROMPTS = []

REPORT = {"summary": "s", "classification": "x" * 80, "confidence": 7, "impact": "i", "evidence": ["a", 2]}
PLAN = {"steps": [{"stage": "Prevention", "action": "p"}, {"stage": "Containment", "action": "c"}]}


def fake(prompt, attempts=3):
    PROMPTS.append(prompt)
    return REPORT if "Respond with ONLY a JSON object with exactly these keys" in prompt else PLAN


def body(**extra):
    b = {"incidentId": 5, "severity": "HIGH", "riskScore": 80, "eventType": "sqli", "sourceIp": "1.2.3.4",
         "mitreId": "T1190", "techniqueName": "Exploit", "tactic": "Initial Access"}
    b.update(extra)
    return b


def test_investigate_normalises_output(monkeypatch):
    monkeypatch.setattr(llm, "complete_json", fake)
    r = client.post("/investigate", json=body()).json()
    assert r["status"] == "READY_FOR_APPROVAL"
    assert len(r["report"]["classification"]) == 50
    assert r["report"]["confidence"] == 1.0
    assert json.loads(r["evidenceJson"]) == ["a", "2"]
    steps = json.loads(r["remediationPlanJson"])
    assert [s["stage"] for s in steps] == ["Containment", "Prevention"]


def test_chain_and_similar_reach_the_prompt(monkeypatch):
    monkeypatch.setattr(llm, "complete_json", fake)
    PROMPTS.clear()
    chain = {"chainId": 1, "stageCount": 2, "sourceIp": "1.2.3.4", "stages": [
        {"incidentId": 1, "tactic": "Reconnaissance", "eventType": "port_scan", "mitreId": "T1595", "severity": "MEDIUM", "detectedAt": "t"},
        {"incidentId": 2, "tactic": "Initial Access", "eventType": "sqli", "mitreId": "T1190", "severity": "CRITICAL", "detectedAt": "t"}]}
    similar = [{"incidentId": 9, "similarity": 0.91, "classification": "SQLi", "severity": "CRITICAL", "planOutcome": "REJECTED",
                "rejected": True, "rejectionReason": "too disruptive",
                "approvedSteps": json.dumps([{"stage": "Containment", "action": "block ip"}])}]
    client.post("/investigate", json=body(chain=chain, similarIncidents=similar))
    assert len(PROMPTS) == 2
    for p in PROMPTS:
        assert "MULTI-STAGE ATTACK" in p and "Reconnaissance" in p
        assert "too disruptive" in p and "block ip" in p


def test_failure_stops_graph(monkeypatch):
    def boom(prompt, attempts=3):
        raise RuntimeError("Gemini failed")
    monkeypatch.setattr(llm, "complete_json", boom)
    r = client.post("/investigate", json=body()).json()
    assert r["status"] == "FAILED" and "Gemini failed" in r["error"] and r["remediationPlanJson"] is None


def test_embed_local_is_768_and_similarity_sensible():
    def emb(t):
        return client.post("/embed", json={"text": t}).json()["embedding"]
    a, b, c = emb("Attack: sqli. Tactic: Initial Access."), emb("Attack: sqli. Tactic: Initial Access. Severity: HIGH."), emb("malware execution workstation")
    assert len(a) == 768
    dot = lambda x, y: sum(i * j for i, j in zip(x, y))
    assert dot(a, b) > 0.6 > dot(a, c)
    assert client.post("/embed", json={"text": "  "}).status_code == 400
