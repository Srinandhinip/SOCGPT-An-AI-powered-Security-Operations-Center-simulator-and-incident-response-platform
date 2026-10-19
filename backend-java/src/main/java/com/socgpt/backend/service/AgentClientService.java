package com.socgpt.backend.service;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.InvestigationReport;
import com.socgpt.backend.model.RemediationPlan;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.InvestigationReportRepository;
import com.socgpt.backend.repository.RemediationPlanRepository;

/**
 * Talks to the Python LangGraph agent. Everything here runs on a background thread so the request
 * that raised the incident is never held up while the AI thinks:
 * find similar past incidents (RAG) -> ask the agent -> save report + PENDING plan ->
 * index the incident for future RAG -> e-mail the people who must decide.
 */
@Service
public class AgentClientService {

    private final WebClient webClient;
    private final Duration timeout;
    private final IncidentRepository incidentRepository;
    private final InvestigationReportRepository reportRepository;
    private final RemediationPlanRepository planRepository;
    private final RagService ragService;
    private final NotificationService notificationService;
    private final AuditService auditService;

    private final Set<Integer> inFlight = ConcurrentHashMap.newKeySet();
    private final Map<Integer, String> lastError = new ConcurrentHashMap<>();
    private final ExecutorService pool = Executors.newFixedThreadPool(4, r -> {
        Thread t = new Thread(r, "socgpt-ai");
        t.setDaemon(true);
        return t;
    });

    public AgentClientService(IncidentRepository incidentRepository,
                              InvestigationReportRepository reportRepository,
                              RemediationPlanRepository planRepository,
                              RagService ragService,
                              NotificationService notificationService,
                              AuditService auditService,
                              @Value("${socgpt.agent.url:http://localhost:8000}") String agentUrl,
                              @Value("${socgpt.agent.timeout-seconds:120}") long timeoutSeconds) {
        this.webClient = WebClient.create(agentUrl);
        this.timeout = Duration.ofSeconds(timeoutSeconds);
        this.incidentRepository = incidentRepository;
        this.reportRepository = reportRepository;
        this.planRepository = planRepository;
        this.ragService = ragService;
        this.notificationService = notificationService;
        this.auditService = auditService;
    }

    public boolean isInFlight(Integer incidentId) {
        return inFlight.contains(incidentId);
    }

    /** Why the last AI attempt for this incident failed (null if it did not, or is still running). */
    public String lastError(Integer incidentId) {
        return lastError.get(incidentId);
    }

    /**
     * Starts the AI investigation in the background.
     * @param chainContext optional description of the multi-stage attack this incident belongs to
     * @return false if an investigation for this incident is already running
     */
    public boolean requestInvestigation(Incident incident, SecurityEvent event,
                                        MitreMappingService.Mapping mapping, Map<String, Object> chainContext) {
        Integer id = incident.getIncidentId();
        if (!inFlight.add(id)) {
            return false;
        }
        lastError.remove(id);
        pool.submit(() -> {
            try {
                Runnable afterwards = investigate(incident, event, mapping, chainContext);
                // the plan is saved: the incident may be re-analysed again while the slower extras run
                inFlight.remove(id);
                try {
                    afterwards.run();
                } catch (RuntimeException e) {
                    System.out.println("[AI AGENT] Follow-up work for incident " + id + " failed: " + e.getMessage());
                }
            } catch (Exception e) {
                String msg = describe(e);
                lastError.put(id, msg);
                System.out.println("[AI AGENT] Incident " + id + " failed: " + msg);
                try {
                    auditService.log(null, "AI_INVESTIGATION_FAILED", "incident", id, msg);
                } catch (RuntimeException ignored) {
                    // the failure is already remembered in memory
                }
            } finally {
                inFlight.remove(id);
            }
        });
        return true;
    }

    private Runnable investigate(Incident incident, SecurityEvent event, MitreMappingService.Mapping mapping,
                             Map<String, Object> chainContext) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("incidentId", incident.getIncidentId());
        body.put("severity", incident.getSeverity());
        body.put("riskScore", incident.getRiskScore());
        if (incident.getEventId() != null) {
            body.put("eventId", incident.getEventId());
        }
        if (event != null) {
            body.put("eventType", event.getEventType());
            body.put("sourceIp", event.getSourceIp());
        }
        if (mapping != null) {
            body.put("mitreId", mapping.mitreId());
            body.put("techniqueName", mapping.techniqueName());
            body.put("tactic", mapping.tactic());
            body.put("csfFunction", mapping.csfFunction());
            body.put("csfDescription", mapping.csfDescription());
        }
        if (chainContext != null) {
            body.put("chain", chainContext);
        }
        List<Map<String, Object>> similar = ragService.findSimilarForPrompt(incident, event, mapping);
        if (!similar.isEmpty()) {
            body.put("similarIncidents", similar);
            System.out.println("[RAG] Incident #" + incident.getIncidentId() + ": " + similar.size() + " similar past incident(s) sent to the AI");
        }

        Map<?, ?> response = webClient.post()
            .uri("/investigate")
            .bodyValue(body)
            .retrieve()
            .bodyToMono(Map.class)
            .block(timeout);
        if (response == null) {
            throw new IllegalStateException("The AI agent returned an empty response");
        }
        return handleResponse(incident, event, mapping, response);
    }

    /** Saves the report and plan; returns the slower follow-up work (indexing, e-mail) to run afterwards. */
    private Runnable handleResponse(Incident original, SecurityEvent event, MitreMappingService.Mapping mapping,
                                Map<?, ?> response) {
        Integer incidentId = original.getIncidentId();
        String status = asString(response.get("status"));
        if (!"READY_FOR_APPROVAL".equals(status)) {
            String err = asString(response.get("error"));
            throw new IllegalStateException(err == null || err.isBlank() ? "The AI did not finish (status " + status + ")" : err);
        }

        Object reportObj = response.get("report");
        String planJson = asString(response.get("remediationPlanJson"));
        if (!(reportObj instanceof Map<?, ?> report) || planJson == null) {
            throw new IllegalStateException("The AI response was missing the report or the plan");
        }

        InvestigationReport r = new InvestigationReport();
        r.setIncidentId(incidentId);
        String summary = asString(report.get("summary"));
        r.setSummary(summary != null ? summary : "No summary returned");
        r.setClassification(cut(asString(report.get("classification")), 50));   // column is VARCHAR(50)
        r.setImpact(asString(report.get("impact")));
        if (report.get("confidence") instanceof Number n) {
            r.setConfidence(Math.max(0, Math.min(1, n.doubleValue())));
        }
        r.setEvidence(asString(response.get("evidenceJson")));
        reportRepository.save(r);

        RemediationPlan plan = new RemediationPlan();
        plan.setIncidentId(incidentId);
        plan.setSteps(planJson);
        plan.setStatus("PENDING");          // nothing runs until a human approves
        planRepository.save(plan);

        Incident incident = incidentRepository.findById(incidentId).orElse(original);
        incident.setStatus("AWAITING_APPROVAL");
        incident = incidentRepository.save(incident);

        System.out.println("[AI AGENT] Incident " + incidentId + " investigated. Report + PENDING plan saved, awaiting approval.");

        Incident saved = incident;
        return () -> {
            ragService.index(saved, event, mapping, r.getClassification());
            notificationService.actionRequired(saved, r, event, mapping);
        };
    }

    private static String describe(Exception e) {
        if (e instanceof WebClientResponseException w) {
            String body = w.getResponseBodyAsString();
            return "AI agent answered HTTP " + w.getStatusCode().value()
                + (body == null || body.isBlank() ? "" : ": " + cut(body, 300));
        }
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String m = root.getMessage() == null ? root.getClass().getSimpleName() : root.getMessage();
        if (m.contains("Connection refused") || m.contains("connect")) {
            return "Cannot reach the AI agent (is the Python service running on port 8000?): " + cut(m, 160);
        }
        return cut(m, 300);
    }

    private static String cut(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max);
    }

    private static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
