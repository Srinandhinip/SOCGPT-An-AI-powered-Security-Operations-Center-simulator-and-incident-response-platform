package com.socgpt.backend.service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.reactive.function.client.WebClient;

import com.socgpt.backend.model.AuditLog;
import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.InvestigationReport;
import com.socgpt.backend.model.RemediationPlan;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.repository.AuditLogRepository;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.InvestigationReportRepository;
import com.socgpt.backend.repository.RemediationPlanRepository;
import com.socgpt.backend.repository.SecurityEventRepository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

/**
 * Retrieval-augmented generation over past incidents. Each investigated incident is turned into a
 * 768-number embedding (via the Python agent's /embed endpoint) and stored in Postgres with pgvector.
 * When a new incident arrives, the most similar past incidents - including what analysts approved or
 * rejected - are sent to the AI as context. Every failure here degrades to "no context".
 */
@Service
public class RagService {

    @PersistenceContext
    private EntityManager em;

    private final TransactionTemplate tx;
    private final WebClient webClient;
    private final MitreMappingService mappingService;
    private final IncidentRepository incidentRepository;
    private final SecurityEventRepository eventRepository;
    private final InvestigationReportRepository reportRepository;
    private final RemediationPlanRepository planRepository;
    private final AuditLogRepository auditRepository;
    private final boolean enabled;
    private final double minSimilarity;
    private final int topK;

    public RagService(PlatformTransactionManager transactionManager,
                      MitreMappingService mappingService,
                      IncidentRepository incidentRepository,
                      SecurityEventRepository eventRepository,
                      InvestigationReportRepository reportRepository,
                      RemediationPlanRepository planRepository,
                      AuditLogRepository auditRepository,
                      @Value("${socgpt.agent.url:http://localhost:8000}") String agentUrl,
                      @Value("${socgpt.rag.enabled:true}") boolean enabled,
                      @Value("${socgpt.rag.min-similarity:0.5}") double minSimilarity,
                      @Value("${socgpt.rag.top-k:3}") int topK) {
        this.tx = new TransactionTemplate(transactionManager);
        this.webClient = WebClient.create(agentUrl);
        this.mappingService = mappingService;
        this.incidentRepository = incidentRepository;
        this.eventRepository = eventRepository;
        this.reportRepository = reportRepository;
        this.planRepository = planRepository;
        this.auditRepository = auditRepository;
        this.enabled = enabled;
        this.minSimilarity = minSimilarity;
        this.topK = Math.max(1, topK);
    }

    public boolean isEnabled() {
        return enabled;
    }

    // ------------------------------------------------------------------ text that gets embedded

    /** Query text: only what is known the moment an incident is raised. */
    public String queryText(Incident incident, SecurityEvent event, MitreMappingService.Mapping mapping) {
        return describe(incident, event, mapping, null);
    }

    /** Document text: the same, plus what the AI concluded. */
    public String documentText(Incident incident, SecurityEvent event, MitreMappingService.Mapping mapping,
                               String classification) {
        return describe(incident, event, mapping, classification);
    }

    private static String describe(Incident incident, SecurityEvent event, MitreMappingService.Mapping m,
                                   String classification) {
        StringBuilder sb = new StringBuilder();
        sb.append("Attack: ").append(event == null ? "unknown" : event.getEventType()).append(". ");
        if (m != null) {
            sb.append("MITRE ATT&CK: ").append(m.mitreId()).append(' ').append(m.techniqueName()).append(". ")
              .append("Tactic: ").append(m.tactic()).append(". NIST CSF: ").append(m.csfFunction()).append(". ");
        }
        sb.append("Severity: ").append(incident.getSeverity()).append('.');
        if (classification != null && !classification.isBlank()) {
            sb.append(" Classification: ").append(classification).append('.');
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ embedding + storage

    /** Asks the Python agent for an embedding; returns it as a pgvector text literal "[0.1,0.2,...]". */
    String embed(String text, String kind) {
        Map<?, ?> response = webClient.post().uri("/embed")
            .bodyValue(Map.of("text", text, "kind", kind))
            .retrieve()
            .bodyToMono(Map.class)
            .block(Duration.ofSeconds(40));
        if (response == null || !(response.get("embedding") instanceof List<?> values) || values.isEmpty()) {
            throw new IllegalStateException("The embedding service returned no vector");
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(((Number) values.get(i)).doubleValue());
        }
        return sb.append(']').toString();
    }

    private void upsert(Integer incidentId, String text, String vector) {
        tx.executeWithoutResult(status -> em.createNativeQuery(
                "INSERT INTO incident_embeddings (incident_id, summary_text, embedding) "
                + "VALUES (?1, ?2, CAST(?3 AS vector)) "
                + "ON CONFLICT (incident_id) DO UPDATE SET summary_text = EXCLUDED.summary_text, "
                + "embedding = EXCLUDED.embedding, created_at = now()")
            .setParameter(1, incidentId)
            .setParameter(2, text)
            .setParameter(3, vector)
            .executeUpdate());
    }

    /** Stores (or replaces) the embedding of an investigated incident. Never throws. */
    public void index(Incident incident, SecurityEvent event, MitreMappingService.Mapping mapping, String classification) {
        if (!enabled) {
            return;
        }
        try {
            String text = documentText(incident, event, mapping, classification);
            upsert(incident.getIncidentId(), text, embed(text, "document"));
            System.out.println("[RAG] Indexed incident #" + incident.getIncidentId());
        } catch (Exception e) {
            System.out.println("[RAG] Could not index incident #" + incident.getIncidentId() + ": " + brief(e));
        }
    }

    // ------------------------------------------------------------------ searching

    /** Similar past incidents for the AI prompt (enriched with outcomes). Empty list on any failure. */
    public List<Map<String, Object>> findSimilarForPrompt(Incident incident, SecurityEvent event,
                                                           MitreMappingService.Mapping mapping) {
        if (!enabled) {
            return List.of();
        }
        try {
            String vector = embed(queryText(incident, event, mapping), "query");
            @SuppressWarnings("unchecked")
            List<Object[]> rows = em.createNativeQuery(
                    "SELECT e.incident_id, 1 - (e.embedding <=> CAST(?1 AS vector)) AS similarity "
                    + "FROM incident_embeddings e WHERE e.incident_id <> ?2 "
                    + "ORDER BY e.embedding <=> CAST(?1 AS vector) LIMIT ?3")
                .setParameter(1, vector)
                .setParameter(2, incident.getIncidentId())
                .setParameter(3, topK)
                .getResultList();
            return enrich(rows, true);
        } catch (Exception e) {
            System.out.println("[RAG] Similarity search skipped for incident #" + incident.getIncidentId() + ": " + brief(e));
            return List.of();
        }
    }

    /** Similar incidents for the UI, using the embedding already stored (no AI call). */
    public List<Map<String, Object>> similarForView(Integer incidentId) {
        if (!enabled) {
            return List.of();
        }
        try {
            @SuppressWarnings("unchecked")
            List<Object[]> rows = em.createNativeQuery(
                    "SELECT o.incident_id, 1 - (o.embedding <=> me.embedding) AS similarity "
                    + "FROM incident_embeddings me JOIN incident_embeddings o ON o.incident_id <> me.incident_id "
                    + "WHERE me.incident_id = ?1 ORDER BY o.embedding <=> me.embedding LIMIT ?2")
                .setParameter(1, incidentId)
                .setParameter(2, topK)
                .getResultList();
            return enrich(rows, false);
        } catch (Exception e) {
            return List.of();
        }
    }

    private List<Map<String, Object>> enrich(List<Object[]> rows, boolean forPrompt) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object[] row : rows) {
            int id = ((Number) row[0]).intValue();
            double sim = ((Number) row[1]).doubleValue();
            if (sim < minSimilarity) {
                continue;
            }
            Incident inc = incidentRepository.findById(id).orElse(null);
            if (inc == null) {
                continue;
            }
            SecurityEvent ev = inc.getEventId() == null ? null : eventRepository.findById(inc.getEventId()).orElse(null);
            InvestigationReport rep = reportRepository.findFirstByIncidentIdOrderByReportIdDesc(id).orElse(null);
            List<RemediationPlan> plans = planRepository.findByIncidentIdOrderByPlanIdAsc(id);

            Map<String, Object> m = new LinkedHashMap<>();
            m.put("incidentId", id);
            m.put("similarity", Math.round(sim * 1000d) / 1000d);
            m.put("eventType", ev == null ? null : ev.getEventType());
            m.put("severity", inc.getSeverity());
            m.put("status", inc.getStatus());
            m.put("classification", rep == null ? null : rep.getClassification());
            m.put("summary", rep == null ? null : rep.getSummary());

            RemediationPlan approved = null, rejected = null;
            for (RemediationPlan p : plans) {
                if ("APPROVED".equals(p.getStatus()) || "EXECUTED".equals(p.getStatus())) {
                    approved = p;
                } else if ("REJECTED".equals(p.getStatus())) {
                    rejected = p;
                }
            }
            RemediationPlan latest = plans.isEmpty() ? null : plans.get(plans.size() - 1);
            m.put("planOutcome", latest == null ? null : latest.getStatus());
            m.put("approvedSteps", approved == null ? null : approved.getSteps());   // JSON text, parsed by Python
            m.put("rejectionReason", rejected == null ? null : rejectionReason(rejected.getPlanId()));
            m.put("rejected", rejected != null);
            if (!forPrompt) {
                m.put("sourceIp", ev == null ? null : ev.getSourceIp());
                m.put("createdAt", inc.getCreatedAt());
            }
            out.add(m);
        }
        return out;
    }

    private String rejectionReason(Integer planId) {
        List<AuditLog> logs = auditRepository.findByTargetTypeAndTargetIdInOrderByLogIdAsc("remediation_plan", Set.of(planId));
        String reason = null;
        for (AuditLog a : logs) {
            if ("REJECT_REMEDIATION".equals(a.getAction()) && a.getDetails() != null) {
                int at = a.getDetails().indexOf("Reason: ");
                reason = at >= 0 ? a.getDetails().substring(at + 8).trim() : null;
            }
        }
        return reason == null || reason.isBlank() ? null : reason;
    }

    // ------------------------------------------------------------------ back-fill

    /** Embeds every incident that has a report (new installs, or after switching embedding provider). */
    public Map<String, Object> reindexAll() {
        int indexed = 0, failed = 0, skipped = 0;
        String lastError = null;
        for (Incident inc : incidentRepository.findAll()) {
            InvestigationReport rep = reportRepository.findFirstByIncidentIdOrderByReportIdDesc(inc.getIncidentId()).orElse(null);
            if (rep == null) {
                skipped++;
                continue;
            }
            SecurityEvent ev = inc.getEventId() == null ? null : eventRepository.findById(inc.getEventId()).orElse(null);
            MitreMappingService.Mapping mp = ev == null ? null : mappingService.lookup(ev.getEventType()).orElse(null);
            try {
                String text = documentText(inc, ev, mp, rep.getClassification());
                upsert(inc.getIncidentId(), text, embed(text, "document"));
                indexed++;
            } catch (Exception e) {
                failed++;
                lastError = brief(e);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("indexed", indexed);
        out.put("failed", failed);
        out.put("skippedNoReport", skipped);
        out.put("lastError", lastError);
        return out;
    }

    private static String brief(Exception e) {
        String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        return m.length() > 220 ? m.substring(0, 220) + "..." : m;
    }
}
