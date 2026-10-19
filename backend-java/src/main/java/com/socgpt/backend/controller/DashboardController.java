package com.socgpt.backend.controller;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.RemediationPlan;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.pdf.ReportPdfService;
import com.socgpt.backend.repository.AuditLogRepository;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.RemediationPlanRepository;
import com.socgpt.backend.repository.SecurityEventRepository;
import com.socgpt.backend.security.AuthInterceptor;
import com.socgpt.backend.security.AuthUser;
import com.socgpt.backend.security.RequiresRole;
import com.socgpt.backend.service.AgentClientService;
import com.socgpt.backend.service.AuditService;
import com.socgpt.backend.service.DetectionService;
import com.socgpt.backend.service.IncidentViewService;
import com.socgpt.backend.service.MetricsService;
import com.socgpt.backend.service.MitreMappingService;
import com.socgpt.backend.service.RagService;

/**
 * JSON API that powers the dashboard pages (index.html, incidents.html, audit.html).
 * Reading is open to any signed-in user; the actions (simulate, re-analyse, re-index) are role-gated.
 */
@RestController
@RequestMapping("/api")
public class DashboardController {

    private static final List<String> STATUSES =
        List.of("OPEN", "INVESTIGATING", "AWAITING_APPROVAL", "REMEDIATED", "CLOSED");
    private static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");
    private static final List<String> CSF_FUNCTIONS =
        List.of("Govern", "Identify", "Protect", "Detect", "Respond", "Recover");

    private static final List<String> FAKE_IPS = List.of(
        "203.0.113.45", "198.51.100.23", "192.0.2.77", "185.220.101.9", "172.16.4.21", "10.0.0.99");
    private static final Pattern IP = Pattern.compile("[0-9A-Fa-f:.]{3,45}");

    // how many raw events one "simulate" click sends for each attack type
    private static final Map<String, Integer> BURST_SIZE =
        Map.of("sqli", 1, "malware", 1, "brute_force", 3, "port_scan", 5);

    private final IncidentRepository incidentRepository;
    private final SecurityEventRepository eventRepository;
    private final RemediationPlanRepository planRepository;
    private final AuditLogRepository auditLogRepository;
    private final MitreMappingService mappingService;
    private final DetectionService detectionService;
    private final AgentClientService agentClientService;
    private final IncidentViewService views;
    private final MetricsService metrics;
    private final RagService ragService;
    private final ReportPdfService pdfService;
    private final AuditService auditService;

    public DashboardController(IncidentRepository incidentRepository,
                               SecurityEventRepository eventRepository,
                               RemediationPlanRepository planRepository,
                               AuditLogRepository auditLogRepository,
                               MitreMappingService mappingService,
                               DetectionService detectionService,
                               AgentClientService agentClientService,
                               IncidentViewService views,
                               MetricsService metrics,
                               RagService ragService,
                               ReportPdfService pdfService,
                               AuditService auditService) {
        this.incidentRepository = incidentRepository;
        this.eventRepository = eventRepository;
        this.planRepository = planRepository;
        this.auditLogRepository = auditLogRepository;
        this.mappingService = mappingService;
        this.detectionService = detectionService;
        this.agentClientService = agentClientService;
        this.views = views;
        this.metrics = metrics;
        this.ragService = ragService;
        this.pdfService = pdfService;
        this.auditService = auditService;
    }

    // ------------------------------------------------------------------
    // Dashboard numbers
    // ------------------------------------------------------------------

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        List<Incident> incidents = incidentRepository.findAll();
        Map<Integer, SecurityEvent> events = views.eventsById();
        Map<Integer, Incident> incidentsById = new HashMap<>();
        for (Incident i : incidents) {
            incidentsById.put(i.getIncidentId(), i);
        }

        Map<String, Integer> byStatus = zeroed(STATUSES);
        Map<String, Integer> bySeverity = zeroed(SEVERITIES);
        Map<String, Integer> byCsf = zeroed(CSF_FUNCTIONS);
        Map<String, Integer> byTactic = new HashMap<>();
        double riskSum = 0;
        int riskCount = 0;

        for (Incident i : incidents) {
            if (i.getStatus() != null) {
                byStatus.merge(i.getStatus(), 1, Integer::sum);
            }
            if (i.getSeverity() != null) {
                bySeverity.merge(i.getSeverity(), 1, Integer::sum);
            }
            if (i.getRiskScore() != null) {
                riskSum += i.getRiskScore();
                riskCount++;
            }
            SecurityEvent e = i.getEventId() == null ? null : events.get(i.getEventId());
            Optional<MitreMappingService.Mapping> mapping =
                e == null ? Optional.empty() : mappingService.lookup(e.getEventType());
            mapping.ifPresent(m -> byTactic.merge(m.tactic(), 1, Integer::sum));

            String csf = i.getCsfFunction() != null
                ? i.getCsfFunction()
                : mapping.map(MitreMappingService.Mapping::csfFunction).orElse(null);
            if (csf != null) {
                byCsf.merge(csf, 1, Integer::sum);
            }
        }

        // Average time from "incident detected" to "a human approved the plan"
        long totalSeconds = 0;
        int approvedCount = 0;
        for (RemediationPlan p : planRepository.findAll()) {
            Incident inc = p.getIncidentId() == null ? null : incidentsById.get(p.getIncidentId());
            if (p.getApprovedAt() != null && inc != null && inc.getCreatedAt() != null) {
                long seconds = Duration.between(inc.getCreatedAt(), p.getApprovedAt()).getSeconds();
                if (seconds >= 0) {
                    totalSeconds += seconds;
                    approvedCount++;
                }
            }
        }

        // Incidents per hour for the last 12 hours (oldest first)
        LocalDateTime thisHour = LocalDateTime.now().truncatedTo(ChronoUnit.HOURS);
        List<Map<String, Object>> hourly = new ArrayList<>();
        for (int back = 11; back >= 0; back--) {
            LocalDateTime start = thisHour.minusHours(back);
            LocalDateTime end = start.plusHours(1);
            int count = 0;
            for (Incident i : incidents) {
                LocalDateTime t = i.getCreatedAt();
                if (t != null && !t.isBefore(start) && t.isBefore(end)) {
                    count++;
                }
            }
            Map<String, Object> bucket = new LinkedHashMap<>();
            bucket.put("hour", String.format("%02d:00", start.getHour()));
            bucket.put("count", count);
            hourly.add(bucket);
        }

        Map<String, Integer> tacticsSorted = byTactic.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (a, b) -> a, LinkedHashMap::new));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("totalIncidents", incidents.size());
        out.put("totalEvents", eventRepository.count());
        out.put("awaitingApproval", byStatus.getOrDefault("AWAITING_APPROVAL", 0));
        out.put("openIncidents", byStatus.getOrDefault("OPEN", 0));
        out.put("closedIncidents", byStatus.getOrDefault("CLOSED", 0));
        out.put("criticalCount", bySeverity.getOrDefault("CRITICAL", 0));
        out.put("avgRisk", riskCount == 0 ? 0.0 : riskSum / riskCount);
        out.put("avgTimeToApproveSeconds", approvedCount == 0 ? null : (Object) (totalSeconds / approvedCount));
        out.put("byStatus", byStatus);
        out.put("bySeverity", bySeverity);
        out.put("byTactic", tacticsSorted);
        out.put("byCsf", byCsf);
        out.put("hourly", hourly);
        out.putAll(metrics.compute(incidents, events));
        return out;
    }

    // ------------------------------------------------------------------
    // Incident list + detail
    // ------------------------------------------------------------------

    @GetMapping("/incidents")
    public List<Map<String, Object>> incidents() {
        return views.list();
    }

    @GetMapping("/incidents/{id}")
    public Map<String, Object> incidentDetail(@PathVariable Integer id,
                                              @RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser user) {
        return views.detail(id, user);
    }

    /** The raw sensor events, newest first, for the live stream on the Command Center. */
    @GetMapping("/events/recent")
    public List<Map<String, Object>> recentEvents() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (SecurityEvent e : eventRepository.findTop25ByOrderByEventIdDesc()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("eventId", e.getEventId());
            m.put("sourceIp", e.getSourceIp());
            m.put("eventType", e.getEventType());
            m.put("mitreId", e.getMitreId());
            m.put("tactic", mappingService.lookup(e.getEventType()).map(MitreMappingService.Mapping::tactic).orElse(null));
            m.put("detectedAt", e.getDetectedAt());
            out.add(m);
        }
        return out;
    }

    @GetMapping("/chains")
    public List<Map<String, Object>> chains() {
        return views.chains();
    }

    /** One-incident PDF report, built on the fly. */
    @GetMapping("/incidents/{id}/report.pdf")
    public ResponseEntity<byte[]> reportPdf(@PathVariable Integer id,
                                            @RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser user) {
        byte[] pdf = pdfService.build(id, user.username());
        auditService.log(user.userId(), "EXPORT_REPORT_PDF", "incident", id, "Exported the PDF report of incident " + id);
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_PDF)
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"incident-" + id + "-report.pdf\"")
            .header(HttpHeaders.CACHE_CONTROL, "no-store")
            .body(pdf);
    }

    /** Re-run the AI analysis for an incident that is back to OPEN (after a rejection or an AI failure). */
    @PostMapping("/incidents/{id}/reinvestigate")
    @RequiresRole({"analyst", "soc_manager"})
    public Map<String, Object> reinvestigate(@PathVariable Integer id,
                                             @RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser user) {
        Incident incident = incidentRepository.findById(id).orElseThrow(() ->
            new ResponseStatusException(HttpStatus.NOT_FOUND, "Incident " + id + " not found"));
        if (!"OPEN".equals(incident.getStatus())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                "Incident " + id + " is " + incident.getStatus() + "; only OPEN incidents can be re-analysed");
        }
        SecurityEvent event = incident.getEventId() == null
            ? null : eventRepository.findById(incident.getEventId()).orElse(null);
        MitreMappingService.Mapping mapping = event == null
            ? null : mappingService.lookup(event.getEventType()).orElse(null);
        Map<String, Object> chainContext = incident.getChainId() == null ? null
            : views.chainContext(incident.getChainId());

        if (!agentClientService.requestInvestigation(incident, event, mapping, chainContext)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "The AI is already analysing incident " + id);
        }
        auditService.log(user.userId(), "REINVESTIGATE", "incident", id, "Asked the AI to re-analyse incident " + id);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("message", "AI re-analysis started for incident " + id);
        return out;
    }

    // ------------------------------------------------------------------
    // Attack lab: fire a simulated attack straight from the UI
    // ------------------------------------------------------------------

    /** @param ip optional source IP, so a multi-stage campaign can reuse one attacker */
    @PostMapping("/simulate")
    @RequiresRole({"analyst", "soc_manager"})
    public Map<String, Object> simulate(@RequestParam String type,
                                        @RequestParam(required = false) String ip,
                                        @RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser user) {
        Integer burst = BURST_SIZE.get(type);
        MitreMappingService.Mapping mapping = mappingService.lookup(type).orElse(null);
        if (burst == null || mapping == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Unknown attack type '" + type + "'. Use one of: " + BURST_SIZE.keySet());
        }
        if (ip != null && !ip.isBlank() && !IP.matcher(ip.trim()).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "That does not look like an IP address.");
        }

        String sourceIp = ip == null || ip.isBlank()
            ? FAKE_IPS.get(ThreadLocalRandom.current().nextInt(FAKE_IPS.size())) : ip.trim();
        List<Integer> raised = new ArrayList<>();
        for (int n = 0; n < burst; n++) {
            SecurityEvent event = new SecurityEvent();
            event.setSourceIp(sourceIp);
            event.setEventType(type);
            event.setMitreId(mapping.mitreId());
            SecurityEvent saved = eventRepository.save(event);
            detectionService.evaluate(saved).ifPresent(i -> raised.add(i.getIncidentId()));   // same real-time path as POST /events
        }
        auditService.log(user.userId(), "SIMULATE_ATTACK", "attack_simulation", null,
            "Simulated " + type + " from " + sourceIp + " (" + burst + " event" + (burst == 1 ? "" : "s") + ")"
                + (raised.isEmpty() ? "" : "; raised incident #" + raised.get(0)));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("type", type);
        out.put("sourceIp", sourceIp);
        out.put("eventsSent", burst);
        out.put("incidentIds", raised);
        return out;
    }

    // ------------------------------------------------------------------
    // Audit trail
    // ------------------------------------------------------------------

    @GetMapping("/audit")
    public List<Map<String, Object>> audit() {
        Map<Integer, String> names = views.usernamesById();
        return auditLogRepository.findTop500ByOrderByLogIdDesc().stream()
            .map(a -> views.auditView(a, names))
            .collect(Collectors.toList());
    }

    // ------------------------------------------------------------------
    // RAG maintenance
    // ------------------------------------------------------------------

    /** Embeds every investigated incident (needed once for old data, and after changing the embedding model). */
    @PostMapping("/rag/reindex")
    @RequiresRole("admin")
    public Map<String, Object> reindex(@RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser user) {
        Map<String, Object> result = ragService.reindexAll();
        auditService.log(user.userId(), "RAG_REINDEX", "rag", null,
            "Re-indexed past incidents: " + result.get("indexed") + " indexed, " + result.get("failed") + " failed");
        return result;
    }

    // ------------------------------------------------------------------

    private static Map<String, Integer> zeroed(List<String> keys) {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (String k : keys) {
            m.put(k, 0);
        }
        return m;
    }
}
