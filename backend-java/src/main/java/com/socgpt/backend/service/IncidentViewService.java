package com.socgpt.backend.service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.socgpt.backend.model.AuditLog;
import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.IncidentChain;
import com.socgpt.backend.model.InvestigationReport;
import com.socgpt.backend.model.Notification;
import com.socgpt.backend.model.RemediationPlan;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.model.User;
import com.socgpt.backend.repository.AuditLogRepository;
import com.socgpt.backend.repository.IncidentChainRepository;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.InvestigationReportRepository;
import com.socgpt.backend.repository.NotificationRepository;
import com.socgpt.backend.repository.RemediationPlanRepository;
import com.socgpt.backend.repository.SecurityEventRepository;
import com.socgpt.backend.repository.UserRepository;
import com.socgpt.backend.security.AccessPolicy;
import com.socgpt.backend.security.AuthUser;

/** Builds the JSON shapes the dashboard pages consume (and the PDF/e-mail code reuses). */
@Service
public class IncidentViewService {

    private final IncidentRepository incidentRepository;
    private final SecurityEventRepository eventRepository;
    private final InvestigationReportRepository reportRepository;
    private final RemediationPlanRepository planRepository;
    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;
    private final IncidentChainRepository chainRepository;
    private final NotificationRepository notificationRepository;
    private final MitreMappingService mappingService;
    private final ChainService chainService;
    private final RagService ragService;
    private final AgentClientService agentClientService;

    public IncidentViewService(IncidentRepository incidentRepository, SecurityEventRepository eventRepository,
                               InvestigationReportRepository reportRepository, RemediationPlanRepository planRepository,
                               AuditLogRepository auditLogRepository, UserRepository userRepository,
                               IncidentChainRepository chainRepository, NotificationRepository notificationRepository,
                               MitreMappingService mappingService, ChainService chainService,
                               RagService ragService, AgentClientService agentClientService) {
        this.incidentRepository = incidentRepository;
        this.eventRepository = eventRepository;
        this.reportRepository = reportRepository;
        this.planRepository = planRepository;
        this.auditLogRepository = auditLogRepository;
        this.userRepository = userRepository;
        this.chainRepository = chainRepository;
        this.notificationRepository = notificationRepository;
        this.mappingService = mappingService;
        this.chainService = chainService;
        this.ragService = ragService;
        this.agentClientService = agentClientService;
    }

    // ------------------------------------------------------------------ list

    public List<Map<String, Object>> list() {
        Map<Integer, SecurityEvent> events = eventsById();
        Map<Integer, RemediationPlan> plans = new HashMap<>();
        planRepository.findAll().stream().filter(p -> p.getIncidentId() != null)
            .sorted(Comparator.comparing(RemediationPlan::getPlanId))
            .forEach(p -> plans.put(p.getIncidentId(), p));     // newer plans overwrite older ones
        Map<Integer, InvestigationReport> reports = new HashMap<>();
        reportRepository.findAll().stream().filter(r -> r.getIncidentId() != null)
            .sorted(Comparator.comparing(InvestigationReport::getReportId))
            .forEach(r -> reports.put(r.getIncidentId(), r));

        return incidentRepository.findAll().stream()
            .sorted(Comparator.comparing(Incident::getIncidentId, Comparator.reverseOrder()))
            .limit(300)
            .map(i -> row(i, i.getEventId() == null ? null : events.get(i.getEventId()),
                plans.get(i.getIncidentId()), reports.get(i.getIncidentId())))
            .collect(Collectors.toList());
    }

    // ------------------------------------------------------------------ detail

    public Map<String, Object> detail(Integer id, AuthUser viewer) {
        Incident incident = incidentRepository.findById(id).orElseThrow(() ->
            new ResponseStatusException(HttpStatus.NOT_FOUND, "Incident " + id + " not found"));
        SecurityEvent event = incident.getEventId() == null
            ? null : eventRepository.findById(incident.getEventId()).orElse(null);
        List<RemediationPlan> myPlans = planRepository.findByIncidentIdOrderByPlanIdAsc(id);
        RemediationPlan plan = myPlans.isEmpty() ? null : myPlans.get(myPlans.size() - 1);
        InvestigationReport report = reportRepository.findFirstByIncidentIdOrderByReportIdDesc(id).orElse(null);
        Map<Integer, String> names = usernamesById();

        Map<String, Object> incidentMap = row(incident, event, plan, report);
        incidentMap.put("riskFactors", incident.getRiskFactors());      // JSON text; the browser parses it

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("incident", incidentMap);
        out.put("mapping", event == null ? null : mappingView(event.getEventType()));
        out.put("report", report == null ? null : reportView(report));
        out.put("plan", plan == null ? null : planView(plan, names));

        Set<Integer> planIds = myPlans.stream().map(RemediationPlan::getPlanId).collect(Collectors.toSet());
        List<AuditLog> audit = new ArrayList<>();
        if (!planIds.isEmpty()) {
            audit.addAll(auditLogRepository.findByTargetTypeAndTargetIdInOrderByLogIdAsc("remediation_plan", planIds));
        }
        audit.addAll(auditLogRepository.findByTargetTypeAndTargetIdInOrderByLogIdAsc("incident", Set.of(id)));
        audit.sort(Comparator.comparing(AuditLog::getLogId));
        out.put("audit", audit.stream().map(a -> auditView(a, names)).collect(Collectors.toList()));

        out.put("notifications", notificationRepository.findByIncidentIdOrderByNotificationIdAsc(id).stream()
            .map(this::notificationView).collect(Collectors.toList()));

        IncidentChain chain = incident.getChainId() == null ? null : chainRepository.findById(incident.getChainId()).orElse(null);
        out.put("chain", chain == null ? null : chainView(chain));
        out.put("similar", ragService.similarForView(id));

        boolean busy = agentClientService.isInFlight(id);
        Map<String, Object> ai = new LinkedHashMap<>();
        ai.put("inFlight", busy);
        ai.put("error", busy ? null : agentClientService.lastError(id));
        out.put("ai", ai);

        AccessPolicy.Decision decide = AccessPolicy.canDecide(viewer, incident.getSeverity());
        AccessPolicy.Decision exec = AccessPolicy.canExecute(viewer);
        Map<String, Object> perms = new LinkedHashMap<>();
        perms.put("canDecide", decide.allowed());
        perms.put("decideReason", decide.reason());
        perms.put("canExecute", exec.allowed());
        perms.put("executeReason", exec.reason());
        perms.put("canReinvestigate", viewer != null && viewer.hasAnyRole("analyst", "soc_manager"));
        out.put("permissions", perms);
        return out;
    }

    // ------------------------------------------------------------------ chains

    public List<Map<String, Object>> chains() {
        return chainRepository.findAll().stream()
            .sorted(Comparator.comparing(IncidentChain::getChainId, Comparator.reverseOrder()))
            .limit(50)
            .map(this::chainView)
            .collect(Collectors.toList());
    }

    /** The chain description sent to the AI for an incident that belongs to a chain. */
    public Map<String, Object> chainContext(Integer chainId) {
        return chainRepository.findById(chainId).map(chainService::contextFor).orElse(null);
    }

    public Map<String, Object> chainView(IncidentChain c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("chainId", c.getChainId());
        m.put("sourceIp", c.getSourceIp());
        m.put("description", c.getDescription());
        m.put("stages", c.getStages());
        m.put("overallRisk", c.getOverallRisk());
        m.put("status", c.getStatus());
        m.put("createdAt", c.getCreatedAt());
        m.put("updatedAt", c.getUpdatedAt());
        Map<Integer, Incident> byId = new HashMap<>();
        incidentRepository.findByChainIdOrderByIncidentIdAsc(c.getChainId()).forEach(i -> byId.put(i.getIncidentId(), i));
        List<Map<String, Object>> members = new ArrayList<>();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> ctx = (List<Map<String, Object>>) chainService.contextFor(c).get("stages");
        for (Map<String, Object> s : ctx) {
            Map<String, Object> mem = new LinkedHashMap<>(s);
            Incident inc = byId.get((Integer) s.get("incidentId"));
            mem.put("status", inc == null ? null : inc.getStatus());
            members.add(mem);
        }
        m.put("members", members);
        return m;
    }

    // ------------------------------------------------------------------ small views

    public Map<String, Object> row(Incident i, SecurityEvent e, RemediationPlan plan, InvestigationReport report) {
        Optional<MitreMappingService.Mapping> mapping =
            e == null ? Optional.empty() : mappingService.lookup(e.getEventType());

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("incidentId", i.getIncidentId());
        m.put("createdAt", i.getCreatedAt());
        m.put("severity", i.getSeverity());
        m.put("riskScore", i.getRiskScore());
        m.put("status", i.getStatus());
        m.put("csfFunction", i.getCsfFunction() != null
            ? i.getCsfFunction()
            : mapping.map(MitreMappingService.Mapping::csfFunction).orElse(null));
        m.put("chainId", i.getChainId());
        m.put("eventId", i.getEventId());
        m.put("eventType", e == null ? null : e.getEventType());
        m.put("sourceIp", e == null ? null : e.getSourceIp());
        m.put("detectedAt", e == null ? null : e.getDetectedAt());
        m.put("mitreId", mapping.map(MitreMappingService.Mapping::mitreId)
            .orElse(e == null ? null : e.getMitreId()));
        m.put("techniqueName", mapping.map(MitreMappingService.Mapping::techniqueName).orElse(null));
        m.put("tactic", mapping.map(MitreMappingService.Mapping::tactic).orElse(null));
        m.put("planId", plan == null ? null : plan.getPlanId());
        m.put("planStatus", plan == null ? null : plan.getStatus());
        m.put("classification", report == null ? null : report.getClassification());
        m.put("confidence", report == null ? null : report.getConfidence());
        return m;
    }

    public Map<String, Object> mappingView(String eventType) {
        return mappingService.lookup(eventType).map(x -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("mitreId", x.mitreId());
            m.put("techniqueName", x.techniqueName());
            m.put("tactic", x.tactic());
            m.put("csfFunction", x.csfFunction());
            m.put("csfDescription", x.csfDescription());
            return m;
        }).orElse(null);
    }

    private Map<String, Object> reportView(InvestigationReport r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("reportId", r.getReportId());
        m.put("summary", r.getSummary());
        m.put("classification", r.getClassification());
        m.put("confidence", r.getConfidence());
        m.put("impact", r.getImpact());
        m.put("evidence", r.getEvidence());          // JSON text; the browser parses it
        m.put("generatedAt", r.getGeneratedAt());
        return m;
    }

    private Map<String, Object> planView(RemediationPlan p, Map<Integer, String> names) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("planId", p.getPlanId());
        m.put("status", p.getStatus());
        m.put("steps", p.getSteps());                // JSON text; the browser parses it
        m.put("approvedBy", p.getApprovedBy());
        m.put("approvedByName", p.getApprovedBy() == null ? null : names.get(p.getApprovedBy()));
        m.put("approvedAt", p.getApprovedAt());
        m.put("createdAt", p.getCreatedAt());
        return m;
    }

    public Map<String, Object> auditView(AuditLog a, Map<Integer, String> names) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("logId", a.getLogId());
        m.put("userId", a.getUserId());
        m.put("username", a.getUserId() == null ? null : names.get(a.getUserId()));
        m.put("action", a.getAction());
        m.put("targetType", a.getTargetType());
        m.put("targetId", a.getTargetId());
        m.put("details", a.getDetails());
        m.put("createdAt", a.getCreatedAt());
        return m;
    }

    private Map<String, Object> notificationView(Notification n) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("notificationId", n.getNotificationId());
        m.put("channel", n.getChannel());
        m.put("recipient", n.getRecipient());
        m.put("subject", n.getSubject());
        m.put("status", n.getStatus());
        m.put("error", n.getError());
        m.put("sentAt", n.getSentAt());
        m.put("createdAt", n.getCreatedAt());
        return m;
    }

    public Map<Integer, SecurityEvent> eventsById() {
        Map<Integer, SecurityEvent> m = new HashMap<>();
        for (SecurityEvent e : eventRepository.findAll()) {
            m.put(e.getEventId(), e);
        }
        return m;
    }

    public Map<Integer, String> usernamesById() {
        Map<Integer, String> m = new HashMap<>();
        for (User u : userRepository.findAll()) {
            m.put(u.getUserId(), u.getUsername());
        }
        return m;
    }
}
