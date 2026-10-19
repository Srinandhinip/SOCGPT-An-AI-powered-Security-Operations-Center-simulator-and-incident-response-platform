package com.socgpt.backend.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.SecurityEventRepository;

/**
 * The real-time detection engine. Rules decide WHETHER something is an incident and give a
 * baseline; {@link RiskScoringService} adds context; {@link ChainService} links multi-stage
 * attacks; the AI agent is then asked to investigate (in the background).
 */
@Service
public class DetectionService {

    private final SecurityEventRepository eventRepository;
    private final IncidentRepository incidentRepository;
    private final AgentClientService agentClientService;
    private final MitreMappingService mappingService;
    private final RiskScoringService riskScoringService;
    private final ChainService chainService;
    private final NotificationService notificationService;

    public DetectionService(SecurityEventRepository eventRepository,
                            IncidentRepository incidentRepository,
                            AgentClientService agentClientService,
                            MitreMappingService mappingService,
                            RiskScoringService riskScoringService,
                            ChainService chainService,
                            NotificationService notificationService) {
        this.eventRepository = eventRepository;
        this.incidentRepository = incidentRepository;
        this.agentClientService = agentClientService;
        this.mappingService = mappingService;
        this.riskScoringService = riskScoringService;
        this.chainService = chainService;
        this.notificationService = notificationService;
    }

    /** Runs the rules for a freshly saved event. Returns the incident if one was raised. */
    public Optional<Incident> evaluate(SecurityEvent newEvent) {
        if (newEvent == null || newEvent.getEventType() == null) {
            return Optional.empty();
        }
        // remember where this event sits along the kill chain
        mappingService.lookup(newEvent.getEventType()).ifPresent(m -> {
            Integer order = ChainService.stageOrderFor(m.tactic());
            if (order != null && !order.equals(newEvent.getStageOrder())) {
                newEvent.setStageOrder(order);
                eventRepository.save(newEvent);
            }
        });

        return switch (newEvent.getEventType()) {
            case "brute_force" -> checkThreshold(newEvent, 3, 5, "HIGH", 70);
            case "port_scan"   -> checkThreshold(newEvent, 5, 2, "MEDIUM", 50);
            case "sqli"        -> createIncident(newEvent, "CRITICAL", 90, 1, 0);
            case "malware"     -> createIncident(newEvent, "CRITICAL", 95, 1, 0);
            default            -> Optional.empty();   // no detection rule for this event type yet
        };
    }

    private Optional<Incident> checkThreshold(SecurityEvent newEvent, int threshold, int windowMinutes,
                                              String severity, int baseline) {
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(windowMinutes);

        List<SecurityEvent> recentMatches = eventRepository
            .findBySourceIpAndEventTypeAndDetectedAtAfter(newEvent.getSourceIp(), newEvent.getEventType(), windowStart);
        if (recentMatches.size() < threshold) {
            return Optional.empty();
        }

        // one incident per burst: if this IP/attack already raised one inside the window, do not
        // raise (and pay the AI for) another incident for every additional event
        Set<Integer> ids = recentMatches.stream().map(SecurityEvent::getEventId).collect(Collectors.toSet());
        boolean alreadyRaised = incidentRepository.findByEventIdIn(ids).stream()
            .anyMatch(i -> i.getCreatedAt() != null && i.getCreatedAt().isAfter(windowStart));
        if (alreadyRaised) {
            return Optional.empty();
        }
        return createIncident(newEvent, severity, baseline, recentMatches.size(), threshold);
    }

    private Optional<Incident> createIncident(SecurityEvent event, String ruleSeverity, int baseline,
                                              int eventsInWindow, int threshold) {
        Optional<MitreMappingService.Mapping> mapping = mappingService.lookup(event.getEventType());
        MitreMappingService.Mapping m = mapping.orElse(null);

        ChainService.Preview preview = chainService.preview(event, m);
        RiskScoringService.Result risk = riskScoringService.score(
            event, ruleSeverity, baseline, eventsInWindow, threshold, preview.stageCount());

        Incident incident = new Incident();
        incident.setEventId(event.getEventId());
        incident.setSeverity(risk.severity());
        incident.setRiskScore(risk.score());
        incident.setRiskFactors(risk.factorsJson());
        incident.setStatus("OPEN");
        mapping.ifPresent(x -> incident.setCsfFunction(x.csfFunction()));
        Incident saved = incidentRepository.save(incident);

        ChainService.Linked linked = chainService.link(saved, event, m, preview);
        if (linked != null) {
            // the chain may have raised the overall picture; keep the saved row in sync
            saved = incidentRepository.findById(saved.getIncidentId()).orElse(saved);
        }

        System.out.println("[DETECTION] Incident #" + saved.getIncidentId() + " created: " + saved.getSeverity()
            + " risk " + saved.getRiskScore() + " (" + event.getEventType() + " from " + event.getSourceIp() + ") -> "
            + mapping.map(x -> x.mitreId() + " " + x.techniqueName() + " / CSF: " + x.csfFunction()).orElse("unmapped")
            + (linked != null ? " | chain #" + linked.chain().getChainId() : ""));

        java.util.Map<String, Object> chainContext = linked == null ? null : chainService.contextFor(linked.chain());
        if (linked != null && linked.grew()) {
            notificationService.chainAlertAsync(linked.chain(), saved, chainContext);
        }

        // hand the incident to the AI agent right away (runs in the background)
        agentClientService.requestInvestigation(saved, event, m, chainContext);
        return Optional.of(saved);
    }
}
