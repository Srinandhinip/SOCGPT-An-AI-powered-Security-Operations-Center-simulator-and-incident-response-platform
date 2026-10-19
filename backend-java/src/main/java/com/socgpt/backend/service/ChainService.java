package com.socgpt.backend.service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.IncidentChain;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.repository.IncidentChainRepository;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.SecurityEventRepository;

/**
 * Detects multi-stage attacks: the same source IP showing up in two or more different
 * MITRE tactics (for example reconnaissance, then credential access, then initial access)
 * inside a time window. Raw events alone never form a chain; at least one earlier
 * incident from that IP is required.
 */
@Service
public class ChainService {

    /** Position of each tactic along the kill chain (used for security_events.stage_order). */
    private static final Map<String, Integer> TACTIC_RANK = Map.of(
        "Reconnaissance", 1,
        "Initial Access", 3,
        "Execution", 4,
        "Credential Access", 8
    );

    public record Preview(List<Incident> related, List<String> tactics, int stageCount) {
        public boolean isChain() {
            return stageCount >= 2;
        }
    }

    public record Linked(IncidentChain chain, boolean created, boolean grew) { }

    private final SecurityEventRepository eventRepository;
    private final IncidentRepository incidentRepository;
    private final IncidentChainRepository chainRepository;
    private final MitreMappingService mappingService;
    private final long windowMinutes;

    public ChainService(SecurityEventRepository eventRepository,
                        IncidentRepository incidentRepository,
                        IncidentChainRepository chainRepository,
                        MitreMappingService mappingService,
                        @Value("${socgpt.chain.window-minutes:30}") long windowMinutes) {
        this.eventRepository = eventRepository;
        this.incidentRepository = incidentRepository;
        this.chainRepository = chainRepository;
        this.mappingService = mappingService;
        this.windowMinutes = windowMinutes;
    }

    public static Integer stageOrderFor(String tactic) {
        return tactic == null ? null : TACTIC_RANK.get(tactic);
    }

    /** Looks at the incidents already raised for this IP, without saving anything. */
    public Preview preview(SecurityEvent event, MitreMappingService.Mapping mapping) {
        List<String> tactics = new ArrayList<>();
        List<Incident> related = new ArrayList<>();
        if (event.getSourceIp() != null) {
            LocalDateTime cutoff = LocalDateTime.now().minusMinutes(windowMinutes);
            Map<Integer, SecurityEvent> events = new HashMap<>();
            for (SecurityEvent e : eventRepository.findBySourceIpAndDetectedAtAfter(event.getSourceIp(), cutoff)) {
                if (e.getEventId() != null && !e.getEventId().equals(event.getEventId())) {
                    events.put(e.getEventId(), e);
                }
            }
            if (!events.isEmpty()) {
                related.addAll(incidentRepository.findByEventIdIn(events.keySet()));
                related.sort(Comparator.comparing((Incident i) -> events.get(i.getEventId()).getDetectedAt())
                    .thenComparing(Incident::getIncidentId));
                for (Incident i : related) {
                    String tactic = tacticOf(events.get(i.getEventId()));
                    if (tactic != null && !tactics.contains(tactic)) {
                        tactics.add(tactic);
                    }
                }
            }
        }
        if (mapping != null && !tactics.contains(mapping.tactic())) {
            tactics.add(mapping.tactic());
        }
        return new Preview(related, tactics, related.isEmpty() ? 1 : tactics.size());
    }

    /** Attaches the new incident (and the related ones) to a chain when the preview found one. */
    public Linked link(Incident incident, SecurityEvent event, MitreMappingService.Mapping mapping, Preview preview) {
        if (preview == null || !preview.isChain()) {
            return null;
        }

        // reuse the chain the related incidents already belong to (lowest id wins), else make one
        Set<Integer> chainIds = new LinkedHashSet<>();
        preview.related().stream().map(Incident::getChainId).filter(c -> c != null).sorted().forEach(chainIds::add);
        IncidentChain chain;
        boolean created = chainIds.isEmpty();
        int previousStages = 0;
        if (created) {
            chain = new IncidentChain();
            chain.setSourceIp(event.getSourceIp());
            chain.setStatus("ACTIVE");
        } else {
            chain = chainRepository.findById(chainIds.iterator().next()).orElseGet(IncidentChain::new);
            if (chain.getChainId() == null) {
                created = true;
                chain.setSourceIp(event.getSourceIp());
                chain.setStatus("ACTIVE");
            } else {
                previousStages = chain.getStages() == null ? 0 : chain.getStages();
            }
        }

        // every member: related incidents + anything already in the chain(s) + the new incident
        Map<Integer, Incident> members = new TreeMap<>();
        preview.related().forEach(i -> members.put(i.getIncidentId(), i));
        for (Integer cid : chainIds) {
            incidentRepository.findByChainIdOrderByIncidentIdAsc(cid).forEach(i -> members.put(i.getIncidentId(), i));
        }
        members.put(incident.getIncidentId(), incident);

        Map<Integer, SecurityEvent> events = new HashMap<>();
        events.put(event.getEventId(), event);
        List<Integer> missing = new ArrayList<>();
        for (Incident m : members.values()) {
            if (m.getEventId() != null && !events.containsKey(m.getEventId())) {
                missing.add(m.getEventId());
            }
        }
        eventRepository.findAllById(missing).forEach(e -> events.put(e.getEventId(), e));

        List<Incident> ordered = new ArrayList<>(members.values());
        ordered.sort(Comparator.comparing((Incident i) -> timeOf(events.get(i.getEventId())))
            .thenComparing(Incident::getIncidentId));

        List<String> tactics = new ArrayList<>();
        int risk = 0;
        LocalDateTime first = null, last = null;
        for (Incident m : ordered) {
            SecurityEvent e = events.get(m.getEventId());
            String tactic = tacticOf(e);
            if (tactic != null && !tactics.contains(tactic)) {
                tactics.add(tactic);
            }
            risk = Math.max(risk, m.getRiskScore() == null ? 0 : m.getRiskScore());
            LocalDateTime t = timeOf(e);
            if (first == null || t.isBefore(first)) {
                first = t;
            }
            if (last == null || t.isAfter(last)) {
                last = t;
            }
        }

        chain.setStages(Math.max(tactics.size(), 2));
        chain.setOverallRisk(Math.min(100, risk));
        chain.setDescription(String.join(" → ", tactics) + " from " + chain.getSourceIp()
            + " over " + minutesLabel(first, last));
        IncidentChain saved = chainRepository.save(chain);

        for (Incident m : ordered) {
            if (!saved.getChainId().equals(m.getChainId())) {
                m.setChainId(saved.getChainId());
                incidentRepository.save(m);
            }
        }
        // any other chain that got absorbed is closed out
        for (Integer cid : chainIds) {
            if (!cid.equals(saved.getChainId())) {
                chainRepository.findById(cid).ifPresent(old -> {
                    old.setStatus("RESOLVED");
                    old.setDescription("Merged into chain #" + saved.getChainId());
                    chainRepository.save(old);
                });
            }
        }

        boolean grew = created || saved.getStages() > previousStages;
        return new Linked(saved, created, grew);
    }

    /** Everything the AI (and the UI) needs to describe one chain. */
    public Map<String, Object> contextFor(IncidentChain chain) {
        List<Incident> members = incidentRepository.findByChainIdOrderByIncidentIdAsc(chain.getChainId());
        Map<Integer, SecurityEvent> events = new HashMap<>();
        eventRepository.findAllById(members.stream().map(Incident::getEventId).filter(e -> e != null).toList())
            .forEach(e -> events.put(e.getEventId(), e));
        members.sort(Comparator.comparing((Incident i) -> timeOf(events.get(i.getEventId())))
            .thenComparing(Incident::getIncidentId));

        List<Map<String, Object>> stages = new ArrayList<>();
        for (Incident m : members) {
            SecurityEvent e = events.get(m.getEventId());
            MitreMappingService.Mapping mp = e == null ? null : mappingService.lookup(e.getEventType()).orElse(null);
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("incidentId", m.getIncidentId());
            s.put("tactic", mp == null ? null : mp.tactic());
            s.put("eventType", e == null ? null : e.getEventType());
            s.put("mitreId", mp == null ? null : mp.mitreId());
            s.put("detectedAt", e == null || e.getDetectedAt() == null ? null : e.getDetectedAt().toString());
            s.put("severity", m.getSeverity());
            s.put("riskScore", m.getRiskScore());
            stages.add(s);
        }
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("chainId", chain.getChainId());
        ctx.put("stageCount", chain.getStages());
        ctx.put("sourceIp", chain.getSourceIp());
        ctx.put("stages", stages);
        return ctx;
    }

    private String tacticOf(SecurityEvent e) {
        if (e == null) {
            return null;
        }
        return mappingService.lookup(e.getEventType()).map(MitreMappingService.Mapping::tactic).orElse(null);
    }

    private static LocalDateTime timeOf(SecurityEvent e) {
        return e == null || e.getDetectedAt() == null ? LocalDateTime.now() : e.getDetectedAt();
    }

    private static String minutesLabel(LocalDateTime first, LocalDateTime last) {
        if (first == null || last == null) {
            return "<1 min";
        }
        long mins = Duration.between(first, last).toMinutes();
        return mins < 1 ? "<1 min" : mins + " min";
    }
}
