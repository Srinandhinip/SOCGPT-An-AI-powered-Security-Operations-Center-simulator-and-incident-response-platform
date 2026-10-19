package com.socgpt.backend.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.SecurityEventRepository;
import com.socgpt.backend.util.Json;

/**
 * Turns the rule baseline (90 / 95 / 70 / 50) into a context-aware risk score.
 * Context can only RAISE the score (capped at 100) and can only UPGRADE the severity,
 * so a rule that says "critical" is never talked down.
 */
@Service
public class RiskScoringService {

    public record Factor(String name, int points, String detail) { }

    public record Result(int score, String severity, List<Factor> factors, boolean escalated) {
        /** JSON text for incidents.risk_factors. */
        public String factorsJson() {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < factors.size(); i++) {
                Factor f = factors.get(i);
                if (i > 0) {
                    sb.append(',');
                }
                sb.append("{\"name\":").append(Json.quote(f.name()))
                  .append(",\"points\":").append(f.points())
                  .append(",\"detail\":").append(Json.quote(f.detail())).append('}');
            }
            return sb.append(']').toString();
        }
    }

    static final int REPEAT_PER_INCIDENT = 5, REPEAT_MAX = 15;
    static final int CHAIN_PER_STAGE = 8, CHAIN_MAX = 24;
    static final int OFF_HOURS = 5;
    static final int BURST_PER_EVENT = 2, BURST_MAX = 6;

    private final SecurityEventRepository eventRepository;
    private final IncidentRepository incidentRepository;
    private final long chainWindowMinutes;

    public RiskScoringService(SecurityEventRepository eventRepository,
                              IncidentRepository incidentRepository,
                              @Value("${socgpt.chain.window-minutes:30}") long chainWindowMinutes) {
        this.eventRepository = eventRepository;
        this.incidentRepository = incidentRepository;
        this.chainWindowMinutes = chainWindowMinutes;
    }

    /**
     * @param ruleSeverity   severity the detection rule chose
     * @param baseline       the rule's baseline score
     * @param eventsInWindow how many matching events the rule saw (burst size)
     * @param threshold      how many the rule needs to fire (0 for instant rules)
     * @param chainStages    distinct attack stages from this IP including this one (1 = standalone)
     */
    public Result score(SecurityEvent event, String ruleSeverity, int baseline,
                        int eventsInWindow, int threshold, int chainStages) {
        return score(event, ruleSeverity, baseline, eventsInWindow, threshold, chainStages, LocalDateTime.now());
    }

    public Result score(SecurityEvent event, String ruleSeverity, int baseline,
                        int eventsInWindow, int threshold, int chainStages, LocalDateTime now) {
        List<Factor> factors = new ArrayList<>();
        factors.add(new Factor("Detection rule baseline", baseline,
            "The " + event.getEventType() + " rule rated this " + ruleSeverity + "."));
        int score = baseline;

        // repeat offender: earlier incidents from this IP in the last 24 h (older than the chain window,
        // because newer ones are already counted as chain progression)
        int priorOld = priorIncidentsOlderThanChainWindow(event, now);
        if (priorOld > 0) {
            int pts = Math.min(REPEAT_MAX, REPEAT_PER_INCIDENT * priorOld);
            factors.add(new Factor("Repeat offender", pts,
                priorOld + " earlier incident" + (priorOld == 1 ? "" : "s") + " from " + event.getSourceIp() + " in the last 24 hours."));
            score += pts;
        }

        if (chainStages > 1) {
            int pts = Math.min(CHAIN_MAX, CHAIN_PER_STAGE * (chainStages - 1));
            factors.add(new Factor("Attack chain progression", pts,
                chainStages + " distinct attack stages from the same IP within " + chainWindowMinutes + " minutes."));
            score += pts;
        }

        int hour = now.getHour();
        if (hour >= 22 || hour < 6) {
            factors.add(new Factor("Off-hours activity", OFF_HOURS,
                "Detected at " + String.format("%02d:%02d", hour, now.getMinute()) + " server time (22:00 to 05:59)."));
            score += OFF_HOURS;
        }

        int extra = threshold > 0 ? eventsInWindow - threshold : 0;
        if (extra > 0) {
            int pts = Math.min(BURST_MAX, BURST_PER_EVENT * extra);
            factors.add(new Factor("Burst intensity", pts,
                extra + " event" + (extra == 1 ? "" : "s") + " beyond the rule threshold of " + threshold + "."));
            score += pts;
        }

        score = Math.min(100, score);
        String derived = severityFor(score);
        String finalSeverity = rank(derived) > rank(ruleSeverity) ? derived : ruleSeverity;
        boolean escalated = !finalSeverity.equals(ruleSeverity);
        if (escalated) {
            factors.add(new Factor("Severity escalated", 0,
                "Context raised the score to " + score + ", so severity moved from " + ruleSeverity + " to " + finalSeverity + "."));
        }
        return new Result(score, finalSeverity, factors, escalated);
    }

    private int priorIncidentsOlderThanChainWindow(SecurityEvent event, LocalDateTime now) {
        if (event.getSourceIp() == null) {
            return 0;
        }
        List<SecurityEvent> recent = eventRepository.findBySourceIpAndDetectedAtAfter(event.getSourceIp(), now.minusHours(24));
        Set<Integer> ids = recent.stream().map(SecurityEvent::getEventId)
            .filter(id -> id != null && !id.equals(event.getEventId())).collect(Collectors.toSet());
        if (ids.isEmpty()) {
            return 0;
        }
        LocalDateTime chainCutoff = now.minusMinutes(chainWindowMinutes);
        int n = 0;
        for (Incident i : incidentRepository.findByEventIdIn(ids)) {
            if (i.getCreatedAt() != null && i.getCreatedAt().isBefore(chainCutoff)) {
                n++;
            }
        }
        return n;
    }

    public static String severityFor(int score) {
        if (score >= 85) {
            return "CRITICAL";
        }
        if (score >= 65) {
            return "HIGH";
        }
        if (score >= 40) {
            return "MEDIUM";
        }
        return "LOW";
    }

    static int rank(String severity) {
        return switch (severity == null ? "" : severity) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }
}
