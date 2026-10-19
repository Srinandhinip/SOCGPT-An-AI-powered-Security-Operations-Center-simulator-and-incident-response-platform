package com.socgpt.backend.service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.socgpt.backend.model.AuditLog;
import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.IncidentChain;
import com.socgpt.backend.model.InvestigationReport;
import com.socgpt.backend.model.RemediationPlan;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.repository.AuditLogRepository;
import com.socgpt.backend.repository.IncidentChainRepository;
import com.socgpt.backend.repository.InvestigationReportRepository;
import com.socgpt.backend.repository.NotificationRepository;
import com.socgpt.backend.repository.RemediationPlanRepository;

/** The "how well is the SOC doing" numbers for the Command Center. */
@Service
public class MetricsService {

    private final RemediationPlanRepository planRepository;
    private final InvestigationReportRepository reportRepository;
    private final AuditLogRepository auditRepository;
    private final IncidentChainRepository chainRepository;
    private final NotificationRepository notificationRepository;

    public MetricsService(RemediationPlanRepository planRepository, InvestigationReportRepository reportRepository,
                          AuditLogRepository auditRepository, IncidentChainRepository chainRepository,
                          NotificationRepository notificationRepository) {
        this.planRepository = planRepository;
        this.reportRepository = reportRepository;
        this.auditRepository = auditRepository;
        this.chainRepository = chainRepository;
        this.notificationRepository = notificationRepository;
    }

    /**
     * @return mttrSeconds, avgAiSeconds, approvalRatePct, topIps, totalChains, activeChains, alertsSent
     *         (null where there is nothing to average yet)
     */
    public Map<String, Object> compute(List<Incident> incidents, Map<Integer, SecurityEvent> events) {
        Map<Integer, Incident> byId = new HashMap<>();
        for (Incident i : incidents) {
            byId.put(i.getIncidentId(), i);
        }
        List<RemediationPlan> plans = planRepository.findAll();

        // MTTR: detection -> recovery executed (time of the EXECUTE audit row)
        Map<Integer, LocalDateTime> executedAt = new HashMap<>();
        Map<Integer, Integer> planToIncident = new HashMap<>();
        plans.forEach(p -> planToIncident.put(p.getPlanId(), p.getIncidentId()));
        for (AuditLog a : auditRepository.findByActionOrderByLogIdAsc("EXECUTE_REMEDIATION_SIMULATED")) {
            Integer incidentId = planToIncident.get(a.getTargetId());
            if (incidentId != null && a.getCreatedAt() != null) {
                executedAt.put(incidentId, a.getCreatedAt());
            }
        }
        double mttrSum = 0;
        int mttrN = 0;
        for (Map.Entry<Integer, LocalDateTime> e : executedAt.entrySet()) {
            Incident inc = byId.get(e.getKey());
            if (inc == null) {
                continue;
            }
            SecurityEvent ev = inc.getEventId() == null ? null : events.get(inc.getEventId());
            LocalDateTime start = ev != null && ev.getDetectedAt() != null ? ev.getDetectedAt() : inc.getCreatedAt();
            if (start != null) {
                long s = Duration.between(start, e.getValue()).getSeconds();
                if (s >= 0) {
                    mttrSum += s;
                    mttrN++;
                }
            }
        }

        // AI speed: incident created -> first report
        Map<Integer, LocalDateTime> firstReport = new HashMap<>();
        for (InvestigationReport r : reportRepository.findAll()) {
            if (r.getIncidentId() != null && r.getGeneratedAt() != null) {
                firstReport.merge(r.getIncidentId(), r.getGeneratedAt(), (a, b) -> a.isBefore(b) ? a : b);
            }
        }
        double aiSum = 0;
        int aiN = 0;
        for (Map.Entry<Integer, LocalDateTime> e : firstReport.entrySet()) {
            Incident inc = byId.get(e.getKey());
            if (inc != null && inc.getCreatedAt() != null) {
                long s = Duration.between(inc.getCreatedAt(), e.getValue()).getSeconds();
                if (s >= 0) {
                    aiSum += s;
                    aiN++;
                }
            }
        }

        // approval rate over decided plans
        int approved = 0, rejected = 0;
        for (RemediationPlan p : plans) {
            if ("APPROVED".equals(p.getStatus()) || "EXECUTED".equals(p.getStatus())) {
                approved++;
            } else if ("REJECTED".equals(p.getStatus())) {
                rejected++;
            }
        }

        // top attacking IPs
        Map<String, int[]> ips = new HashMap<>();      // ip -> {count, maxRisk}
        for (Incident i : incidents) {
            SecurityEvent ev = i.getEventId() == null ? null : events.get(i.getEventId());
            if (ev == null || ev.getSourceIp() == null) {
                continue;
            }
            int[] v = ips.computeIfAbsent(ev.getSourceIp(), k -> new int[2]);
            v[0]++;
            v[1] = Math.max(v[1], i.getRiskScore() == null ? 0 : i.getRiskScore());
        }
        List<Map<String, Object>> top = new ArrayList<>();
        ips.entrySet().stream()
            .sorted(Comparator.<Map.Entry<String, int[]>>comparingInt(e -> -e.getValue()[0])
                .thenComparingInt(e -> -e.getValue()[1]))
            .limit(5)
            .forEach(e -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ip", e.getKey());
                m.put("count", e.getValue()[0]);
                m.put("maxRisk", e.getValue()[1]);
                top.add(m);
            });

        List<IncidentChain> chains = chainRepository.findAll();
        long active = chains.stream().filter(c -> "ACTIVE".equals(c.getStatus())).count();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mttrSeconds", mttrN == 0 ? null : (Object) Math.round(mttrSum / mttrN));
        out.put("avgAiSeconds", aiN == 0 ? null : (Object) Math.round(aiSum / aiN));
        out.put("approvalRatePct", approved + rejected == 0 ? null : (Object) Math.round(100.0 * approved / (approved + rejected)));
        out.put("topIps", top);
        out.put("totalChains", chains.size());
        out.put("activeChains", active);
        out.put("alertsSent", notificationRepository.countByStatus("SENT"));
        return out;
    }
}
