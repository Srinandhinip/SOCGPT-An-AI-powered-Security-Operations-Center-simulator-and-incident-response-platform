package com.socgpt.backend.pdf;

import static com.socgpt.backend.pdf.SimplePdf.BOLD;
import static com.socgpt.backend.pdf.SimplePdf.HELV;
import static com.socgpt.backend.pdf.SimplePdf.MARGIN;
import static com.socgpt.backend.pdf.SimplePdf.MONO;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.socgpt.backend.model.AuditLog;
import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.IncidentChain;
import com.socgpt.backend.model.InvestigationReport;
import com.socgpt.backend.model.RemediationPlan;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.model.User;
import com.socgpt.backend.repository.AuditLogRepository;
import com.socgpt.backend.repository.IncidentChainRepository;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.InvestigationReportRepository;
import com.socgpt.backend.repository.RemediationPlanRepository;
import com.socgpt.backend.repository.SecurityEventRepository;
import com.socgpt.backend.repository.UserRepository;
import com.socgpt.backend.service.MitreMappingService;
import com.socgpt.backend.util.Json;

/** Builds the one-incident PDF report on demand (nothing is stored). */
@Service
public class ReportPdfService {

    private static final int INK = 0x0F172A, MUTED = 0x64748B, LINE = 0xE2E8F0, PANEL = 0xF1F5F9,
        BRAND = 0x0B1220, CYAN = 0x06B6D4, GREEN = 0x16A34A, AMBER = 0xD97706, RED = 0xDC2626;
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm:ss");

    private final IncidentRepository incidentRepository;
    private final SecurityEventRepository eventRepository;
    private final InvestigationReportRepository reportRepository;
    private final RemediationPlanRepository planRepository;
    private final AuditLogRepository auditRepository;
    private final UserRepository userRepository;
    private final IncidentChainRepository chainRepository;
    private final MitreMappingService mappingService;

    public ReportPdfService(IncidentRepository incidentRepository, SecurityEventRepository eventRepository,
                            InvestigationReportRepository reportRepository, RemediationPlanRepository planRepository,
                            AuditLogRepository auditRepository, UserRepository userRepository,
                            IncidentChainRepository chainRepository, MitreMappingService mappingService) {
        this.incidentRepository = incidentRepository;
        this.eventRepository = eventRepository;
        this.reportRepository = reportRepository;
        this.planRepository = planRepository;
        this.auditRepository = auditRepository;
        this.userRepository = userRepository;
        this.chainRepository = chainRepository;
        this.mappingService = mappingService;
    }

    public byte[] build(Integer incidentId, String generatedBy) {
        Incident inc = incidentRepository.findById(incidentId).orElseThrow(() ->
            new ResponseStatusException(HttpStatus.NOT_FOUND, "Incident " + incidentId + " not found"));
        SecurityEvent ev = inc.getEventId() == null ? null : eventRepository.findById(inc.getEventId()).orElse(null);
        MitreMappingService.Mapping map = ev == null ? null : mappingService.lookup(ev.getEventType()).orElse(null);
        InvestigationReport rep = reportRepository.findFirstByIncidentIdOrderByReportIdDesc(incidentId).orElse(null);
        List<RemediationPlan> plans = planRepository.findByIncidentIdOrderByPlanIdAsc(incidentId);
        RemediationPlan plan = plans.isEmpty() ? null : plans.get(plans.size() - 1);
        IncidentChain chain = inc.getChainId() == null ? null : chainRepository.findById(inc.getChainId()).orElse(null);
        Map<Integer, String> names = userRepository.findAll().stream()
            .collect(Collectors.toMap(User::getUserId, User::getUsername, (a, b) -> a, HashMap::new));

        List<AuditLog> audit = new ArrayList<>();
        Set<Integer> planIds = plans.stream().map(RemediationPlan::getPlanId).collect(Collectors.toSet());
        if (!planIds.isEmpty()) {
            audit.addAll(auditRepository.findByTargetTypeAndTargetIdInOrderByLogIdAsc("remediation_plan", planIds));
        }
        audit.addAll(auditRepository.findByTargetTypeAndTargetIdInOrderByLogIdAsc("incident", Set.of(incidentId)));
        audit.sort((a, b) -> Integer.compare(a.getLogId(), b.getLogId()));

        SimplePdf pdf = new SimplePdf();
        pdf.setFooterLeft("SOCGPT  |  Incident #" + incidentId + " report  |  Confidential");
        float cw = pdf.contentWidth();

        brandBand(pdf);
        String attack = ev == null ? "Unknown event" : label(ev.getEventType());
        pdf.setY(96);
        pdf.text("Incident #" + incidentId + "  -  " + attack, BOLD, 19, INK, MARGIN, pdf.y() + 19);
        pdf.gap(26);
        pdf.text("Generated " + LocalDateTime.now().format(TS) + (generatedBy == null ? "" : " by " + generatedBy),
            HELV, 9, MUTED, MARGIN, pdf.y() + 9);
        pdf.gap(22);

        // pills
        float px = MARGIN;
        px += pill(pdf, px, pdf.y(), inc.getSeverity(), sevColor(inc.getSeverity())) + 8;
        px += pill(pdf, px, pdf.y(), statusLabel(inc.getStatus()), 0x475569) + 8;
        if (chain != null) {
            pill(pdf, px, pdf.y(), "Chain #" + chain.getChainId(), 0x7C3AED);
        }
        pdf.gap(34);

        // ---- key facts
        section(pdf, "Key facts");
        List<String[]> facts = new ArrayList<>();
        facts.add(new String[] {"Source IP", ev == null ? "-" : nz(ev.getSourceIp())});
        facts.add(new String[] {"Attack type", attack});
        facts.add(new String[] {"MITRE ATT&CK", map == null ? "-" : map.mitreId() + " " + map.techniqueName()});
        facts.add(new String[] {"Tactic", map == null ? "-" : map.tactic()});
        facts.add(new String[] {"NIST CSF 2.0", map == null ? nz(inc.getCsfFunction()) : map.csfFunction()});
        facts.add(new String[] {"Detected", ev == null || ev.getDetectedAt() == null ? "-" : ev.getDetectedAt().format(TS)});
        facts.add(new String[] {"Risk score", (inc.getRiskScore() == null ? 0 : inc.getRiskScore()) + " / 100"});
        facts.add(new String[] {"Incident created", inc.getCreatedAt() == null ? "-" : inc.getCreatedAt().format(TS)});
        float colW = cw / 2f;
        for (int i = 0; i < facts.size(); i += 2) {
            pdf.ensure(34);
            float top = pdf.y();
            for (int k = 0; k < 2 && i + k < facts.size(); k++) {
                float x = MARGIN + k * colW;
                pdf.text(facts.get(i + k)[0].toUpperCase(), BOLD, 7.5f, MUTED, x, top + 8);
                pdf.text(clip(facts.get(i + k)[1], HELV, 10.5f, colW - 12), HELV, 10.5f, INK, x, top + 22);
            }
            pdf.gap(34);
        }

        // ---- risk breakdown
        section(pdf, "Why this risk score");
        int score = inc.getRiskScore() == null ? 0 : inc.getRiskScore();
        pdf.ensure(30);
        bar(pdf, MARGIN, pdf.y() + 2, cw - 70, 9, score / 100f, sevColor(inc.getSeverity()));
        pdf.text(score + " / 100", BOLD, 11, INK, MARGIN + cw - 62, pdf.y() + 11);
        pdf.gap(24);
        List<Object> factors = Json.parseList(inc.getRiskFactors());
        if (factors.isEmpty()) {
            pdf.paragraph("No scoring breakdown was recorded for this incident (it was created before risk scoring existed).",
                HELV, 9.5f, MUTED, MARGIN, cw, 13);
        }
        for (Object o : factors) {
            Map<String, Object> f = Json.asMap(o);
            int pts = (int) Math.round(num(f.get("points")));
            String name = Json.str(f.get("name"));
            boolean base = "Detection rule baseline".equals(name);
            List<String> lines = SimplePdf.wrap(nz(Json.str(f.get("detail"))), HELV, 9, cw - 215);
            float h = Math.max(1, lines.size()) * 12 + 8;
            pdf.ensure(h);
            float top = pdf.y();
            pdf.text(name, BOLD, 9.5f, INK, MARGIN, top + 11);
            pdf.textRight(base ? String.valueOf(pts) : (pts > 0 ? "+" + pts : String.valueOf(pts)), BOLD, 10,
                pts > 0 && !base ? AMBER : INK, MARGIN + 188, top + 11);
            float ly = top;
            for (String line : lines) {
                pdf.text(line, HELV, 9, MUTED, MARGIN + 208, ly + 11);
                ly += 12;
            }
            pdf.setY(top + h);
            pdf.hLine(MARGIN, MARGIN + cw, pdf.y() - 3, LINE, 0.5f);
        }
        pdf.gap(10);

        // ---- attack chain
        if (chain != null) {
            section(pdf, "Multi-stage attack chain");
            pdf.paragraph(nz(chain.getDescription()), BOLD, 10, INK, MARGIN, cw, 14);
            pdf.paragraph("Chain #" + chain.getChainId() + "  |  " + nz(chain.getStages() == null ? null : String.valueOf(chain.getStages()))
                + " distinct stages  |  overall risk " + (chain.getOverallRisk() == null ? 0 : chain.getOverallRisk()) + "/100  |  status "
                + nz(chain.getStatus()), HELV, 9, MUTED, MARGIN, cw, 13);
            pdf.gap(12);
        }

        // ---- AI report
        section(pdf, "AI investigation report");
        if (rep == null) {
            pdf.paragraph("The AI has not produced a report for this incident yet.", HELV, 10, MUTED, MARGIN, cw, 14);
            pdf.gap(10);
        } else {
            pdf.ensure(60);
            pdf.text("CLASSIFICATION", BOLD, 7.5f, MUTED, MARGIN, pdf.y() + 8);
            pdf.gap(12);
            pdf.paragraph(nz(rep.getClassification()), BOLD, 13, INK, MARGIN, cw, 17);
            double conf = Math.max(0, Math.min(1, rep.getConfidence() == null ? 0 : rep.getConfidence()));
            pdf.gap(4);
            pdf.text("CONFIDENCE", BOLD, 7.5f, MUTED, MARGIN, pdf.y() + 8);
            bar(pdf, MARGIN + 70, pdf.y() + 1, 180, 8, (float) conf, conf >= .75 ? GREEN : conf >= .5 ? AMBER : RED);
            pdf.text(Math.round(conf * 100) + "%", BOLD, 10, INK, MARGIN + 260, pdf.y() + 9);
            pdf.gap(22);

            pdf.text("SUMMARY", BOLD, 7.5f, MUTED, MARGIN, pdf.y() + 8);
            pdf.gap(12);
            pdf.paragraph(nz(rep.getSummary()), HELV, 10, INK, MARGIN, cw, 14);
            pdf.gap(8);

            // impact box
            List<String> impact = SimplePdf.wrap(nz(rep.getImpact()), HELV, 10, cw - 24);
            float boxH = impact.size() * 14 + 30;
            pdf.ensure(boxH);
            float top = pdf.y();
            pdf.fillRect(MARGIN, top, cw, boxH, 0xFEF3C7);
            pdf.fillRect(MARGIN, top, 3, boxH, AMBER);
            pdf.text("IMPACT IF NOT CONTAINED", BOLD, 7.5f, 0x92400E, MARGIN + 12, top + 14);
            float ly = top + 16;
            for (String line : impact) {
                pdf.text(line, HELV, 10, INK, MARGIN + 12, ly + 12);
                ly += 14;
            }
            pdf.setY(top + boxH + 10);

            List<Object> evidence = Json.parseList(rep.getEvidence());
            if (!evidence.isEmpty()) {
                pdf.ensure(24);
                pdf.text("EVIDENCE", BOLD, 7.5f, MUTED, MARGIN, pdf.y() + 8);
                pdf.gap(14);
                for (Object e : evidence) {
                    List<String> lines = SimplePdf.wrap(String.valueOf(e), HELV, 10, cw - 16);
                    pdf.ensure(lines.size() * 14);
                    pdf.text("•", BOLD, 10, CYAN, MARGIN + 2, pdf.y() + 10);
                    for (String line : lines) {
                        pdf.text(line, HELV, 10, INK, MARGIN + 14, pdf.y() + 10);
                        pdf.gap(14);
                    }
                    pdf.gap(2);
                }
                pdf.gap(8);
            }
        }

        // ---- remediation plan
        section(pdf, "Remediation plan");
        if (plan == null) {
            pdf.paragraph("No remediation plan exists yet.", HELV, 10, MUTED, MARGIN, cw, 14);
            pdf.gap(10);
        } else {
            String who = plan.getApprovedBy() == null ? "" : "  |  decided by " + nz(names.get(plan.getApprovedBy()))
                + (plan.getApprovedAt() == null ? "" : " on " + plan.getApprovedAt().format(TS));
            pdf.paragraph("Plan #" + plan.getPlanId() + "  |  status " + nz(plan.getStatus()) + who, BOLD, 9.5f, INK, MARGIN, cw, 14);
            pdf.gap(6);
            int n = 1;
            for (Object o : Json.parseList(plan.getSteps())) {
                Map<String, Object> st = Json.asMap(o);
                List<String> lines = SimplePdf.wrap(nz(Json.str(st.get("action"))), HELV, 10, cw - 34);
                pdf.ensure(lines.size() * 14 + 22);
                float top = pdf.y();
                pdf.fillRect(MARGIN, top, 20, 20, CYAN);
                pdf.text(String.valueOf(n), BOLD, 10, 0xFFFFFF, MARGIN + (n > 9 ? 4.5f : 7), top + 14);
                pdf.text(nz(Json.str(st.get("stage"))).toUpperCase(), BOLD, 8, MUTED, MARGIN + 30, top + 8);
                float ly = top + 10;
                for (String line : lines) {
                    pdf.text(line, HELV, 10, INK, MARGIN + 30, ly + 10);
                    ly += 14;
                }
                pdf.setY(Math.max(top + 24, ly + 4) + 4);
                n++;
            }
            pdf.gap(6);
        }

        // ---- audit trail
        section(pdf, "Audit trail");
        if (audit.isEmpty()) {
            pdf.paragraph("No human actions have been recorded for this incident yet.", HELV, 10, MUTED, MARGIN, cw, 14);
        }
        for (AuditLog a : audit) {
            String head = (a.getCreatedAt() == null ? "-" : a.getCreatedAt().format(TS)) + "   " + nz(a.getAction())
                + (a.getUserId() == null ? "" : "   by " + nz(names.get(a.getUserId())));
            List<String> lines = SimplePdf.wrap(nz(a.getDetails()), HELV, 9, cw - 12);
            pdf.ensure(16 + lines.size() * 12 + 6);
            pdf.text(head, MONO, 8, INK, MARGIN, pdf.y() + 9);
            pdf.gap(14);
            for (String line : lines) {
                pdf.text(line, HELV, 9, MUTED, MARGIN + 12, pdf.y() + 9);
                pdf.gap(12);
            }
            pdf.gap(6);
        }

        return pdf.toBytes();
    }

    // ------------------------------------------------------------------ drawing helpers

    private void brandBand(SimplePdf pdf) {
        pdf.fillRect(0, 0, SimplePdf.W, 72, BRAND);
        pdf.fillRect(0, 72, SimplePdf.W, 3, CYAN);
        pdf.text("SOCGPT", BOLD, 22, 0xFFFFFF, MARGIN, 36);
        pdf.text("AI Security Operations Center", HELV, 9.5f, 0x67E8F9, MARGIN, 54);
        pdf.textRight("INCIDENT REPORT", BOLD, 11, 0xFFFFFF, SimplePdf.W - MARGIN, 36);
        pdf.textRight("Confidential", HELV, 9, 0x94A3B8, SimplePdf.W - MARGIN, 54);
    }

    private void section(SimplePdf pdf, String title) {
        pdf.ensure(46);
        pdf.gap(6);
        float top = pdf.y();
        pdf.fillRect(MARGIN, top, 4, 16, CYAN);
        pdf.text(title, BOLD, 12.5f, INK, MARGIN + 12, top + 12.5f);
        pdf.hLine(MARGIN, MARGIN + pdf.contentWidth(), top + 22, LINE, 0.8f);
        pdf.setY(top + 32);
    }

    /** Draws a coloured label box; returns its width. */
    private float pill(SimplePdf pdf, float x, float top, String text, int rgb) {
        String t = text == null ? "-" : text.toUpperCase();
        float w = SimplePdf.width(t, BOLD, 9) + 20;
        pdf.fillRect(x, top, w, 20, rgb);
        pdf.text(t, BOLD, 9, 0xFFFFFF, x + 10, top + 14);
        return w;
    }

    private void bar(SimplePdf pdf, float x, float top, float w, float h, float fraction, int rgb) {
        pdf.fillRect(x, top, w, h, LINE);
        pdf.fillRect(x, top, Math.max(2, w * Math.max(0, Math.min(1, fraction))), h, rgb);
    }

    private static String clip(String s, int font, float size, float maxW) {
        String t = SimplePdf.sanitize(s);
        if (SimplePdf.width(t, font, size) <= maxW) {
            return t;
        }
        while (t.length() > 1 && SimplePdf.width(t + "...", font, size) > maxW) {
            t = t.substring(0, t.length() - 1);
        }
        return t + "...";
    }

    private static int sevColor(String sev) {
        return switch (sev == null ? "" : sev) {
            case "CRITICAL" -> 0xDC2626;
            case "HIGH" -> 0xEA580C;
            case "MEDIUM" -> 0xCA8A04;
            case "LOW" -> 0x16A34A;
            default -> 0x475569;
        };
    }

    private static String statusLabel(String st) {
        return st == null ? "-" : st.replace('_', ' ');
    }

    private static String label(String type) {
        return switch (type == null ? "" : type) {
            case "brute_force" -> "Brute force";
            case "sqli" -> "SQL injection";
            case "port_scan" -> "Port scan";
            case "malware" -> "Malware";
            default -> type == null ? "Unknown" : type;
        };
    }

    private static String nz(String s) {
        return s == null ? "-" : s;
    }

    private static double num(Object o) {
        return o instanceof Number n ? n.doubleValue() : 0;
    }
}
