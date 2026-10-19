package com.socgpt.backend.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.IncidentChain;
import com.socgpt.backend.model.InvestigationReport;
import com.socgpt.backend.model.Notification;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.model.User;
import com.socgpt.backend.pdf.ReportPdfService;
import com.socgpt.backend.repository.NotificationRepository;
import com.socgpt.backend.repository.UserRepository;

import jakarta.mail.internet.MimeMessage;

/**
 * E-mail alerts. Two kinds: "action required" (an AI plan is waiting for a human, PDF attached)
 * and "multi-stage attack detected". Every send is stored in the notifications table.
 * Sending never blocks or breaks the detection pipeline: failures are recorded and logged.
 */
@Service
public class NotificationService {

    private final ObjectProvider<JavaMailSender> mailSender;
    private final NotificationRepository notificationRepository;
    private final UserRepository userRepository;
    private final ReportPdfService pdfService;
    private final boolean enabled;
    private final String from;
    private final String recipientOverride;
    private final String baseUrl;
    private final ExecutorService executor = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "socgpt-mail");
        t.setDaemon(true);
        return t;
    });

    public NotificationService(ObjectProvider<JavaMailSender> mailSender,
                               NotificationRepository notificationRepository,
                               UserRepository userRepository,
                               ReportPdfService pdfService,
                               @Value("${socgpt.alerts.enabled:true}") boolean enabled,
                               @Value("${socgpt.alerts.from:socgpt@localhost}") String from,
                               @Value("${socgpt.alerts.recipients:}") String recipientOverride,
                               @Value("${socgpt.base-url:http://localhost:8080}") String baseUrl) {
        this.mailSender = mailSender;
        this.notificationRepository = notificationRepository;
        this.userRepository = userRepository;
        this.pdfService = pdfService;
        this.enabled = enabled;
        this.from = from;
        this.recipientOverride = recipientOverride == null ? "" : recipientOverride;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }

    // ------------------------------------------------------------------ the two alerts

    /** "A plan is waiting for your decision." Called from the AI pipeline's own background thread. */
    public void actionRequired(Incident incident, InvestigationReport report, SecurityEvent event,
                               MitreMappingService.Mapping mapping) {
        if (!enabled) {
            return;
        }
        try {
            List<String> to = recipientsFor(incident.getSeverity());
            if (to.isEmpty()) {
                return;
            }
            String attack = event == null ? "incident" : event.getEventType();
            String subject = "[SOCGPT] Action required: " + incident.getSeverity() + " " + attack
                + " (incident #" + incident.getIncidentId() + ")";
            String link = baseUrl + "/incidents.html?id=" + incident.getIncidentId();

            String summary = report == null ? "" : nz(report.getSummary());
            String classification = report == null ? "" : nz(report.getClassification());
            String plain = "An AI remediation plan is waiting for a human decision.\n\n"
                + "Incident #" + incident.getIncidentId() + " - " + incident.getSeverity() + " - risk " + incident.getRiskScore() + "/100\n"
                + (event == null ? "" : "Attack: " + event.getEventType() + " from " + event.getSourceIp() + "\n")
                + (mapping == null ? "" : "MITRE ATT&CK: " + mapping.mitreId() + " " + mapping.techniqueName() + " (" + mapping.tactic() + ")\n")
                + "Classification: " + classification + "\n\n" + summary + "\n\n"
                + "Review and decide: " + link + "\n\nThe full incident report is attached as a PDF.\n";

            String html = layout("Action required", "#f59e0b",
                row("Incident", "#" + incident.getIncidentId() + " &middot; " + esc(incident.getSeverity()) + " &middot; risk " + incident.getRiskScore() + "/100")
                + (event == null ? "" : row("Attack", esc(event.getEventType()) + " from <code>" + esc(event.getSourceIp()) + "</code>"))
                + (mapping == null ? "" : row("MITRE ATT&CK", esc(mapping.mitreId() + " " + mapping.techniqueName() + " (" + mapping.tactic() + ")")))
                + row("AI classification", esc(classification))
                + "<p style=\"margin:16px 0 4px;font-size:14px;line-height:1.55;color:#1e293b\">" + esc(summary) + "</p>",
                "Review &amp; decide", link,
                "Nothing runs until a human approves it. The full incident report is attached as a PDF.");

            byte[] pdf = null;
            try {
                pdf = pdfService.build(incident.getIncidentId(), "SOCGPT");
            } catch (RuntimeException e) {
                System.out.println("[MAIL] Could not build the PDF attachment: " + e.getMessage());
            }
            for (String recipient : to) {
                send(incident.getIncidentId(), recipient, subject, plain, html,
                    pdf == null ? null : "incident-" + incident.getIncidentId() + "-report.pdf", pdf);
            }
        } catch (RuntimeException e) {
            System.out.println("[MAIL] Action-required alert failed: " + e.getMessage());
        }
    }

    /** "Multi-stage attack detected" - sent in the background so detection is never delayed. */
    public void chainAlertAsync(IncidentChain chain, Incident newest, Map<String, Object> context) {
        if (!enabled) {
            return;
        }
        executor.submit(() -> {
            try {
                List<String> to = recipientsFor("CRITICAL");   // chains always go to the senior people
                if (to.isEmpty()) {
                    return;
                }
                String subject = "[SOCGPT] Multi-stage attack detected from " + chain.getSourceIp()
                    + " (" + chain.getStages() + " stages)";
                String link = baseUrl + "/incidents.html?id=" + newest.getIncidentId();
                String plain = "A multi-stage attack was detected.\n\n" + nz(chain.getDescription())
                    + "\nChain #" + chain.getChainId() + ", overall risk " + chain.getOverallRisk() + "/100.\n\n"
                    + "Latest incident: " + link + "\n";
                StringBuilder stages = new StringBuilder();
                Object list = context == null ? null : context.get("stages");
                if (list instanceof List<?> l) {
                    int n = 1;
                    for (Object o : l) {
                        if (o instanceof Map<?, ?> m) {
                            stages.append("<li style=\"margin:3px 0\"><b>").append(n++).append(".</b> ")
                                .append(esc(String.valueOf(m.get("tactic")))).append(" &middot; ")
                                .append(esc(String.valueOf(m.get("eventType")))).append(" &middot; incident #")
                                .append(esc(String.valueOf(m.get("incidentId")))).append("</li>");
                        }
                    }
                }
                String html = layout("Multi-stage attack detected", "#ef4444",
                    row("Source IP", "<code>" + esc(chain.getSourceIp()) + "</code>")
                    + row("Attack path", esc(nz(chain.getDescription())))
                    + row("Overall risk", chain.getOverallRisk() + "/100")
                    + (stages.length() == 0 ? "" : "<ol style=\"margin:14px 0 0;padding-left:20px;font-size:14px;color:#1e293b\">" + stages + "</ol>"),
                    "Open the latest incident", link,
                    "Several different attack stages from one IP in a short time usually means a real, progressing intrusion.");
                for (String recipient : to) {
                    send(newest.getIncidentId(), recipient, subject, plain, html, null, null);
                }
            } catch (RuntimeException e) {
                System.out.println("[MAIL] Chain alert failed: " + e.getMessage());
            }
        });
    }

    // ------------------------------------------------------------------ plumbing

    /** Override from properties, else users with an e-mail chosen by role. */
    List<String> recipientsFor(String severity) {
        Set<String> out = new LinkedHashSet<>();
        for (String r : recipientOverride.split(",")) {
            if (!r.isBlank()) {
                out.add(r.trim());
            }
        }
        if (out.isEmpty()) {
            List<String> roles = "CRITICAL".equals(severity)
                ? List.of("soc_manager", "admin") : List.of("analyst", "soc_manager", "admin");
            for (User u : userRepository.findByRoleIn(roles)) {
                if (u.getEmail() != null && !u.getEmail().isBlank()) {
                    out.add(u.getEmail().trim());
                }
            }
        }
        return new ArrayList<>(out);
    }

    private void send(Integer incidentId, String recipient, String subject, String plain, String html,
                      String attachmentName, byte[] attachment) {
        Notification n = new Notification();
        n.setIncidentId(incidentId);
        n.setChannel("email");
        n.setRecipient(recipient);
        n.setSubject(subject.length() > 200 ? subject.substring(0, 200) : subject);
        n.setStatus("PENDING");
        n = notificationRepository.save(n);
        try {
            JavaMailSender sender = mailSender.getIfAvailable();
            if (sender == null) {
                throw new IllegalStateException("No mail server is configured (spring.mail.host)");
            }
            MimeMessage message = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(from);
            helper.setTo(recipient);
            helper.setSubject(subject);
            helper.setText(plain, html);
            if (attachment != null) {
                helper.addAttachment(attachmentName, new ByteArrayResource(attachment), "application/pdf");
            }
            // the mail server may be starting up or briefly busy: try up to 3 times before giving up
            for (int attempt = 1; ; attempt++) {
                try {
                    sender.send(message);
                    break;
                } catch (RuntimeException sendError) {
                    if (attempt >= 3) {
                        throw sendError;
                    }
                    System.out.println("[MAIL] Attempt " + attempt + " failed (" + sendError.getMessage() + "), retrying");
                    try {
                        Thread.sleep(2000L * attempt);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw sendError;
                    }
                }
            }
            n.setStatus("SENT");
            n.setSentAt(LocalDateTime.now());
            System.out.println("[MAIL] Sent '" + subject + "' to " + recipient);
        } catch (Exception e) {
            n.setStatus("FAILED");
            n.setError(shorten(e.getMessage() == null ? e.toString() : e.getMessage()));
            System.out.println("[MAIL] Could not send to " + recipient + ": " + n.getError());
        }
        notificationRepository.save(n);
    }

    private static String layout(String title, String accent, String bodyHtml, String button, String url, String footer) {
        return "<!doctype html><html><body style=\"margin:0;background:#f1f5f9;font-family:Segoe UI,Arial,sans-serif\">"
            + "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr><td align=\"center\" style=\"padding:24px 12px\">"
            + "<table width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:600px;background:#ffffff;border-radius:10px;overflow:hidden\">"
            + "<tr><td style=\"background:#0b1220;padding:18px 24px\"><span style=\"color:#fff;font-size:20px;font-weight:700\">SOCGPT</span>"
            + "<span style=\"color:#67e8f9;font-size:12px;margin-left:10px\">AI Security Operations</span></td></tr>"
            + "<tr><td style=\"height:4px;background:" + accent + "\"></td></tr>"
            + "<tr><td style=\"padding:24px\"><h2 style=\"margin:0 0 14px;font-size:20px;color:#0f172a\">" + esc(title) + "</h2>"
            + "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">" + bodyHtml + "</table>"
            + "<p style=\"margin:22px 0 8px\"><a href=\"" + esc(url) + "\" style=\"display:inline-block;background:#0891b2;color:#fff;text-decoration:none;"
            + "padding:11px 20px;border-radius:7px;font-weight:600;font-size:14px\">" + button + "</a></p>"
            + "<p style=\"margin:14px 0 0;font-size:12px;color:#64748b\">" + esc(footer) + "</p></td></tr></table>"
            + "</td></tr></table></body></html>";
    }

    private static String row(String label, String valueHtml) {
        return "<tr><td style=\"padding:5px 0;width:140px;font-size:12px;color:#64748b;vertical-align:top\">" + esc(label)
            + "</td><td style=\"padding:5px 0;font-size:14px;color:#0f172a\">" + valueHtml + "</td></tr>";
    }

    static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static String shorten(String s) {
        return s.length() > 480 ? s.substring(0, 480) + "..." : s;
    }
}
