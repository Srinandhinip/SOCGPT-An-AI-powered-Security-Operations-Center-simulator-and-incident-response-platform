package com.socgpt.backend;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.Map;

import org.springframework.boot.SpringApplication;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;
import com.socgpt.backend.util.Json;
import com.sun.net.httpserver.HttpServer;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;

/**
 * Runs the whole backend WITHOUT Docker, Python or a Gemini key, for demos and UI work:
 * an in-process PostgreSQL, a stub "AI agent" that writes canned reports, and a local mail sink.
 * (pgvector is not available here, so the RAG memory is off; everything else is real.)
 *
 * Start it from the backend-java folder:
 *   .\mvnw.cmd -q test-compile exec:java "-Dexec.mainClass=com.socgpt.backend.DevHarness" "-Dexec.classpathScope=test"
 */
public class DevHarness {

    public static void main(String[] args) throws Exception {
        EmbeddedPostgres pg = EmbeddedPostgres.builder().start();
        String schema = Files.readString(Path.of("../db/schema.sql"));
        schema = schema.replaceAll("(?m)^CREATE EXTENSION.*$", "").replace("vector(768)", "text");
        try (Connection c = pg.getPostgresDatabase().getConnection(); Statement s = c.createStatement()) {
            s.execute(schema);
        }

        HttpServer agent = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        agent.createContext("/investigate", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> req = Json.asMap(Json.parse(body));
            try {
                Thread.sleep(2500);   // pretend the model is thinking
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            String type = String.valueOf(req.get("eventType"));
            boolean chain = req.get("chain") != null;
            String classification = switch (type) {
                case "sqli" -> "SQL injection against the login endpoint";
                case "malware" -> "Malicious attachment executed on a workstation";
                case "brute_force" -> "Credential brute-force against SSH";
                case "port_scan" -> "Network reconnaissance (port sweep)";
                default -> "Suspicious activity";
            };
            String summary = "Source " + req.get("sourceIp") + " triggered the " + type + " rule (" + req.get("mitreId") + "). "
                + (chain ? "This is one stage of a progressing multi-stage intrusion from the same IP, so the earlier stages must be treated as part of the same attack. " : "")
                + "[Stub AI: set up the Python agent and a Gemini key for real analysis.]";
            String evidence = "[\"Rule engine matched " + type + " from " + req.get("sourceIp") + "\",\"Mapped to " + req.get("techniqueName") + " (" + req.get("tactic") + ")\"]";
            String plan = "[{\"stage\":\"Containment\",\"action\":\"Block " + req.get("sourceIp") + " at the perimeter firewall and revoke any active sessions.\"},"
                + "{\"stage\":\"Eradication\",\"action\":\"Remove any persistence the attacker created and rotate exposed credentials.\"},"
                + "{\"stage\":\"Recovery\",\"action\":\"Restore affected services from a known-good state and re-enable access gradually.\"},"
                + "{\"stage\":\"Validation\",\"action\":\"Re-run the attack pattern in a test and confirm the detection and block both fire.\"},"
                + "{\"stage\":\"Prevention\",\"action\":\"Add a WAF/EDR rule for this technique and review rate limits on the affected service.\"}]";
            String json = "{\"incidentId\":" + ((Number) req.get("incidentId")).intValue() + ",\"status\":\"READY_FOR_APPROVAL\","
                + "\"report\":{\"summary\":" + Json.quote(summary) + ",\"classification\":" + Json.quote(classification)
                + ",\"confidence\":0.87,\"impact\":\"Unauthorised access and data exposure if the activity is not contained.\",\"evidence\":[]},"
                + "\"evidenceJson\":" + Json.quote(evidence) + ",\"remediationPlanJson\":" + Json.quote(plan) + ",\"error\":null}";
            byte[] out = json.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        agent.createContext("/embed", ex -> {
            byte[] out = "{\"detail\":\"embeddings unavailable in the dev harness\"}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(503, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        agent.start();

        int smtp = 1025;
        try (ServerSocket probe = new ServerSocket(smtp)) {
            // free
        } catch (Exception busy) {
            try (ServerSocket s = new ServerSocket(0)) {
                smtp = s.getLocalPort();
            }
        }
        GreenMail mail = new GreenMail(new ServerSetup(smtp, "127.0.0.1", ServerSetup.PROTOCOL_SMTP));
        mail.start();

        System.setProperty("spring.datasource.url", pg.getJdbcUrl("postgres", "postgres"));
        System.setProperty("spring.datasource.username", "postgres");
        System.setProperty("spring.datasource.password", "postgres");
        System.setProperty("socgpt.agent.url", "http://127.0.0.1:" + agent.getAddress().getPort());
        System.setProperty("spring.mail.port", String.valueOf(smtp));
        System.setProperty("socgpt.rag.enabled", "false");

        System.out.println("[DEV] Stub AI on port " + agent.getAddress().getPort() + ", mail sink on port " + smtp);
        SpringApplication.run(BackendApplication.class, args);
    }
}
