package com.socgpt.backend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.service.RiskScoringService;
import com.socgpt.backend.util.Json;
import com.sun.net.httpserver.HttpServer;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;

/**
 * End-to-end test of the Java backend with everything real except the outside world:
 * an in-process PostgreSQL (the project's own db/schema.sql), a stub of the Python AI agent,
 * and a fake SMTP server. It drives the actual REST API with real tokens and roles.
 *
 * (pgvector is not available in the embedded Postgres, so the schema is loaded with the vector
 * column as plain text; the RAG calls then fail and the pipeline must carry on without them.)
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.MethodName.class)
class SocgptIntegrationTest {

    static EmbeddedPostgres pg;
    static HttpServer agent;
    static GreenMail mail;
    static final List<String> agentRequests = new CopyOnWriteArrayList<>();
    static volatile boolean agentFails = false;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        pg = EmbeddedPostgres.builder().start();
        String schema = Files.readString(Path.of("../db/schema.sql"));
        schema = schema.replaceAll("(?m)^CREATE EXTENSION.*$", "").replace("vector(768)", "text");
        try (Connection c = pg.getPostgresDatabase().getConnection(); Statement s = c.createStatement()) {
            s.execute(schema);
        }

        agent = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        agent.createContext("/investigate", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            agentRequests.add(body);
            byte[] out;
            int code = 200;
            if (agentFails) {
                code = 500;
                out = "{\"detail\":\"model overloaded\"}".getBytes(StandardCharsets.UTF_8);
            } else {
                Map<String, Object> req = Json.asMap(Json.parse(body));
                int id = ((Number) req.get("incidentId")).intValue();
                String plan = "[{\"stage\":\"Containment\",\"action\":\"Block the source IP at the firewall.\"},"
                    + "{\"stage\":\"Eradication\",\"action\":\"Remove the attacker foothold.\"},"
                    + "{\"stage\":\"Recovery\",\"action\":\"Restore services.\"},"
                    + "{\"stage\":\"Validation\",\"action\":\"Re-test the endpoint.\"},"
                    + "{\"stage\":\"Prevention\",\"action\":\"Add a WAF rule → monitor.\"}]";
                String json = "{\"incidentId\":" + id + ",\"status\":\"READY_FOR_APPROVAL\","
                    + "\"report\":{\"summary\":\"Stub summary for incident " + id + ".\","
                    + "\"classification\":\"A very long classification that is well over fifty characters in length\","
                    + "\"confidence\":0.91,\"impact\":\"Data theft is possible.\",\"evidence\":[\"e1\",\"e2\"]},"
                    + "\"evidenceJson\":\"[\\\"Source IP seen repeatedly\\\",\\\"Matches MITRE T1190\\\"]\","
                    + "\"remediationPlanJson\":" + Json.quote(plan) + ",\"error\":null}";
                out = json.getBytes(StandardCharsets.UTF_8);
            }
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(code, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        agent.createContext("/embed", ex -> {
            byte[] out = "{\"detail\":\"embeddings unavailable\"}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(503, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        agent.start();

        int smtpPort;
        try (ServerSocket s = new ServerSocket(0)) {
            smtpPort = s.getLocalPort();
        }
        mail = new GreenMail(new ServerSetup(smtpPort, "127.0.0.1", ServerSetup.PROTOCOL_SMTP));
        mail.start();

        r.add("spring.datasource.url", () -> pg.getJdbcUrl("postgres", "postgres"));
        r.add("spring.datasource.username", () -> "postgres");
        r.add("spring.datasource.password", () -> "postgres");
        r.add("socgpt.agent.url", () -> "http://127.0.0.1:" + agent.getAddress().getPort());
        r.add("spring.mail.host", () -> "127.0.0.1");
        r.add("spring.mail.port", () -> String.valueOf(smtpPort));
    }

    @AfterAll
    static void stop() throws Exception {
        if (mail != null) {
            mail.stop();
        }
        if (agent != null) {
            agent.stop(0);
        }
        if (pg != null) {
            pg.close();
        }
    }

    @Value("${local.server.port}")
    int port;

    @Autowired
    RiskScoringService riskScoring;

    // ------------------------------------------------------------------ tiny HTTP client

    record Resp(int status, String body, byte[] bytes) {
        Map<String, Object> map() { return Json.asMap(Json.parse(body)); }
        List<Object> list() { return Json.parseList(body); }
    }

    private final HttpClient http = HttpClient.newHttpClient();

    Resp call(String method, String path, String token, String ingestKey, String jsonBody) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path));
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        if (ingestKey != null) {
            b.header("X-Ingest-Key", ingestKey);
        }
        if (jsonBody != null) {
            b.header("Content-Type", "application/json");
        }
        b.method(method, jsonBody == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(jsonBody));
        HttpResponse<byte[]> res = http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
        return new Resp(res.statusCode(), new String(res.body(), StandardCharsets.UTF_8), res.body());
    }

    Resp get(String path, String token) throws Exception { return call("GET", path, token, null, null); }
    Resp post(String path, String token) throws Exception { return call("POST", path, token, null, null); }

    String login(String user, String pass) throws Exception {
        Resp r = call("POST", "/api/auth/login", null, null,
            "{\"username\":" + Json.quote(user) + ",\"password\":" + Json.quote(pass) + "}");
        assertEquals(200, r.status(), "login " + user + ": " + r.body());
        return (String) r.map().get("token");
    }

    String admin() throws Exception { return login("admin", "Admin@123"); }
    String manager() throws Exception { return login("manager1", "Manager@123"); }
    String analyst() throws Exception { return login("analyst1", "Analyst@123"); }

    void sendEvent(String ip, String type) throws Exception {
        Resp r = call("POST", "/events", null, "dev-ingest-key",
            "{\"sourceIp\":\"" + ip + "\",\"eventType\":\"" + type + "\"}");
        assertEquals(200, r.status(), r.body());
    }

    List<Map<String, Object>> incidentsFor(String ip, String token) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : get("/api/incidents", token).list()) {
            Map<String, Object> m = Json.asMap(o);
            if (ip.equals(m.get("sourceIp"))) {
                out.add(m);
            }
        }
        return out;
    }

    static <T> T await(String what, Supplier<T> check) throws Exception {
        long end = System.currentTimeMillis() + 20_000;
        while (System.currentTimeMillis() < end) {
            T v = check.get();
            if (v != null && !Boolean.FALSE.equals(v)) {
                return v;
            }
            Thread.sleep(150);
        }
        throw new AssertionError("Timed out waiting for: " + what);
    }

    int incidentId(Map<String, Object> m) { return ((Number) m.get("incidentId")).intValue(); }

    Map<String, Object> detail(int id, String token) throws Exception {
        Resp r = get("/api/incidents/" + id, token);
        assertEquals(200, r.status(), r.body());
        return r.map();
    }

    /** Waits until the stub AI has produced the plan, then returns the incident detail. */
    Map<String, Object> awaitPlan(int id, String token) throws Exception {
        return await("AI plan for incident " + id, () -> {
            try {
                Map<String, Object> d = detail(id, token);
                return d.get("plan") != null ? d : null;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // ------------------------------------------------------------------ tests

    @Test
    void t01_authAndRoles() throws Exception {
        assertEquals(401, get("/api/incidents", null).status());
        assertEquals(401, get("/api/incidents", "garbage.token").status());
        assertEquals(401, call("POST", "/api/auth/login", null, null, "{\"username\":\"admin\",\"password\":\"nope\"}").status());

        Resp ok = call("POST", "/api/auth/login", null, null, "{\"username\":\"analyst1\",\"password\":\"Analyst@123\"}");
        assertEquals(200, ok.status());
        assertFalse(ok.body().contains("passwordHash"));
        String analyst = (String) ok.map().get("token");
        assertEquals("analyst", Json.asMap(get("/api/auth/me", analyst).map()).get("role"));

        // sensors need the key; strangers are refused
        assertEquals(401, call("POST", "/events", null, null, "{\"sourceIp\":\"1.2.3.4\",\"eventType\":\"sqli\"}").status());
        assertEquals(401, call("POST", "/events", null, "wrong-key", "{\"sourceIp\":\"1.2.3.4\",\"eventType\":\"sqli\"}").status());
        assertEquals(400, call("POST", "/events", null, "dev-ingest-key", "{\"eventType\":\"sqli\"}").status());

        // users: no hashes ever, admin-only creation
        Resp users = get("/users", analyst);
        assertEquals(200, users.status());
        assertFalse(users.body().contains("password"), "user list must not expose password data");
        String newUser = "{\"username\":\"student1\",\"email\":\"student1@example.com\",\"password\":\"Student@1234\",\"role\":\"analyst\"}";
        assertEquals(403, call("POST", "/users", analyst, null, newUser).status());
        String admin = admin();
        assertEquals(200, call("POST", "/users", admin, null, newUser).status());
        assertEquals(409, call("POST", "/users", admin, null, newUser).status());
        assertEquals(400, call("POST", "/users", admin, null, newUser.replace("Student@1234", "short")).status());
        login("student1", "Student@1234");

        // lock-out after 5 wrong passwords
        for (int i = 0; i < 5; i++) {
            assertEquals(401, call("POST", "/api/auth/login", null, null, "{\"username\":\"ghost\",\"password\":\"x" + i + "\"}").status());
        }
        assertEquals(429, call("POST", "/api/auth/login", null, null, "{\"username\":\"ghost\",\"password\":\"x\"}").status());

        // the old unauthenticated write paths are closed
        assertEquals(403, call("POST", "/incidents", analyst, null, "{\"severity\":\"LOW\",\"riskScore\":1}").status());
    }

    @Test
    void t02_criticalIncident_fullLifecycle() throws Exception {
        String ip = "198.51.100.7";
        sendEvent(ip, "sqli");
        String analyst = analyst(), manager = manager(), admin = admin();

        int id = incidentId(await("incident for " + ip, () -> {
            try {
                List<Map<String, Object>> l = incidentsFor(ip, analyst);
                return l.isEmpty() ? null : l.get(0);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }));
        Map<String, Object> d = awaitPlan(id, analyst);
        Map<String, Object> inc = Json.asMap(d.get("incident"));
        assertEquals("CRITICAL", inc.get("severity"));
        assertEquals("AWAITING_APPROVAL", inc.get("status"));
        assertTrue(((Number) inc.get("riskScore")).intValue() >= 90);
        assertTrue(((String) inc.get("riskFactors")).contains("Detection rule baseline"));
        Map<String, Object> report = Json.asMap(d.get("report"));
        assertEquals(50, ((String) report.get("classification")).length(), "classification must fit VARCHAR(50)");
        assertEquals("T1190", Json.asMap(d.get("mapping")).get("mitreId"));

        // four-eyes: an analyst cannot decide a CRITICAL incident, and the UI is told why
        int planId = ((Number) Json.asMap(d.get("plan")).get("planId")).intValue();
        Map<String, Object> perms = Json.asMap(d.get("permissions"));
        assertEquals(Boolean.FALSE, perms.get("canDecide"));
        assertTrue(String.valueOf(perms.get("decideReason")).contains("manager"));
        Resp denied = post("/remediation-plans/" + planId + "/approve", analyst);
        assertEquals(403, denied.status());
        assertTrue(denied.body().contains("SOC manager"), denied.body());

        // the manager approves; the analyst may not run the recovery
        assertEquals(200, post("/remediation-plans/" + planId + "/approve", manager).status());
        assertEquals(409, post("/remediation-plans/" + planId + "/approve", manager).status());
        assertEquals(403, post("/remediation-plans/" + planId + "/execute", analyst).status());
        assertEquals(200, post("/remediation-plans/" + planId + "/execute", manager).status());

        Map<String, Object> after = detail(id, admin);
        assertEquals("CLOSED", Json.asMap(after.get("incident")).get("status"));
        @SuppressWarnings("unchecked")
        List<Object> audit = (List<Object>) after.get("audit");
        List<String> actions = new ArrayList<>();
        audit.forEach(a -> actions.add((String) Json.asMap(a).get("action")));
        assertTrue(actions.contains("APPROVE_REMEDIATION") && actions.contains("EXECUTE_REMEDIATION_SIMULATED"), actions.toString());

        // e-mail: "action required" with the PDF attached, recorded as SENT
        await("action-required e-mail", () -> mail.getReceivedMessages().length > 0 ? Boolean.TRUE : null);
        MimeMessage found = null;
        for (MimeMessage m : mail.getReceivedMessages()) {
            if (m.getSubject().contains("incident #" + id)) {
                found = m;
            }
        }
        assertNotNull(found, "no e-mail about incident " + id);
        assertTrue(found.getContent() instanceof MimeMultipart);
        String raw = new String(found.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        assertTrue(raw.contains("incident-" + id + "-report.pdf"), "PDF attachment missing");
        await("notification recorded as SENT", () -> {
            try {
                Object n = detail(id, admin).get("notifications");
                return n instanceof List<?> l && !l.isEmpty() && "SENT".equals(Json.asMap(l.get(0)).get("status")) ? Boolean.TRUE : null;
            } catch (Exception e) { throw new RuntimeException(e); }
        });

        // the PDF report
        Resp pdf = get("/api/incidents/" + id + "/report.pdf", manager);
        assertEquals(200, pdf.status());
        assertTrue(new String(pdf.bytes(), 0, 5, StandardCharsets.ISO_8859_1).equals("%PDF-"));
        assertTrue(pdf.bytes().length > 3000);
        Files.createDirectories(Path.of("target/it"));
        Files.write(Path.of("target/it/incident-" + id + "-report.pdf"), pdf.bytes());

        // metrics now have data
        Map<String, Object> stats = get("/api/stats", analyst).map();
        assertNotNull(stats.get("mttrSeconds"));
        assertEquals(100.0, ((Number) stats.get("approvalRatePct")).doubleValue());
        assertNotNull(stats.get("avgAiSeconds"));
        assertTrue(((Number) stats.get("alertsSent")).intValue() >= 1);
    }

    @Test
    void t03_bruteForce_oneIncidentPerBurst() throws Exception {
        String ip = "192.0.2.55";
        for (int i = 0; i < 6; i++) {
            sendEvent(ip, "brute_force");
        }
        String analyst = analyst();
        await("incident", () -> {
            try { return incidentsFor(ip, analyst).isEmpty() ? null : Boolean.TRUE; } catch (Exception e) { throw new RuntimeException(e); }
        });
        Thread.sleep(500);
        List<Map<String, Object>> list = incidentsFor(ip, analyst);
        assertEquals(1, list.size(), "events beyond the threshold must not spawn extra incidents");
        assertEquals("HIGH", list.get(0).get("severity"));
    }

    @Test
    void t04_multiStageAttackChain() throws Exception {
        String ip = "203.0.113.99";
        String analyst = analyst(), manager = manager();
        for (int i = 0; i < 5; i++) {
            sendEvent(ip, "port_scan");
        }
        sendEvent(ip, "brute_force");
        sendEvent(ip, "brute_force");
        sendEvent(ip, "brute_force");
        sendEvent(ip, "sqli");

        List<Map<String, Object>> list = await("3 incidents", () -> {
            try {
                List<Map<String, Object>> l = incidentsFor(ip, analyst);
                return l.size() >= 3 ? l : null;
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        assertEquals(3, list.size());
        Object chainId = list.get(0).get("chainId");
        assertNotNull(chainId, "incidents should be linked into a chain");
        for (Map<String, Object> m : list) {
            assertEquals(chainId, m.get("chainId"));
        }

        List<Map<String, Object>> chains = new ArrayList<>();
        for (Object o : get("/api/chains", analyst).list()) {
            Map<String, Object> c = Json.asMap(o);
            if (ip.equals(c.get("sourceIp"))) {
                chains.add(c);
            }
        }
        assertEquals(1, chains.size());
        Map<String, Object> chain = chains.get(0);
        assertEquals(3, ((Number) chain.get("stages")).intValue());
        assertTrue(String.valueOf(chain.get("description")).startsWith("Reconnaissance → Credential Access → Initial Access from " + ip),
            String.valueOf(chain.get("description")));
        assertEquals(3, ((List<?>) chain.get("members")).size());

        // the SQL-injection incident is the newest: chain progression must appear in its risk factors
        Map<String, Object> sqli = list.stream().filter(m -> "sqli".equals(m.get("eventType"))).findFirst().orElseThrow();
        Map<String, Object> d = detail(incidentId(sqli), analyst);
        String factors = (String) Json.asMap(d.get("incident")).get("riskFactors");
        assertTrue(factors.contains("Attack chain progression"), factors);
        assertNotNull(d.get("chain"));

        // the AI was told about the chain
        await("chain context sent to the AI", () -> agentRequests.stream().anyMatch(b -> b.contains("\"chain\"") && b.contains(ip)) ? Boolean.TRUE : null);
        // and the senior staff got a multi-stage alert
        await("chain alert e-mail", () -> {
            for (MimeMessage m : mail.getReceivedMessages()) {
                try { if (m.getSubject().contains("Multi-stage attack detected from " + ip)) return Boolean.TRUE; } catch (Exception e) { return null; }
            }
            return null;
        });
        assertEquals(200, get("/api/incidents/" + incidentId(sqli) + "/report.pdf", manager).status());
    }

    @Test
    void t05_riskScoring_contextOnlyRaisesSeverity() {
        SecurityEvent e = new SecurityEvent();
        e.setSourceIp("10.77.77.77");
        e.setEventType("port_scan");
        LocalDateTime noon = LocalDateTime.now().withHour(12).withMinute(0);

        var plain = riskScoring.score(e, "MEDIUM", 50, 5, 5, 1, noon);
        assertEquals(50, plain.score());
        assertEquals("MEDIUM", plain.severity());
        assertFalse(plain.escalated());

        var chained = riskScoring.score(e, "MEDIUM", 50, 5, 5, 4, noon);       // +24 chain progression
        assertEquals(74, chained.score());
        assertEquals("HIGH", chained.severity());
        assertTrue(chained.escalated());

        var night = riskScoring.score(e, "CRITICAL", 95, 1, 0, 3, noon.withHour(23));   // 95 + 16 + 5 -> capped
        assertEquals(100, night.score());
        assertEquals("CRITICAL", night.severity());
        assertTrue(night.factorsJson().contains("Off-hours activity"));

        var burst = riskScoring.score(e, "HIGH", 70, 12, 3, 1, noon);          // +6 cap
        assertEquals(76, burst.score());
        assertEquals("HIGH", burst.severity());
    }

    @Test
    void t06_aiFailure_isVisibleAndRetryable() throws Exception {
        String ip = "198.18.0.1";
        String analyst = analyst();
        agentFails = true;
        try {
            sendEvent(ip, "malware");
            int id = incidentId(await("incident", () -> {
                try { List<Map<String, Object>> l = incidentsFor(ip, analyst); return l.isEmpty() ? null : l.get(0); }
                catch (Exception e) { throw new RuntimeException(e); }
            }));
            Map<String, Object> d = await("AI failure recorded", () -> {
                try {
                    Map<String, Object> x = detail(id, analyst);
                    return Json.asMap(x.get("ai")).get("error") != null ? x : null;
                } catch (Exception e) { throw new RuntimeException(e); }
            });
            assertEquals("OPEN", Json.asMap(d.get("incident")).get("status"));
            assertTrue(String.valueOf(Json.asMap(d.get("ai")).get("error")).contains("500"));
            assertNotNull(d.get("permissions"));
            agentFails = false;

            Resp re = post("/api/incidents/" + id + "/reinvestigate", analyst);
            assertEquals(200, re.status(), re.body());
            Map<String, Object> ok = awaitPlan(id, analyst);
            assertEquals("AWAITING_APPROVAL", Json.asMap(ok.get("incident")).get("status"));
        } finally {
            agentFails = false;
        }
    }

    @Test
    void t07_rejectWithReason_thenReanalyse() throws Exception {
        String ip = "192.0.2.200";
        String analyst = analyst();
        for (int i = 0; i < 3; i++) {
            sendEvent(ip, "brute_force");
        }
        int id = incidentId(await("incident", () -> {
            try { List<Map<String, Object>> l = incidentsFor(ip, analyst); return l.isEmpty() ? null : l.get(0); }
            catch (Exception e) { throw new RuntimeException(e); }
        }));
        Map<String, Object> d = awaitPlan(id, analyst);
        int plan1 = ((Number) Json.asMap(d.get("plan")).get("planId")).intValue();
        assertEquals(Boolean.TRUE, Json.asMap(d.get("permissions")).get("canDecide"), "HIGH incidents may be decided by an analyst");

        Resp rej = post("/remediation-plans/" + plan1 + "/reject?reason=Too%20disruptive%20for%20production", analyst);
        assertEquals(200, rej.status(), rej.body());
        Map<String, Object> after = detail(id, analyst);
        assertEquals("OPEN", Json.asMap(after.get("incident")).get("status"));
        String audit = String.valueOf(after.get("audit"));
        assertTrue(audit.contains("Too disruptive for production"), audit);

        assertEquals(200, post("/api/incidents/" + id + "/reinvestigate", analyst).status());
        Map<String, Object> again = await("new plan", () -> {
            try {
                Map<String, Object> x = detail(id, analyst);
                Object p = Json.asMap(x.get("plan")).get("planId");
                return p != null && ((Number) p).intValue() != plan1 ? x : null;
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        assertEquals("PENDING", Json.asMap(again.get("plan")).get("status"));
    }

    @Test
    void t08_simulateAndAdminOnlyActions() throws Exception {
        String analyst = analyst(), admin = admin();
        Resp sim = post("/api/simulate?type=malware&ip=198.51.100.222", analyst);
        assertEquals(200, sim.status(), sim.body());
        assertFalse(((List<?>) sim.map().get("incidentIds")).isEmpty());
        assertEquals(400, post("/api/simulate?type=nonsense", analyst).status());
        assertEquals(400, post("/api/simulate?type=sqli&ip=%3Cscript%3E", analyst).status());

        assertEquals(403, post("/api/rag/reindex", analyst).status());
        Resp re = post("/api/rag/reindex", admin);
        assertEquals(200, re.status(), re.body());     // embeddings are unavailable in this test: it must report, not crash
        assertNotNull(re.map().get("failed"));

        // everything above is in the audit trail
        String audit = get("/api/audit", admin).body();
        assertTrue(audit.contains("SIMULATE_ATTACK") && audit.contains("RAG_REINDEX") && audit.contains("CREATE_USER")
            && audit.contains("LOGIN_FAILED"), "audit trail incomplete");
    }
}
