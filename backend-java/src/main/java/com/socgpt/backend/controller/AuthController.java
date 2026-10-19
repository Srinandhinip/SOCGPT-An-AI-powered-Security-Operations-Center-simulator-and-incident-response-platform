package com.socgpt.backend.controller;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.socgpt.backend.model.User;
import com.socgpt.backend.repository.UserRepository;
import com.socgpt.backend.security.AuthInterceptor;
import com.socgpt.backend.security.AuthUser;
import com.socgpt.backend.security.PasswordService;
import com.socgpt.backend.security.TokenService;
import com.socgpt.backend.service.AuditService;

/** Sign-in. The only API endpoint that does not need a token. */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final int MAX_FAILURES = 5;
    private static final long WINDOW_MS = 5 * 60_000L;

    private final UserRepository users;
    private final PasswordService passwords;
    private final TokenService tokens;
    private final AuditService audit;
    // checked against when the username does not exist, so "unknown user" and "wrong password" take equally long
    private final String dummyHash;
    private final Map<String, Deque<Long>> failures = new ConcurrentHashMap<>();

    public AuthController(UserRepository users, PasswordService passwords, TokenService tokens, AuditService audit) {
        this.users = users;
        this.passwords = passwords;
        this.tokens = tokens;
        this.audit = audit;
        this.dummyHash = passwords.hash("not-a-real-password");
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> body) {
        String username = body == null ? null : body.get("username");
        String password = body == null ? null : body.get("password");
        if (username == null || username.isBlank() || password == null || password.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Enter your username and password.");
        }
        username = username.trim();
        String key = username.toLowerCase();

        long waitSeconds = lockedForSeconds(key);
        if (waitSeconds > 0) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                "Too many failed attempts. Try again in " + ((waitSeconds + 59) / 60) + " minute(s).");
        }

        User user = users.findByUsername(username).orElse(null);
        boolean ok;
        if (user != null) {
            ok = passwords.verify(password, user.getPasswordHash());
        } else {
            passwords.verify(password, dummyHash);
            ok = false;
        }
        if (!ok) {
            recordFailure(key);
            audit.log(user == null ? null : user.getUserId(), "LOGIN_FAILED", "user",
                user == null ? null : user.getUserId(), "Failed sign-in for username '" + cut(username, 50) + "'");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password.");
        }

        failures.remove(key);
        if (!passwords.isHashed(user.getPasswordHash())) {      // upgrade an old plain-text row
            user.setPasswordHash(passwords.hash(password));
            users.save(user);
        }
        audit.log(user.getUserId(), "LOGIN", "user", user.getUserId(), "Signed in");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("token", tokens.issue(user.getUserId()));
        out.put("expiresAt", Instant.now().plusSeconds(tokens.ttlSeconds()).toString());
        out.put("user", userView(AuthInterceptor.toAuthUser(user)));
        return out;
    }

    @GetMapping("/me")
    public Map<String, Object> me(@RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser user) {
        return userView(user);
    }

    private static Map<String, Object> userView(AuthUser u) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("userId", u.userId());
        m.put("username", u.username());
        m.put("role", u.role());
        m.put("email", u.email());
        return m;
    }

    private long lockedForSeconds(String key) {
        Deque<Long> q = failures.get(key);
        if (q == null) {
            return 0;
        }
        synchronized (q) {
            long now = System.currentTimeMillis();
            while (!q.isEmpty() && now - q.peekFirst() > WINDOW_MS) {
                q.pollFirst();
            }
            if (q.size() >= MAX_FAILURES) {
                return Math.max(1, (q.peekFirst() + WINDOW_MS - now) / 1000);
            }
            return 0;
        }
    }

    private void recordFailure(String key) {
        Deque<Long> q = failures.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (q) {
            q.addLast(System.currentTimeMillis());
        }
    }

    private static String cut(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n);
    }
}
