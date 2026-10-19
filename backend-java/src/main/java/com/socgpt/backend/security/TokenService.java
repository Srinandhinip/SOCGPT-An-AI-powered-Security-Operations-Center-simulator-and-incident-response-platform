package com.socgpt.backend.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Signed login tokens (a tiny JWT-style design using HMAC-SHA256 from the JDK).
 * Token = base64url("userId|expiresAtEpochSeconds") + "." + base64url(HMAC of the first part).
 * Stateless: nothing is stored, so tokens survive server restarts as long as the secret is unchanged.
 * Only the user id is inside the token; the role is always looked up fresh from the database.
 */
@Service
public class TokenService {

    private static final String DEFAULT_SECRET = "dev-only-secret-change-me-before-sharing-this-project";

    private final byte[] secret;
    private final long ttlSeconds;

    public TokenService(@Value("${socgpt.auth.secret:" + DEFAULT_SECRET + "}") String secret,
                        @Value("${socgpt.auth.token-hours:8}") long tokenHours) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.ttlSeconds = tokenHours * 3600;
        if (DEFAULT_SECRET.equals(secret)) {
            System.out.println("[AUTH] WARNING: using the default token secret. Set socgpt.auth.secret in "
                + "application.properties before sharing or deploying this project.");
        }
    }

    public long ttlSeconds() {
        return ttlSeconds;
    }

    public String issue(Integer userId) {
        return issue(userId, Instant.now().getEpochSecond() + ttlSeconds);
    }

    String issue(Integer userId, long expiresAtEpochSeconds) {
        String payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString((userId + "|" + expiresAtEpochSeconds).getBytes(StandardCharsets.UTF_8));
        return payload + "." + sign(payload);
    }

    /** Returns the user id if the signature is valid and the token has not expired. */
    public Optional<Integer> verify(String token) {
        if (token == null) {
            return Optional.empty();
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1) {
            return Optional.empty();
        }
        String payload = token.substring(0, dot);
        String signature = token.substring(dot + 1);
        if (!MessageDigest.isEqual(sign(payload).getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8))) {
            return Optional.empty();
        }
        try {
            String[] parts = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8).split("\\|");
            if (parts.length != 2 || Long.parseLong(parts[1]) < Instant.now().getEpochSecond()) {
                return Optional.empty();
            }
            return Optional.of(Integer.valueOf(parts[0]));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private String sign(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is not available", e);
        }
    }
}
