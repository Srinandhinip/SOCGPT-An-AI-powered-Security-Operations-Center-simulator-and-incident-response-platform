package com.socgpt.backend.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import com.socgpt.backend.model.User;
import com.socgpt.backend.repository.UserRepository;
import com.socgpt.backend.util.Json;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The gatekeeper: runs before every controller method.
 *  - the login endpoint is open
 *  - sensors may POST /events with the X-Ingest-Key header
 *  - everything else needs "Authorization: Bearer <token>"
 *  - @RequiresRole decides who may call a method; unannotated writes are admin-only
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    public static final String USER_ATTR = "socgpt.user";

    private final TokenService tokens;
    private final UserRepository users;
    private final String ingestKey;

    public AuthInterceptor(TokenService tokens, UserRepository users,
                           @Value("${socgpt.ingest.key:dev-ingest-key}") String ingestKey) {
        this.tokens = tokens;
        this.users = users;
        this.ingestKey = ingestKey;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (!(handler instanceof HandlerMethod hm)) {
            return true;   // static files (the pages themselves contain no data)
        }
        String method = request.getMethod();
        String path = request.getRequestURI();
        if ("OPTIONS".equals(method) || "/api/auth/login".equals(path)) {
            return true;
        }
        if ("POST".equals(method) && "/events".equals(path) && validIngestKey(request.getHeader("X-Ingest-Key"))) {
            return true;
        }

        AuthUser user = authenticate(request);
        if (user == null) {
            return deny(response, 401, "Unauthorized", "Please sign in to continue.");
        }
        request.setAttribute(USER_ATTR, user);

        RequiresRole rule = hm.getMethodAnnotation(RequiresRole.class);
        if (rule == null) {
            rule = hm.getBeanType().getAnnotation(RequiresRole.class);
        }
        if (rule != null) {
            if (!user.hasAnyRole(rule.value())) {
                return deny(response, 403, "Forbidden", "Your role (" + user.role()
                    + ") cannot do this. It needs: " + String.join(" or ", rule.value()) + ".");
            }
        } else if (!isReadOnly(method) && !user.isAdmin()) {
            return deny(response, 403, "Forbidden", "Only an admin can change this resource.");
        }
        return true;
    }

    private AuthUser authenticate(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        return tokens.verify(header.substring(7).trim())
            .flatMap(users::findById)
            .map(AuthInterceptor::toAuthUser)
            .orElse(null);
    }

    public static AuthUser toAuthUser(User u) {
        return new AuthUser(u.getUserId(), u.getUsername(), u.getRole(), u.getEmail());
    }

    private boolean validIngestKey(String supplied) {
        return supplied != null && MessageDigest.isEqual(
            supplied.getBytes(StandardCharsets.UTF_8), ingestKey.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean isReadOnly(String method) {
        return "GET".equals(method) || "HEAD".equals(method);
    }

    private static boolean deny(HttpServletResponse response, int status, String error, String message)
            throws java.io.IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"status\":" + status + ",\"error\":" + Json.quote(error)
            + ",\"message\":" + Json.quote(message) + "}");
        return false;
    }
}
