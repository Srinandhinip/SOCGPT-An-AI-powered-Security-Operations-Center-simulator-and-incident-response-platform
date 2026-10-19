package com.socgpt.backend.controller;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

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
import com.socgpt.backend.security.RequiresRole;
import com.socgpt.backend.service.AuditService;

/** Users are never returned with their password hash. Creating users is admin-only. */
@RestController
@RequestMapping("/users")
public class UserController {

    private static final Set<String> ROLES = Set.of("analyst", "soc_manager", "admin");
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_.-]{3,50}");
    private static final Pattern EMAIL = Pattern.compile("[^@\\s]+@[^@\\s]+\\.[^@\\s]+");

    private final UserRepository userRepository;
    private final PasswordService passwords;
    private final AuditService audit;

    public UserController(UserRepository userRepository, PasswordService passwords, AuditService audit) {
        this.userRepository = userRepository;
        this.passwords = passwords;
        this.audit = audit;
    }

    @GetMapping
    public List<Map<String, Object>> getAllUsers() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (User u : userRepository.findAll()) {
            out.add(view(u));
        }
        return out;
    }

    /** Body: {username, email, password, role}. */
    @PostMapping
    @RequiresRole("admin")
    public Map<String, Object> createUser(@RequestBody Map<String, String> body,
                                          @RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser admin) {
        String username = trim(body.get("username"));
        String email = trim(body.get("email"));
        String password = body.get("password");
        String role = trim(body.get("role"));

        if (username == null || !USERNAME.matcher(username).matches()) {
            throw bad("Username must be 3 to 50 characters: letters, digits, dot, dash or underscore.");
        }
        if (email == null || email.length() > 120 || !EMAIL.matcher(email).matches()) {
            throw bad("Enter a valid e-mail address.");
        }
        if (password == null || password.length() < 8) {
            throw bad("The password must be at least 8 characters.");
        }
        if (role == null || !ROLES.contains(role)) {
            throw bad("Role must be one of: analyst, soc_manager, admin.");
        }
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "That username is already taken.");
        }
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "That e-mail address is already used.");
        }

        User u = new User();
        u.setUsername(username);
        u.setEmail(email);
        u.setRole(role);
        u.setPasswordHash(passwords.hash(password));
        User saved = userRepository.save(u);
        audit.log(admin.userId(), "CREATE_USER", "user", saved.getUserId(),
            "Created user '" + username + "' with role " + role);
        return view(saved);
    }

    private static Map<String, Object> view(User u) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("userId", u.getUserId());
        m.put("username", u.getUsername());
        m.put("email", u.getEmail());
        m.put("role", u.getRole());
        m.put("createdAt", u.getCreatedAt());
        return m;
    }

    private static String trim(String s) {
        return s == null ? null : s.trim();
    }

    private static ResponseStatusException bad(String msg) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, msg);
    }
}
