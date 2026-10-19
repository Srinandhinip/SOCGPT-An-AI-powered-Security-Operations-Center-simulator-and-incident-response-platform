package com.socgpt.backend.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import com.socgpt.backend.model.User;
import com.socgpt.backend.repository.UserRepository;

/**
 * Creates the demo accounts on start-up if they are missing (or still hold an old plain-text password).
 * Turn off with socgpt.seed-demo-users=false and create real users through POST /users instead.
 */
@Component
public class DataInitializer implements ApplicationRunner {

    private record Demo(String username, String password, String role, String email) { }

    private static final Demo[] DEMOS = {
        new Demo("admin", "Admin@123", "admin", "admin@socgpt.com"),
        new Demo("manager1", "Manager@123", "soc_manager", "manager1@socgpt.com"),
        new Demo("analyst1", "Analyst@123", "analyst", "analyst1@socgpt.com"),
    };

    private final UserRepository users;
    private final PasswordService passwords;
    private final boolean seed;

    public DataInitializer(UserRepository users, PasswordService passwords,
                           @Value("${socgpt.seed-demo-users:true}") boolean seed) {
        this.users = users;
        this.passwords = passwords;
        this.seed = seed;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!seed) {
            return;
        }
        for (Demo d : DEMOS) {
            User u = users.findByUsername(d.username()).orElse(null);
            if (u == null) {
                u = new User();
                u.setUsername(d.username());
                u.setEmail(users.existsByEmailIgnoreCase(d.email()) ? d.username() + "@socgpt.local" : d.email());
                u.setRole(d.role());
                u.setPasswordHash(passwords.hash(d.password()));
                users.save(u);
                System.out.println("[AUTH] Created demo account '" + d.username() + "' (" + d.role() + ")");
            } else if (!passwords.isHashed(u.getPasswordHash())) {
                u.setPasswordHash(passwords.hash(d.password()));
                users.save(u);
                System.out.println("[AUTH] Upgraded the old plain-text password of '" + d.username() + "' to the demo password");
            }
        }
    }
}
