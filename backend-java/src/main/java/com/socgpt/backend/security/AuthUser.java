package com.socgpt.backend.security;

/** The signed-in person making the current request. */
public record AuthUser(Integer userId, String username, String role, String email) {

    public boolean isAdmin() {
        return "admin".equals(role);
    }

    /** Admins are allowed everything; everyone else needs one of the listed roles. */
    public boolean hasAnyRole(String... roles) {
        if (isAdmin()) {
            return true;
        }
        for (String r : roles) {
            if (r.equals(role)) {
                return true;
            }
        }
        return false;
    }
}
