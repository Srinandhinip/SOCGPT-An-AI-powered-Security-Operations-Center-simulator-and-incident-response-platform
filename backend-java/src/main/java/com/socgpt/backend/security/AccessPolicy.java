package com.socgpt.backend.security;

/**
 * The business rules about who may decide what. Kept in one place so the API
 * (which enforces them) and the screen (which explains them) always agree.
 */
public final class AccessPolicy {
    private AccessPolicy() { }

    public record Decision(boolean allowed, String reason) {
        static Decision yes() { return new Decision(true, null); }
        static Decision no(String why) { return new Decision(false, why); }
    }

    /** Approve or reject a remediation plan. */
    public static Decision canDecide(AuthUser user, String incidentSeverity) {
        if (user == null) {
            return Decision.no("Sign in to decide on this plan.");
        }
        if (user.isAdmin() || "soc_manager".equals(user.role())) {
            return Decision.yes();
        }
        if ("analyst".equals(user.role())) {
            if ("CRITICAL".equals(incidentSeverity)) {
                return Decision.no("Critical incidents need a SOC manager's approval (four-eyes rule).");
            }
            return Decision.yes();
        }
        return Decision.no("Your role (" + user.role() + ") cannot decide on plans.");
    }

    /** Run the (simulated) recovery after approval. */
    public static Decision canExecute(AuthUser user) {
        if (user == null) {
            return Decision.no("Sign in to run the recovery.");
        }
        if (user.isAdmin() || "soc_manager".equals(user.role())) {
            return Decision.yes();
        }
        return Decision.no("Only a SOC manager can run the recovery.");
    }
}
