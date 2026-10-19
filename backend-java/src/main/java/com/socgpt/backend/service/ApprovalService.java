package com.socgpt.backend.service;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.RemediationPlan;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.RemediationPlanRepository;
import com.socgpt.backend.security.AccessPolicy;
import com.socgpt.backend.security.AuthUser;

/**
 * The human gate. Nothing the AI proposes runs until a person with the right role approves it,
 * and every decision is written to the audit log.
 */
@Service
public class ApprovalService {

    private final RemediationPlanRepository planRepository;
    private final IncidentRepository incidentRepository;
    private final AuditService auditService;

    public ApprovalService(RemediationPlanRepository planRepository,
                           IncidentRepository incidentRepository,
                           AuditService auditService) {
        this.planRepository = planRepository;
        this.incidentRepository = incidentRepository;
        this.auditService = auditService;
    }

    /** Approves a PENDING plan. */
    @Transactional
    public RemediationPlan approve(Integer planId, AuthUser user) {
        RemediationPlan plan = loadPlan(planId, "PENDING", "approve");
        requireDecide(user, plan);

        plan.setStatus("APPROVED");
        plan.setApprovedBy(user.userId());
        plan.setApprovedAt(LocalDateTime.now());
        RemediationPlan saved = planRepository.save(plan);

        setIncidentStatus(plan.getIncidentId(), "REMEDIATED");
        auditService.log(user.userId(), "APPROVE_REMEDIATION", "remediation_plan", planId,
            "Approved plan for incident " + plan.getIncidentId());
        return saved;
    }

    /** Rejects a PENDING plan; the incident goes back to OPEN so the AI can try again. */
    @Transactional
    public RemediationPlan reject(Integer planId, AuthUser user, String reason) {
        RemediationPlan plan = loadPlan(planId, "PENDING", "reject");
        requireDecide(user, plan);

        plan.setStatus("REJECTED");
        RemediationPlan saved = planRepository.save(plan);

        setIncidentStatus(plan.getIncidentId(), "OPEN");
        String cleanReason = reason == null ? null : reason.trim();
        auditService.log(user.userId(), "REJECT_REMEDIATION", "remediation_plan", planId,
            "Rejected plan for incident " + plan.getIncidentId()
                + (cleanReason == null || cleanReason.isEmpty() ? "" : ". Reason: " + cleanReason));
        return saved;
    }

    /** Simulated recovery: only an APPROVED plan can be executed. Closes the incident. */
    @Transactional
    public RemediationPlan execute(Integer planId, AuthUser user) {
        RemediationPlan plan = loadPlan(planId, "APPROVED", "execute");
        AccessPolicy.Decision d = AccessPolicy.canExecute(user);
        if (!d.allowed()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, d.reason());
        }

        plan.setStatus("EXECUTED");
        RemediationPlan saved = planRepository.save(plan);

        setIncidentStatus(plan.getIncidentId(), "CLOSED");
        auditService.log(user.userId(), "EXECUTE_REMEDIATION_SIMULATED", "remediation_plan", planId,
            "Simulated recovery completed for incident " + plan.getIncidentId());
        System.out.println("[RECOVERY] Incident " + plan.getIncidentId()
            + ": remediation plan executed (simulated), incident closed.");
        return saved;
    }

    // ---------- helpers ----------

    private void requireDecide(AuthUser user, RemediationPlan plan) {
        Incident incident = plan.getIncidentId() == null ? null
            : incidentRepository.findById(plan.getIncidentId()).orElse(null);
        AccessPolicy.Decision d = AccessPolicy.canDecide(user, incident == null ? null : incident.getSeverity());
        if (!d.allowed()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, d.reason());
        }
    }

    private RemediationPlan loadPlan(Integer planId, String requiredStatus, String verb) {
        RemediationPlan plan = planRepository.findById(planId).orElseThrow(() ->
            new ResponseStatusException(HttpStatus.NOT_FOUND, "Plan " + planId + " not found"));

        if (!requiredStatus.equals(plan.getStatus())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                "Cannot " + verb + " plan " + planId + ": its status is "
                    + plan.getStatus() + " but it must be " + requiredStatus);
        }
        return plan;
    }

    private void setIncidentStatus(Integer incidentId, String status) {
        if (incidentId == null) {
            return;
        }
        incidentRepository.findById(incidentId).ifPresent(incident -> {
            incident.setStatus(status);
            incidentRepository.save(incident);
        });
    }
}
