package com.socgpt.backend.controller;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.socgpt.backend.model.RemediationPlan;
import com.socgpt.backend.security.AuthInterceptor;
import com.socgpt.backend.security.AuthUser;
import com.socgpt.backend.security.RequiresRole;
import com.socgpt.backend.service.ApprovalService;

/** Who is deciding comes from the signed-in token, never from a request parameter. */
@RestController
@RequestMapping("/remediation-plans")
public class ApprovalController {

    private final ApprovalService approvalService;

    public ApprovalController(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    @PostMapping("/{planId}/approve")
    @RequiresRole({"analyst", "soc_manager"})
    public RemediationPlan approve(@PathVariable Integer planId,
                                   @RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser user) {
        return approvalService.approve(planId, user);
    }

    @PostMapping("/{planId}/reject")
    @RequiresRole({"analyst", "soc_manager"})
    public RemediationPlan reject(@PathVariable Integer planId,
                                  @RequestParam(required = false) String reason,
                                  @RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser user) {
        return approvalService.reject(planId, user, reason);
    }

    @PostMapping("/{planId}/execute")
    @RequiresRole("soc_manager")
    public RemediationPlan execute(@PathVariable Integer planId,
                                   @RequestAttribute(AuthInterceptor.USER_ATTR) AuthUser user) {
        return approvalService.execute(planId, user);
    }
}
