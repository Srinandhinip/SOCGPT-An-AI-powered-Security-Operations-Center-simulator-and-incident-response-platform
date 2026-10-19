package com.socgpt.backend.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.socgpt.backend.model.AuditLog;
import com.socgpt.backend.repository.AuditLogRepository;

/** Read-only on purpose: the audit trail is written by the system, never edited through the API. */
@RestController
@RequestMapping("/audit-log")
public class AuditLogController {
    private final AuditLogRepository repo;

    public AuditLogController(AuditLogRepository repo) {
        this.repo = repo;
    }

    @GetMapping
    public List<AuditLog> getAll() {
        return repo.findAll();
    }
}
