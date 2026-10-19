package com.socgpt.backend.service;

import org.springframework.stereotype.Service;

import com.socgpt.backend.model.AuditLog;
import com.socgpt.backend.repository.AuditLogRepository;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void log(Integer userId, String action, String targetType,
                    Integer targetId, String details) {
        AuditLog entry = new AuditLog();
        entry.setUserId(userId);
        entry.setAction(action);
        entry.setTargetType(targetType);
        entry.setTargetId(targetId);
        entry.setDetails(details);
        auditLogRepository.save(entry);

        System.out.println("[AUDIT] user " + userId + " -> " + action
            + " on " + targetType + " #" + targetId);
    }
}