package com.socgpt.backend.repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.socgpt.backend.model.AuditLog;

public interface AuditLogRepository extends JpaRepository<AuditLog, Integer> {
    List<AuditLog> findByTargetTypeAndTargetIdInOrderByLogIdAsc(String targetType, Collection<Integer> targetIds);

    List<AuditLog> findTop500ByOrderByLogIdDesc();

    List<AuditLog> findByActionAndCreatedAtAfter(String action, LocalDateTime after);

    List<AuditLog> findByActionOrderByLogIdAsc(String action);

    long countByActionAndUserIdAndCreatedAtAfter(String action, Integer userId, LocalDateTime after);
}
