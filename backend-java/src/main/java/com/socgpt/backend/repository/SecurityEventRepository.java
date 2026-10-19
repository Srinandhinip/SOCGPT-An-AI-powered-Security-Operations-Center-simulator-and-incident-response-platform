package com.socgpt.backend.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.socgpt.backend.model.SecurityEvent;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Integer> {

    List<SecurityEvent> findBySourceIpAndEventTypeAndDetectedAtAfter(
        String sourceIp, String eventType, LocalDateTime after
    );

    List<SecurityEvent> findBySourceIpAndDetectedAtAfter(String sourceIp, LocalDateTime after);

    List<SecurityEvent> findTop25ByOrderByEventIdDesc();
}
