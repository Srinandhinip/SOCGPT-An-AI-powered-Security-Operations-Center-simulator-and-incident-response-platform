package com.socgpt.backend.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.socgpt.backend.model.Notification;

public interface NotificationRepository extends JpaRepository<Notification, Integer> {
    List<Notification> findByIncidentIdOrderByNotificationIdAsc(Integer incidentId);

    long countByStatus(String status);
}
