package com.socgpt.backend.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "event_id")
    private Integer eventId;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "event_type")
    private String eventType;

    @Column(name = "mitre_id")
    private String mitreId;

    @Column(name = "stage_order")
    private Integer stageOrder;

    @Column(name = "detected_at")
    private LocalDateTime detectedAt;

    @PrePersist
    public void setDefaults() {
        if (detectedAt == null) {
            detectedAt = LocalDateTime.now();
        }
    }

    // Getters and setters
    public Integer getEventId() { return eventId; }
    public void setEventId(Integer eventId) { this.eventId = eventId; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }

    public String getMitreId() { return mitreId; }
    public void setMitreId(String mitreId) { this.mitreId = mitreId; }

    public Integer getStageOrder() { return stageOrder; }
    public void setStageOrder(Integer stageOrder) { this.stageOrder = stageOrder; }

    public LocalDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(LocalDateTime detectedAt) { this.detectedAt = detectedAt; }
}