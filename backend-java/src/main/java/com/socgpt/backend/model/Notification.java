package com.socgpt.backend.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "notifications")
public class Notification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "notification_id")
    private Integer notificationId;

    @Column(name = "incident_id")
    private Integer incidentId;

    @Column(name = "channel")
    private String channel;

    @Column(name = "recipient")
    private String recipient;

    @Column(name = "sent_at")
    private LocalDateTime sentAt;

    @Column(name = "status")
    private String status;

    @Column(name = "subject")
    private String subject;

    @Column(name = "error")
    private String error;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    public void setDefaults() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (channel == null) {
            channel = "email";
        }
        if (status == null) {
            status = "PENDING";
        }
    }

    public Integer getNotificationId() { return notificationId; }
    public void setNotificationId(Integer notificationId) { this.notificationId = notificationId; }
    public Integer getIncidentId() { return incidentId; }
    public void setIncidentId(Integer incidentId) { this.incidentId = incidentId; }
    public String getChannel() { return channel; }
    public void setChannel(String channel) { this.channel = channel; }
    public String getRecipient() { return recipient; }
    public void setRecipient(String recipient) { this.recipient = recipient; }
    public LocalDateTime getSentAt() { return sentAt; }
    public void setSentAt(LocalDateTime sentAt) { this.sentAt = sentAt; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
