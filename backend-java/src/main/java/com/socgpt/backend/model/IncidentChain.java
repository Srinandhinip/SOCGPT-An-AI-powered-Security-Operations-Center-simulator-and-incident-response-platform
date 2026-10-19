package com.socgpt.backend.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "incident_chains")
public class IncidentChain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "chain_id")
    private Integer chainId;

    @Column(name = "description")
    private String description;

    @Column(name = "overall_risk")
    private Integer overallRisk;

    @Column(name = "status")
    private String status;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "stages")
    private Integer stages;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    public void setDefaults() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) {
            createdAt = now;
        }
        if (updatedAt == null) {
            updatedAt = now;
        }
        if (status == null) {
            status = "ACTIVE";
        }
        if (stages == null) {
            stages = 1;
        }
    }

    @PreUpdate
    public void touch() {
        updatedAt = LocalDateTime.now();
    }

    public Integer getChainId() { return chainId; }
    public void setChainId(Integer chainId) { this.chainId = chainId; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public Integer getOverallRisk() { return overallRisk; }
    public void setOverallRisk(Integer overallRisk) { this.overallRisk = overallRisk; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public Integer getStages() { return stages; }
    public void setStages(Integer stages) { this.stages = stages; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
}
