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
@Table(name = "investigation_reports")
public class InvestigationReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "report_id")
    private Integer reportId;

    @Column(name = "incident_id")
    private Integer incidentId;

    @Column(name = "summary")
    private String summary;

    @Column(name = "evidence")
    private String evidence;

    @Column(name = "classification")
    private String classification;

    @Column(name = "confidence")
    private Double confidence;

    @Column(name = "impact")
    private String impact;

    @Column(name = "generated_at")
    private LocalDateTime generatedAt;

    @PrePersist
    public void setDefaults() {
        if (generatedAt == null) {
            generatedAt = LocalDateTime.now();
        }
    }

    public Integer getReportId() { return reportId; }
    public void setReportId(Integer reportId) { this.reportId = reportId; }
    public Integer getIncidentId() { return incidentId; }
    public void setIncidentId(Integer incidentId) { this.incidentId = incidentId; }
    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }
    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }
    public String getClassification() { return classification; }
    public void setClassification(String classification) { this.classification = classification; }
    public Double getConfidence() { return confidence; }
    public void setConfidence(Double confidence) { this.confidence = confidence; }
    public String getImpact() { return impact; }
    public void setImpact(String impact) { this.impact = impact; }
    public LocalDateTime getGeneratedAt() { return generatedAt; }
    public void setGeneratedAt(LocalDateTime generatedAt) { this.generatedAt = generatedAt; }
}