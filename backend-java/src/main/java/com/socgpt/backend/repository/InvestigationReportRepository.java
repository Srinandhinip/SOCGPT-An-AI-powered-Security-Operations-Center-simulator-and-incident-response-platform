package com.socgpt.backend.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.socgpt.backend.model.InvestigationReport;

public interface InvestigationReportRepository extends JpaRepository<InvestigationReport, Integer> {
    Optional<InvestigationReport> findFirstByIncidentIdOrderByReportIdDesc(Integer incidentId);

    List<InvestigationReport> findByIncidentIdOrderByReportIdAsc(Integer incidentId);
}
