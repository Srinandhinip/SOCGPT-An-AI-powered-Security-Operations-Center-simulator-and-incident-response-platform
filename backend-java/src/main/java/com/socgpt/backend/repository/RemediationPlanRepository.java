package com.socgpt.backend.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.socgpt.backend.model.RemediationPlan;

public interface RemediationPlanRepository extends JpaRepository<RemediationPlan, Integer> {
    Optional<RemediationPlan> findFirstByIncidentIdOrderByPlanIdDesc(Integer incidentId);

    List<RemediationPlan> findByIncidentIdOrderByPlanIdAsc(Integer incidentId);
}
