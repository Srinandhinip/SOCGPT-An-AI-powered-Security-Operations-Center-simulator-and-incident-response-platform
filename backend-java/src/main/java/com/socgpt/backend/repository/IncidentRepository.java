package com.socgpt.backend.repository;

import java.util.Collection;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.socgpt.backend.model.Incident;

public interface IncidentRepository extends JpaRepository<Incident, Integer> {

    List<Incident> findByEventIdIn(Collection<Integer> eventIds);

    List<Incident> findByChainIdOrderByIncidentIdAsc(Integer chainId);
}
