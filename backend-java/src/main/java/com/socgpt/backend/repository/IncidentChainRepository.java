package com.socgpt.backend.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.socgpt.backend.model.IncidentChain;

public interface IncidentChainRepository extends JpaRepository<IncidentChain, Integer> {
    Optional<IncidentChain> findFirstBySourceIpAndStatusOrderByChainIdDesc(String sourceIp, String status);
}
