package com.socgpt.backend.controller;

import com.socgpt.backend.model.RemediationPlan;
import com.socgpt.backend.repository.RemediationPlanRepository;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/remediation-plans")
public class RemediationPlanController {
    private final RemediationPlanRepository repo;
    public RemediationPlanController(RemediationPlanRepository repo) { this.repo = repo; }

    @GetMapping
    public List<RemediationPlan> getAll() { return repo.findAll(); }
     @PostMapping
    public RemediationPlan createPlan(@RequestBody RemediationPlan plan) {
        return repo.save(plan);
    }
}