package com.socgpt.backend.controller;

import com.socgpt.backend.model.InvestigationReport;
import com.socgpt.backend.repository.InvestigationReportRepository;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/reports")
public class InvestigationReportController {
    private final InvestigationReportRepository repo;
    public InvestigationReportController(InvestigationReportRepository repo) { this.repo = repo; }

    @GetMapping
    public List<InvestigationReport> getAll() { return repo.findAll(); }
     @PostMapping
    public InvestigationReport createReport(@RequestBody InvestigationReport report) {
        return repo.save(report);
    }
}