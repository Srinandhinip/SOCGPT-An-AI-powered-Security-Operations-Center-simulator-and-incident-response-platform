package com.socgpt.backend.controller;

import com.socgpt.backend.model.IncidentChain;
import com.socgpt.backend.repository.IncidentChainRepository;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/chains")
public class IncidentChainController {
    private final IncidentChainRepository repo;
    public IncidentChainController(IncidentChainRepository repo) { this.repo = repo; }

    @GetMapping
    public List<IncidentChain> getAll() { return repo.findAll(); }
     @PostMapping
    public IncidentChain createChain(@RequestBody IncidentChain chain) {
        return repo.save(chain);
    }
}