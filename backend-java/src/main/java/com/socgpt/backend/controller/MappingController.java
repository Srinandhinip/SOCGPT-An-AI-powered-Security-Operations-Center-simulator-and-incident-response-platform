package com.socgpt.backend.controller;

import com.socgpt.backend.model.Incident;
import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.repository.IncidentRepository;
import com.socgpt.backend.repository.SecurityEventRepository;
import com.socgpt.backend.service.MitreMappingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/mapping")
public class MappingController {

    private final MitreMappingService mappingService;
    private final IncidentRepository incidentRepository;
    private final SecurityEventRepository eventRepository;

    public MappingController(MitreMappingService mappingService,
                              IncidentRepository incidentRepository,
                              SecurityEventRepository eventRepository) {
        this.mappingService = mappingService;
        this.incidentRepository = incidentRepository;
        this.eventRepository = eventRepository;
    }

    // e.g. GET /mapping/event-type/sqli
    @GetMapping("/event-type/{eventType}")
    public ResponseEntity<MitreMappingService.Mapping> byEventType(@PathVariable String eventType) {
        return mappingService.lookup(eventType)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    // e.g. GET /mapping/incident/6
    @GetMapping("/incident/{incidentId}")
    public ResponseEntity<MitreMappingService.Mapping> byIncident(@PathVariable Integer incidentId) {
        Incident incident = incidentRepository.findById(incidentId).orElse(null);
        if (incident == null || incident.getEventId() == null) {
            return ResponseEntity.notFound().build();
        }
        SecurityEvent event = eventRepository.findById(incident.getEventId()).orElse(null);
        if (event == null) {
            return ResponseEntity.notFound().build();
        }
        return mappingService.lookup(event.getEventType())
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }
}