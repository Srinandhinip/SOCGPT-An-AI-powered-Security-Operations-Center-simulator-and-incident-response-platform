package com.socgpt.backend.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.socgpt.backend.model.SecurityEvent;
import com.socgpt.backend.repository.SecurityEventRepository;
import com.socgpt.backend.service.DetectionService;

/**
 * Sensors (the attack simulator) post raw events here with the X-Ingest-Key header;
 * admins can also post with a normal token. Each event runs through the detection engine.
 */
@RestController
@RequestMapping("/events")
public class SecurityEventController {

    private final SecurityEventRepository securityEventRepository;
    private final DetectionService detectionService;

    public SecurityEventController(SecurityEventRepository securityEventRepository,
                                    DetectionService detectionService) {
        this.securityEventRepository = securityEventRepository;
        this.detectionService = detectionService;
    }

    @GetMapping
    public List<SecurityEvent> getAllEvents() {
        return securityEventRepository.findAll();
    }

    @PostMapping
    public SecurityEvent createEvent(@RequestBody SecurityEvent event) {
        if (event.getSourceIp() == null || event.getSourceIp().isBlank() || event.getSourceIp().length() > 45) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sourceIp is required (max 45 characters).");
        }
        if (event.getEventType() == null || event.getEventType().isBlank() || event.getEventType().length() > 50) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "eventType is required (max 50 characters).");
        }
        if (event.getMitreId() != null && event.getMitreId().length() > 10) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "mitreId is too long (max 10 characters).");
        }
        event.setEventId(null);
        SecurityEvent saved = securityEventRepository.save(event);
        detectionService.evaluate(saved);
        return saved;
    }
}
