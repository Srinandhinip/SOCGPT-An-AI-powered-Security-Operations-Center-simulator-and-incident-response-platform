package com.socgpt.backend.controller;

import com.socgpt.backend.model.Notification;
import com.socgpt.backend.repository.NotificationRepository;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/notifications")
public class NotificationController {
    private final NotificationRepository repo;
    public NotificationController(NotificationRepository repo) { this.repo = repo; }

    @GetMapping
    public List<Notification> getAll() { return repo.findAll(); }
    @PostMapping
    public Notification createNotification(@RequestBody Notification notification) {
        return repo.save(notification);
    }
}
