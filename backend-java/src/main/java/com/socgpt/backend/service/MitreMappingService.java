package com.socgpt.backend.service;

import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;

@Service
public class MitreMappingService {

    // One result = everything we know about an attack type
    public record Mapping(
        String mitreId,
        String techniqueName,
        String tactic,
        String csfFunction,
        String csfDescription
    ) {}

    // NIST CSF 2.0 functions and what they mean
    private static final Map<String, String> CSF_DESCRIPTIONS = Map.of(
        "Govern",   "Security policies, roles, and risk management strategy are established and communicated.",
        "Identify", "Asset inventory, vulnerabilities, and organizational risk are understood.",
        "Protect",  "Safeguards (access control, MFA, patching) are implemented to limit or contain impact.",
        "Detect",   "Anomalies and indicators of compromise are found through log monitoring and alerting.",
        "Respond",  "Actions are taken to investigate, contain, and remediate a detected incident.",
        "Recover",  "Restoration of assets/operations and lessons-learned activities are carried out."
    );

    // event type -> MITRE ATT&CK technique + NIST CSF function
    private static final Map<String, Mapping> BY_EVENT_TYPE = Map.of(
        "brute_force", build("T1110", "Brute Force", "Credential Access", "Detect"),
        "sqli",        build("T1190", "Exploit Public-Facing Application", "Initial Access", "Protect"),
        "port_scan",   build("T1595", "Active Scanning", "Reconnaissance", "Detect"),
        "malware",     build("T1204", "User Execution", "Execution", "Respond")
    );

    private static Mapping build(String mitreId, String name, String tactic, String csfFunction) {
        return new Mapping(mitreId, name, tactic, csfFunction, CSF_DESCRIPTIONS.get(csfFunction));
    }

    public Optional<Mapping> lookup(String eventType) {
        return Optional.ofNullable(BY_EVENT_TYPE.get(eventType));
    }
}