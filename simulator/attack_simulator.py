"""
SOCGPT Attack Simulator
Generates fake attack events and sends them to the Java backend's /events API,
authenticating as a sensor with the X-Ingest-Key header.

Usage:
    python attack_simulator.py                 # 5 random single attacks, 2 seconds apart
    python attack_simulator.py campaign        # recon -> brute force -> SQL injection from ONE IP
                                               # (the backend links these into a multi-stage attack chain)
    python attack_simulator.py sqli            # one specific attack: sqli | malware | brute_force | port_scan

Environment variables (optional):
    SOCGPT_API_URL      default http://localhost:8080
    SOCGPT_INGEST_KEY   default dev-ingest-key   (must match socgpt.ingest.key in application.properties)
"""

import os
import random
import sys
import time

import requests

API_BASE = os.getenv("SOCGPT_API_URL", "http://localhost:8080")
API_URL = API_BASE.rstrip("/") + "/events"
INGEST_KEY = os.getenv("SOCGPT_INGEST_KEY", "dev-ingest-key")

# A few realistic-looking fake source IPs to rotate through
FAKE_IPS = [
    "192.168.1.50",
    "10.0.0.99",
    "203.0.113.45",
    "198.51.100.23",
]

# Attack scenarios: each maps an event_type to its MITRE ATT&CK technique ID and how many
# raw events it takes to trip the detection rule
ATTACKS = {
    "brute_force": {"mitreId": "T1110", "burst": 3},
    "sqli": {"mitreId": "T1190", "burst": 1},
    "port_scan": {"mitreId": "T1595", "burst": 5},
    "malware": {"mitreId": "T1204", "burst": 1},
}


def send_event(event):
    """Send one fake event to the Java backend."""
    try:
        response = requests.post(API_URL, json=event, headers={"X-Ingest-Key": INGEST_KEY}, timeout=15)
    except requests.RequestException as e:
        print(f"[FAIL] Cannot reach {API_URL}: {e}")
        return
    if response.status_code == 200:
        print(f"[OK] Sent {event['eventType']} from {event['sourceIp']} -> event #{response.json().get('eventId')}")
    elif response.status_code == 401:
        print("[FAIL] 401: the ingest key was refused. Set SOCGPT_INGEST_KEY to match socgpt.ingest.key.")
    else:
        print(f"[FAIL] {response.status_code}: {response.text}")


def simulate_attack(attack_type, ip, pause=0.4):
    """Send the burst of raw events one attack needs to be detected."""
    spec = ATTACKS[attack_type]
    for _ in range(spec["burst"]):
        send_event({"sourceIp": ip, "eventType": attack_type, "mitreId": spec["mitreId"]})
        time.sleep(pause)


def simulate_single_attack():
    """Generate and send one random attack."""
    simulate_attack(random.choice(list(ATTACKS)), random.choice(FAKE_IPS))


def simulate_campaign():
    """A realistic intrusion from a single attacker: scan, guess passwords, then exploit."""
    ip = random.choice(["185.220.101.9", "203.0.113.45", "198.51.100.23"])
    print(f"Campaign from {ip}: reconnaissance -> credential access -> initial access\n")
    for stage in ("port_scan", "brute_force", "sqli"):
        print(f"--- stage: {stage}")
        simulate_attack(stage, ip)
        time.sleep(3)


if __name__ == "__main__":
    print("Starting SOCGPT Attack Simulator...")
    print(f"Sending events to {API_URL}\n")

    mode = sys.argv[1] if len(sys.argv) > 1 else "random"
    if mode == "campaign":
        simulate_campaign()
    elif mode in ATTACKS:
        simulate_attack(mode, random.choice(FAKE_IPS))
    elif mode == "random":
        for _ in range(5):
            simulate_single_attack()
            time.sleep(2)
    else:
        print(f"Unknown mode '{mode}'. Use: random, campaign, " + ", ".join(ATTACKS))
        sys.exit(1)

    print("\nSimulation complete.")
