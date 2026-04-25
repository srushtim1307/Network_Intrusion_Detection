#!/usr/bin/env python3
# ============================================================
#  test_detector.py  –  Network IDS  |  Unit Tests
# ============================================================
#  Tests the Detector class WITHOUT needing root or a network.
#  Run with:   python3 test_detector.py
# ============================================================

import time
import sys
import os

# Minimal stub so we can import without root / scapy
sys.path.insert(0, os.path.dirname(__file__))

from logger   import AlertLogger
from detector import Detector
from config   import (
    PACKET_FLOOD_THRESHOLD,
    TIME_WINDOW,
    SUSPICIOUS_PORTS,
    REPEATED_CONNECTION_THRESHOLD,
    BLACKLISTED_IPS,
)

PASS = "\033[92m✓ PASS\033[0m"
FAIL = "\033[91m✗ FAIL\033[0m"
test_count  = 0
pass_count  = 0


def assert_equal(label, got, expected):
    global test_count, pass_count
    test_count += 1
    ok = (got == expected)
    if ok:
        pass_count += 1
    status = PASS if ok else FAIL
    print(f"  {status}  {label}")
    if not ok:
        print(f"         expected: {expected}")
        print(f"         got     : {got}")


def make_detector():
    """Fresh logger + detector for each test group."""
    logger   = AlertLogger()
    detector = Detector(logger)
    return detector, logger


# ── Test 1: Packet Flood ──────────────────────────────────

def test_packet_flood():
    print("\n── Test: Packet Flood Rule ─────────────────────────")
    detector, logger = make_detector()

    # Send just under the threshold → no alert
    for _ in range(PACKET_FLOOD_THRESHOLD - 1):
        detector.analyse({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                          "dst_port": 80, "protocol": "TCP"})

    assert_equal(
        f"No alert before {PACKET_FLOOD_THRESHOLD} packets",
        logger.alert_count, 0
    )

    # Send one more → crosses threshold → alert fires
    detector.analyse({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                      "dst_port": 80, "protocol": "TCP"})

    assert_equal(
        f"Alert fires at {PACKET_FLOOD_THRESHOLD} packets",
        logger.alert_count, 1
    )

    # Sending MORE packets from the same IP should NOT repeat the alert
    for _ in range(20):
        detector.analyse({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                          "dst_port": 80, "protocol": "TCP"})
    assert_equal(
        "Flood alert fires only once per window",
        logger.alert_count, 1
    )


# ── Test 2: Suspicious Ports ─────────────────────────────

def test_suspicious_ports():
    print("\n── Test: Suspicious Port Rule ──────────────────────")
    detector, logger = make_detector()
    alerts_before = logger.alert_count

    # Connection to SSH port (22) – always in SUSPICIOUS_PORTS
    detector.analyse({"src_ip": "3.3.3.3", "dst_ip": "4.4.4.4",
                      "dst_port": 22, "protocol": "TCP"})

    assert_equal(
        "Alert fires for port 22 (SSH)",
        logger.alert_count, alerts_before + 1
    )

    # Benign port (80) – no alert
    detector.analyse({"src_ip": "3.3.3.3", "dst_ip": "4.4.4.4",
                      "dst_port": 80, "protocol": "TCP"})

    assert_equal(
        "No alert for port 80 (HTTP)",
        logger.alert_count, alerts_before + 1
    )


# ── Test 3: Repeated Connections ─────────────────────────

def test_repeated_connections():
    print("\n── Test: Repeated Connection Rule ──────────────────")
    detector, logger = make_detector()

    base = logger.alert_count

    # Blast the same (src → dst:port) pair
    for _ in range(REPEATED_CONNECTION_THRESHOLD - 1):
        detector.analyse({"src_ip": "5.5.5.5", "dst_ip": "6.6.6.6",
                          "dst_port": 443, "protocol": "TCP"})

    assert_equal(
        f"No alert before {REPEATED_CONNECTION_THRESHOLD} repeats",
        logger.alert_count, base
    )

    detector.analyse({"src_ip": "5.5.5.5", "dst_ip": "6.6.6.6",
                      "dst_port": 443, "protocol": "TCP"})

    assert_equal(
        f"Alert fires at {REPEATED_CONNECTION_THRESHOLD} repeats",
        logger.alert_count > base, True
    )


# ── Test 4: Blacklisted IP ────────────────────────────────

def test_blacklisted_ip():
    print("\n── Test: Blacklisted IP Rule ────────────────────────")
    if not BLACKLISTED_IPS:
        print("  (skip – BLACKLISTED_IPS is empty in config.py)")
        return

    detector, logger = make_detector()
    bad_ip = next(iter(BLACKLISTED_IPS))  # grab first blacklisted IP
    base   = logger.alert_count

    detector.analyse({"src_ip": bad_ip, "dst_ip": "9.9.9.9",
                      "dst_port": 80, "protocol": "TCP"})

    assert_equal(
        f"Alert fires for blacklisted IP {bad_ip}",
        logger.alert_count > base, True
    )


# ── Test 5: Non-IP packets ────────────────────────────────

def test_non_ip_packets():
    print("\n── Test: Non-IP / Malformed Packets ────────────────")
    detector, logger = make_detector()
    base = logger.alert_count

    # Packet with no src_ip / dst_ip – should be silently ignored
    detector.analyse({})
    detector.analyse({"src_ip": None, "dst_ip": None, "dst_port": 22})

    assert_equal(
        "No crash or alert for malformed packets",
        logger.alert_count, base
    )


# ── Runner ────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═" * 55)
    print("  Network IDS – Detector Unit Tests")
    print("═" * 55)

    test_packet_flood()
    test_suspicious_ports()
    test_repeated_connections()
    test_blacklisted_ip()
    test_non_ip_packets()

    print(f"\n{'═'*55}")
    result = f"{pass_count}/{test_count} tests passed"
    colour = "\033[92m" if pass_count == test_count else "\033[91m"
    print(f"  {colour}{result}\033[0m")
    print("═" * 55 + "\n")

    sys.exit(0 if pass_count == test_count else 1)
