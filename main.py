#!/usr/bin/env python3
# ============================================================
#  main.py  –  Network IDS  |  Entry Point
# ============================================================
#  Run this file to start the IDS:
#
#      sudo python3 main.py           (Linux / macOS)
#      python main.py  (Windows, as Administrator)
#
# ============================================================

import os
import sys
import time
from logger   import AlertLogger
from detector import Detector
from sniffer  import PacketSniffer

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


# ── Banner ────────────────────────────────────────────────

BANNER = r"""
  ╔══════════════════════════════════════════════════════════╗
  ║         NETWORK INTRUSION DETECTION SYSTEM (IDS)         ║
  ║              Python  |  Scapy  |  Rule-Based             ║
  ╚══════════════════════════════════════════════════════════╝
"""

RULES_SUMMARY = """
  Active Detection Rules
  ──────────────────────
  [1] Packet Flood      – Alert when a single IP sends too many
                          packets in a short time window.
  [2] Suspicious Ports  – Alert on connections to sensitive ports
                          (SSH/22, Telnet/23, RDP/3389 …).
  [3] Repeated Connects – Alert when the same connection pair
                          hammers the same port repeatedly.
  [4] Blacklisted IPs   – Alert on any traffic to/from known-bad
                          IP addresses.
"""


# ── Pre-flight checks ─────────────────────────────────────

def check_root():
    """Packet sniffing requires root / Administrator privileges."""
    if os.name == "nt":
        # Windows: check if running as Administrator
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("\n  [!] Please run this script as Administrator.\n")
            sys.exit(1)
    else:
        # Linux / macOS: check UID
        if os.geteuid() != 0:
            print("\n  [!] Please run with sudo:  sudo python3 main.py\n")
            sys.exit(1)


def check_scapy():
    """Make sure Scapy is installed before we start."""
    try:
        import scapy  # noqa: F401
    except ImportError:
        print("\n  [!] Scapy not found.  Install it with:\n")
        print("      pip install scapy\n")
        sys.exit(1)


# ── Main ──────────────────────────────────────────────────

def main():
    print(BANNER)
    print(RULES_SUMMARY)

    # Safety checks
    check_root()
    check_scapy()

    # Wire up the three components
    logger   = AlertLogger()
    detector = Detector(logger)
    sniffer  = PacketSniffer(detector, logger)

    start_time = time.time()

    try:
        sniffer.start()

    except Exception as exc:
        logger.alert(
            alert_type = "SNIFFER_ERROR",
            message    = f"Unexpected error: {exc}",
            severity   = "HIGH",
        )

    finally:
        # ── Session summary ───────────────────────────────
        elapsed = time.time() - start_time
        stats   = detector.get_stats()

        print(f"\n\n  {'─'*60}")
        print(f"  SESSION SUMMARY")
        print(f"  {'─'*60}")
        print(f"  Duration              : {elapsed:.1f} seconds")
        print(f"  Packets captured      : {sniffer.packet_count}")
        print(f"  Unique source IPs     : {stats['unique_sources']}")
        print(f"  Unique connections    : {stats['unique_connections']}")
        print(f"  ── Alerts ───────────────────────────────────────")
        print(f"  Flood alerts          : {stats['flood_alerts']}")
        print(f"  Repeat alerts         : {stats['repeat_alerts']}")
        print(f"  Blacklist alerts      : {stats['blacklist_alerts']}")
        print(f"  TOTAL alerts          : {stats['total_alerts']}")
        print(f"  {'─'*60}\n")

        logger.summary()


if __name__ == "__main__":
    main()
