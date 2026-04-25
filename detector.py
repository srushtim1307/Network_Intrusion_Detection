# ============================================================
#  detector.py  –  Network IDS  |  Detection Engine
# ============================================================
#  All rule-based detection lives here.  The Detector class
#  receives parsed packet data from the sniffer, updates its
#  internal counters, and fires alerts through AlertLogger.
# ============================================================

import time
from collections import defaultdict
from logger import AlertLogger
from config import (
    PACKET_FLOOD_THRESHOLD,
    TIME_WINDOW,
    SUSPICIOUS_PORTS,
    BLACKLISTED_IPS,
    REPEATED_CONNECTION_THRESHOLD,
)


class Detector:
    """
    Stateful, rule-based intrusion detector.

    Internal state (all reset when the object is created):
      ip_packet_times   – {src_ip: [timestamp, ...]}
                          Used to count packets per IP per time window.
      connection_counts – {(src_ip, dst_ip, dst_port): count}
                          Used to detect repeated connections.
      alerted_floods    – {src_ip}
                          Prevents spamming the same flood alert.
      alerted_repeats   – {(src_ip, dst_ip, dst_port)}
                          Prevents spamming the same repeat alert.
    """

    def __init__(self, logger: AlertLogger):
        self.logger = logger

        # Rule 1 – Packet flood
        self.ip_packet_times: dict = defaultdict(list)
        self.alerted_floods:  set  = set()

        # Rule 2 – Suspicious port access
        #   (alert every time – no de-duplication, intentional)

        # Rule 3 – Repeated connections
        self.connection_counts: dict = defaultdict(int)
        self.alerted_repeats:   set  = set()

        # Rule 4 – Blacklisted IP
        self.alerted_blacklist: set  = set()

    # ── Public entry point ────────────────────────────────

    def analyse(self, packet_info: dict):
        """
        Receive a parsed packet dictionary and run all detection rules.

        Expected keys in packet_info:
          src_ip, dst_ip, protocol, src_port, dst_port, size
        """
        src_ip   = packet_info.get("src_ip")
        dst_ip   = packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")

        if not src_ip or not dst_ip:
            return   # skip malformed / non-IP packets

        self._rule_blacklist(src_ip, dst_ip)
        self._rule_packet_flood(src_ip)
        self._rule_suspicious_port(src_ip, dst_ip, dst_port, packet_info)
        self._rule_repeated_connection(src_ip, dst_ip, dst_port)

    # ── Detection Rules ───────────────────────────────────

    def _rule_blacklist(self, src_ip: str, dst_ip: str):
        """
        Rule 4 – Blacklisted IP
        Alert once per IP if src or dst is in the blacklist.
        """
        for ip in (src_ip, dst_ip):
            if ip in BLACKLISTED_IPS and ip not in self.alerted_blacklist:
                self.alerted_blacklist.add(ip)
                self.logger.alert(
                    alert_type = "BLACKLISTED_IP",
                    message    = (
                        f"Traffic involving known-bad IP: {ip}  "
                        f"({src_ip} → {dst_ip})"
                    ),
                    severity   = "HIGH",
                )

    def _rule_packet_flood(self, src_ip: str):
        """
        Rule 1 – Packet Flood / DDoS Detection
        If a single source IP sends more than PACKET_FLOOD_THRESHOLD
        packets within TIME_WINDOW seconds, raise an alert.
        """
        now = time.time()

        # Record this packet's arrival time
        self.ip_packet_times[src_ip].append(now)

        # Discard timestamps older than the time window
        self.ip_packet_times[src_ip] = [
            t for t in self.ip_packet_times[src_ip]
            if now - t <= TIME_WINDOW
        ]

        count = len(self.ip_packet_times[src_ip])

        if count >= PACKET_FLOOD_THRESHOLD:
            if src_ip not in self.alerted_floods:
                self.alerted_floods.add(src_ip)
                self.logger.alert(
                    alert_type = "PACKET_FLOOD",
                    message    = (
                        f"{src_ip} sent {count} packets "
                        f"in {TIME_WINDOW}s  "
                        f"(threshold: {PACKET_FLOOD_THRESHOLD})"
                    ),
                    severity   = "HIGH",
                )
        else:
            # Reset so it can alert again if the flood resumes later
            self.alerted_floods.discard(src_ip)

    def _rule_suspicious_port(
        self,
        src_ip   : str,
        dst_ip   : str,
        dst_port : int | None,
        pkt_info : dict,
    ):
        """
        Rule 2 – Access to Suspicious Port
        Alert every time a packet targets a port in SUSPICIOUS_PORTS.
        """
        if dst_port and dst_port in SUSPICIOUS_PORTS:
            protocol = pkt_info.get("protocol", "UNKNOWN")
            self.logger.alert(
                alert_type = "SUSPICIOUS_PORT",
                message    = (
                    f"{src_ip} → {dst_ip}:{dst_port}  "
                    f"({protocol})  "
                    f"— sensitive port access"
                ),
                severity   = "MEDIUM",
            )

    def _rule_repeated_connection(
        self,
        src_ip   : str,
        dst_ip   : str,
        dst_port : int | None,
    ):
        """
        Rule 3 – Repeated / Hammering Connection
        Alert once when the same (src → dst:port) tuple exceeds the
        REPEATED_CONNECTION_THRESHOLD.  Could indicate port scanning
        or an automated brute-force tool.
        """
        if dst_port is None:
            return

        key = (src_ip, dst_ip, dst_port)
        self.connection_counts[key] += 1

        count = self.connection_counts[key]

        if (count >= REPEATED_CONNECTION_THRESHOLD
                and key not in self.alerted_repeats):
            self.alerted_repeats.add(key)
            self.logger.alert(
                alert_type = "REPEATED_CONNECTION",
                message    = (
                    f"{src_ip} → {dst_ip}:{dst_port}  "
                    f"seen {count} times  "
                    f"— possible scan or brute-force"
                ),
                severity   = "MEDIUM",
            )

    # ── Statistics ────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return a snapshot of current detector state for display."""
        return {
            "unique_sources"      : len(self.ip_packet_times),
            "unique_connections"  : len(self.connection_counts),
            "flood_alerts"        : len(self.alerted_floods),
            "repeat_alerts"       : len(self.alerted_repeats),
            "blacklist_alerts"    : len(self.alerted_blacklist),
            "total_alerts"        : self.logger.alert_count,
        }
