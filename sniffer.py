# ============================================================
#  sniffer.py  –  Network IDS  |  Packet Sniffer
# ============================================================
#  Uses Scapy to capture live packets and extract fields into
#  a clean dictionary that the Detector can work with.
# ============================================================

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from config import INTERFACE, MAX_PACKETS, PROTOCOL_MAP
from detector import Detector
from logger import AlertLogger


class PacketSniffer:
    """
    Captures live packets from the network interface and passes
    each parsed packet to the Detector for analysis.
    """

    def __init__(self, detector: Detector, logger: AlertLogger):
        self.detector     = detector
        self.logger       = logger
        self.packet_count = 0

    # ── Packet Parsing ────────────────────────────────────

    def _parse_packet(self, packet) -> dict | None:
        """
        Extract relevant fields from a Scapy packet object.

        Returns a dictionary with these keys (or None if non-IP):
          src_ip, dst_ip, protocol,
          src_port, dst_port, size, flags
        """
        # Only process IP packets
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]

        # Protocol number → human name
        proto_num  = ip_layer.proto
        proto_name = PROTOCOL_MAP.get(proto_num, f"PROTO-{proto_num}")

        info = {
            "src_ip"   : ip_layer.src,
            "dst_ip"   : ip_layer.dst,
            "protocol" : proto_name,
            "src_port" : None,
            "dst_port" : None,
            "size"     : len(packet),
            "flags"    : None,
        }

        # Extract port numbers for TCP / UDP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info["src_port"] = tcp.sport
            info["dst_port"] = tcp.dport
            info["flags"]    = str(tcp.flags)   # e.g. "S", "SA", "PA"

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info["src_port"] = udp.sport
            info["dst_port"] = udp.dport

        return info

    # ── Per-packet callback ───────────────────────────────

    def _handle_packet(self, packet):
        """
        Called by Scapy for every captured packet.
        Parses it, prints a one-line summary, then runs detection.
        """
        self.packet_count += 1
        parsed = self._parse_packet(packet)

        if parsed is None:
            return   # skip non-IP frames (ARP, etc.)

        # One-line live display
        src_port_str = f":{parsed['src_port']}" if parsed["src_port"] else ""
        dst_port_str = f":{parsed['dst_port']}" if parsed["dst_port"] else ""

        print(
            f"  [{self.packet_count:>5}]  "
            f"{parsed['protocol']:<6}  "
            f"{parsed['src_ip']}{src_port_str:<22}  →  "
            f"{parsed['dst_ip']}{dst_port_str:<22}  "
            f"({parsed['size']} bytes)"
        )

        # Hand off to the detection engine
        self.detector.analyse(parsed)

    # ── Start / Stop ──────────────────────────────────────

    def start(self):
        """
        Begin live packet capture.
        Blocks until MAX_PACKETS packets are seen (0 = infinite)
        or the user presses Ctrl+C.
        """
        count_arg = MAX_PACKETS if MAX_PACKETS > 0 else 0   # 0 = no limit

        self.logger.info(
            f"Sniffer started on interface: "
            f"{INTERFACE or 'default'}  "
            f"(max packets: {'∞' if count_arg == 0 else count_arg})"
        )
        self.logger.info(
            "Press Ctrl+C to stop."
        )
        self.logger.separator()

        print(
            f"\n  {'#':<7}  {'Proto':<6}  "
            f"{'Source':<30}  {'Destination':<30}  Size\n"
            + "  " + "─" * 85
        )

        try:
            sniff(
                iface   = INTERFACE,
                prn     = self._handle_packet,
                count   = count_arg,
                store   = False,   # don't keep packets in RAM
            )
        except KeyboardInterrupt:
            pass   # user pressed Ctrl+C — handled in main.py
