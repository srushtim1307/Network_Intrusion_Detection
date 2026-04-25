# ============================================================
#  config.py  –  Network IDS  |  Configuration & Rules
# ============================================================
#  All tunable parameters live here so you never have to dig
#  through other files to tweak thresholds or add new ports.
# ============================================================

# ── Network Interface ─────────────────────────────────────
# Set to None to let Scapy pick the default interface, or
# specify one explicitly, e.g. "eth0", "Wi-Fi", "en0"
INTERFACE = None

# ── Packet Capture ────────────────────────────────────────
# Maximum packets to capture before the sniffer stops.
# Set to 0 for unlimited (press Ctrl+C to stop).
MAX_PACKETS = 0

# ── Detection Rule: Port Scan / Flood ────────────────────
# How many packets from a SINGLE source IP, within
# TIME_WINDOW seconds, trigger a "packet flood" alert.
PACKET_FLOOD_THRESHOLD = 100          # packet count
TIME_WINDOW            = 10           # seconds

# ── Detection Rule: Suspicious Ports ─────────────────────
# Connections to these destination ports will raise alerts.
# Common attack / sensitive service ports:
#   22  – SSH brute-force
#   23  – Telnet (plaintext)
#   3389– RDP
#   445 – SMB (ransomware pivot)
#   1433– MS-SQL
#   3306– MySQL
#   8080– Proxy / alternate HTTP
SUSPICIOUS_PORTS = {22, 23, 3389, 445, 1433, 3306, 8080}

# ── Detection Rule: Blacklisted IPs ──────────────────────
# Traffic from/to these IPs always triggers an alert.
# Add known-bad IPs or your lab's "attacker" VM here.
BLACKLISTED_IPS = {
    "192.168.1.200",   # example – replace with real values
    "10.0.0.99",
}

# ── Detection Rule: Repeated Connections ─────────────────
# If the SAME (src_ip → dst_ip : dst_port) pair is seen
# more than this many times, it looks like a scan or DoS.
REPEATED_CONNECTION_THRESHOLD = 50

# ── Logging ───────────────────────────────────────────────
LOG_FILE        = "alerts.log"   # where alerts are saved
LOG_TO_CONSOLE  = True           # also print to terminal

# ── Protocol Map ─────────────────────────────────────────
# Human-readable names for common IP protocol numbers.
PROTOCOL_MAP = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}
