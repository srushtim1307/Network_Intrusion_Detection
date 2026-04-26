# ============================================================
#  ids_helpers.py  –  Network IDS  |  Dashboard Helper Module
# ============================================================
#  Contains utility functions for the Streamlit dashboard:
#    - IP Geolocation (cached)
#    - Anomaly Detection (spike detection)
#    - Email Alerting (SMTP)
#    - PCAP File Analysis
#    - Attack Simulation
#    - PDF Report Generation
# ============================================================

import time
import random
import smtplib
import io
import numpy as np
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter

import requests
import streamlit as st
from fpdf import FPDF

# Import backend modules for reuse
from detector import Detector
from logger import AlertLogger
from config import PROTOCOL_MAP


# ════════════════════════════════════════════════════════════════
#  1. IP GEOLOCATION (Cached)
# ════════════════════════════════════════════════════════════════

# Country code → flag emoji mapping
COUNTRY_FLAGS = {
    "AF": "🇦🇫", "AL": "🇦🇱", "DZ": "🇩🇿", "AR": "🇦🇷", "AU": "🇦🇺",
    "AT": "🇦🇹", "BD": "🇧🇩", "BE": "🇧🇪", "BR": "🇧🇷", "CA": "🇨🇦",
    "CL": "🇨🇱", "CN": "🇨🇳", "CO": "🇨🇴", "CZ": "🇨🇿", "DK": "🇩🇰",
    "EG": "🇪🇬", "FI": "🇫🇮", "FR": "🇫🇷", "DE": "🇩🇪", "GR": "🇬🇷",
    "HK": "🇭🇰", "HU": "🇭🇺", "IN": "🇮🇳", "ID": "🇮🇩", "IE": "🇮🇪",
    "IL": "🇮🇱", "IT": "🇮🇹", "JP": "🇯🇵", "KR": "🇰🇷", "MY": "🇲🇾",
    "MX": "🇲🇽", "NL": "🇳🇱", "NZ": "🇳🇿", "NG": "🇳🇬", "NO": "🇳🇴",
    "PK": "🇵🇰", "PH": "🇵🇭", "PL": "🇵🇱", "PT": "🇵🇹", "RO": "🇷🇴",
    "RU": "🇷🇺", "SA": "🇸🇦", "SG": "🇸🇬", "ZA": "🇿🇦", "ES": "🇪🇸",
    "SE": "🇸🇪", "CH": "🇨🇭", "TW": "🇹🇼", "TH": "🇹🇭", "TR": "🇹🇷",
    "UA": "🇺🇦", "AE": "🇦🇪", "GB": "🇬🇧", "US": "🇺🇸", "VN": "🇻🇳",
}


@st.cache_data(ttl=3600, show_spinner=False)
def get_ip_geolocation(ip: str) -> dict:
    """
    Look up geolocation for an IP address using ip-api.com (free).
    Results are cached for 1 hour to avoid rate limiting.
    Returns dict with 'country', 'countryCode', 'flag' keys.
    """
    # Skip private/local IPs
    if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                      "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                      "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                      "172.29.", "172.30.", "172.31.", "127.", "0.")):
        return {"country": "Private/Local", "countryCode": "--", "flag": "🏠"}

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode",
            timeout=2
        )
        data = resp.json()
        if data.get("status") == "success":
            code = data.get("countryCode", "??")
            return {
                "country": data.get("country", "Unknown"),
                "countryCode": code,
                "flag": COUNTRY_FLAGS.get(code, "🌐"),
            }
    except Exception:
        pass

    return {"country": "Unknown", "countryCode": "??", "flag": "🌐"}


def enrich_ip_with_geo(ip: str) -> str:
    """Return a formatted string like '🇺🇸 United States' for display."""
    geo = get_ip_geolocation(ip)
    return f"{geo['flag']} {geo['country']}"


# ════════════════════════════════════════════════════════════════
#  2. ANOMALY DETECTION (Lightweight Spike Detection)
# ════════════════════════════════════════════════════════════════

def detect_pps_anomaly(pps_history: list, current_pps: int) -> dict | None:
    """
    Detect if the current packets-per-second is anomalously high.
    Uses a simple z-score approach: alert if current_pps > mean + 2*std.
    Returns an alert dict or None.
    """
    if len(pps_history) < 10 or current_pps <= 0:
        return None

    arr = np.array(pps_history)
    mean_pps = arr.mean()
    std_pps = arr.std()

    # Avoid false positives when traffic is very low
    if std_pps < 5 or mean_pps < 5:
        return None

    threshold = mean_pps + (2 * std_pps)

    if current_pps > threshold:
        return {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Type": "ANOMALY_DETECTED",
            "Severity": "HIGH",
            "Message": (
                f"PPS spike detected: {current_pps} pps "
                f"(normal avg: {mean_pps:.0f}, threshold: {threshold:.0f})"
            )
        }
    return None


def detect_port_anomaly(packet_q: list, port_counter: Counter) -> dict | None:
    """
    Detect unusual port activity — if a single port receives
    a sudden burst of connections that is unusual.
    """
    if not port_counter or len(port_counter) < 3:
        return None

    most_common_port, count = port_counter.most_common(1)[0]
    total = sum(port_counter.values())
    ratio = count / total if total > 0 else 0

    # If one port has > 60% of all traffic and count > 50, flag it
    if ratio > 0.6 and count > 50:
        return {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Type": "ANOMALY_DETECTED",
            "Severity": "MEDIUM",
            "Message": (
                f"Unusual port concentration: port {most_common_port} "
                f"has {ratio*100:.0f}% of traffic ({count}/{total} packets)"
            )
        }
    return None


# ════════════════════════════════════════════════════════════════
#  3. EMAIL ALERTING (SMTP)
# ════════════════════════════════════════════════════════════════

def send_email_alert(
    smtp_server: str,
    smtp_port: int,
    sender_email: str,
    sender_password: str,
    recipient_email: str,
    alert_data: dict,
) -> bool:
    """
    Send an email notification for a HIGH severity alert.
    Returns True on success, False on failure.
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 IDS ALERT: {alert_data.get('Type', 'UNKNOWN')}"
        msg["From"] = sender_email
        msg["To"] = recipient_email

        body = f"""
        ╔══════════════════════════════════════════╗
        ║   NETWORK IDS - HIGH SEVERITY ALERT      ║
        ╚══════════════════════════════════════════╝

        Timestamp : {alert_data.get('Timestamp', 'N/A')}
        Type      : {alert_data.get('Type', 'N/A')}
        Severity  : {alert_data.get('Severity', 'N/A')}
        Message   : {alert_data.get('Message', 'N/A')}

        — Network IDS Dashboard
        """

        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())

        return True
    except Exception:
        return False


# ════════════════════════════════════════════════════════════════
#  4. PCAP FILE ANALYSIS
# ════════════════════════════════════════════════════════════════

def analyze_pcap_file(file_bytes: bytes) -> tuple[list, list]:
    """
    Analyze a .pcap file using the existing Detector logic.
    Returns (alerts_list, packets_list).
    """
    from scapy.all import rdpcap, IP, TCP, UDP
    import tempfile
    import os

    alerts = []
    packets = []

    # Write bytes to a temp file for Scapy
    tmp_path = os.path.join(os.path.dirname(__file__), "_temp_upload.pcap")
    try:
        with open(tmp_path, "wb") as f:
            f.write(file_bytes)

        # Custom logger that captures alerts into our list
        class PcapLogger(AlertLogger):
            def alert(self, alert_type, message, severity="HIGH"):
                super().alert(alert_type, message, severity)
                alerts.append({
                    "Timestamp": self._timestamp(),
                    "Type": alert_type,
                    "Severity": severity,
                    "Message": message,
                })

        logger = PcapLogger()
        detector = Detector(logger)
        pkts = rdpcap(tmp_path)

        for pkt in pkts:
            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            proto_num = ip_layer.proto
            proto_name = PROTOCOL_MAP.get(proto_num, f"PROTO-{proto_num}")

            info = {
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "protocol": proto_name,
                "src_port": None,
                "dst_port": None,
                "size": len(pkt),
                "flags": None,
            }

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                info["src_port"] = tcp.sport
                info["dst_port"] = tcp.dport
                info["flags"] = str(tcp.flags)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                info["src_port"] = udp.sport
                info["dst_port"] = udp.dport

            packets.append(info)
            detector.analyse(info)

    except Exception as e:
        alerts.append({
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Type": "PCAP_ERROR",
            "Severity": "HIGH",
            "Message": f"Error analyzing PCAP: {str(e)}",
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    return alerts, packets


# ════════════════════════════════════════════════════════════════
#  5. ATTACK SIMULATION
# ════════════════════════════════════════════════════════════════

def generate_simulated_flood(count: int = 150) -> list:
    """Generate synthetic packet flood events from a single IP."""
    attacker_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    target_ip = "192.168.1.1"
    packets = []
    for _ in range(count):
        packets.append({
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "protocol": "TCP",
            "src_port": random.randint(40000, 65535),
            "dst_port": 80,
            "size": random.randint(60, 1500),
            "flags": "S",
        })
    return packets


def generate_simulated_port_scan() -> list:
    """Generate synthetic port scan events."""
    attacker_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    target_ip = "192.168.1.1"
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
                  445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
    packets = []
    for port in scan_ports:
        for _ in range(random.randint(3, 8)):
            packets.append({
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "protocol": "TCP",
                "src_port": random.randint(40000, 65535),
                "dst_port": port,
                "size": random.randint(40, 80),
                "flags": "S",
            })
    return packets


def generate_simulated_blacklist() -> list:
    """Generate traffic from a known-bad IP."""
    from config import BLACKLISTED_IPS
    bad_ip = list(BLACKLISTED_IPS)[0] if BLACKLISTED_IPS else "10.0.0.99"
    target_ip = "192.168.1.1"
    packets = []
    for _ in range(20):
        packets.append({
            "src_ip": bad_ip,
            "dst_ip": target_ip,
            "protocol": random.choice(["TCP", "UDP"]),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([22, 80, 443, 3389]),
            "size": random.randint(60, 1500),
            "flags": "S" if random.random() > 0.5 else "PA",
        })
    return packets


def run_simulation(sim_type: str, state, alert_q_append, ip_counter) -> dict:
    """
    Run a simulation and feed packets through a real Detector.
    Returns summary dict with results.
    """
    # Choose simulation type
    if sim_type == "flood":
        sim_packets = generate_simulated_flood()
    elif sim_type == "port_scan":
        sim_packets = generate_simulated_port_scan()
    elif sim_type == "blacklist":
        sim_packets = generate_simulated_blacklist()
    else:
        return {"error": "Unknown simulation type"}

    # Create a dedicated logger/detector for simulation
    sim_alerts = []

    class SimLogger(AlertLogger):
        def alert(self, alert_type, message, severity="HIGH"):
            # Don't call super() to avoid writing to alerts.log
            self.alert_count += 1
            sim_alerts.append({
                "Timestamp": self._timestamp(),
                "Type": alert_type,
                "Severity": severity,
                "Message": f"[SIMULATED] {message}",
            })

    logger = SimLogger()
    detector = Detector(logger)

    for pkt in sim_packets:
        detector.analyse(pkt)
        # Also update shared state so UI can see packets
        state.packet_q.appendleft(pkt)
        src_ip = pkt.get("src_ip")
        if src_ip:
            ip_counter[src_ip] += 1

    # Push simulation alerts into the shared alert queue
    for alert in sim_alerts:
        alert_q_append(alert)

    return {
        "packets_generated": len(sim_packets),
        "alerts_triggered": len(sim_alerts),
        "alerts": sim_alerts,
    }


# ════════════════════════════════════════════════════════════════
#  6. PDF REPORT GENERATION
# ════════════════════════════════════════════════════════════════

def _sanitize_for_pdf(text: str) -> str:
    """
    Replace Unicode characters that Helvetica (Latin-1) cannot render.
    This prevents FPDFUnicodeEncodingException errors.
    """
    replacements = {
        "\u2192": "->",   # →
        "\u2014": "--",   # —
        "\u2013": "-",    # –
        "\u221e": "inf",  # ∞
        "\u2022": "*",    # •
        "\u2018": "'",    # '
        "\u2019": "'",    # '
        "\u201c": '"',    # "
        "\u201d": '"',    # "
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    # Strip any remaining non-Latin-1 characters
    return text.encode("latin-1", errors="replace").decode("latin-1")


def generate_pdf_report(alerts_list: list, stats: dict) -> bytes:
    """
    Generate a PDF summary report of IDS alerts.
    Returns PDF as bytes.
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 15, "Network IDS - Security Report", ln=True, align="C")
    pdf.ln(5)

    # Metadata
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(0, 8, f"Total Alerts: {stats.get('total_alerts', len(alerts_list))}", ln=True)
    pdf.cell(0, 8, f"Unique Sources: {stats.get('unique_sources', 'N/A')}", ln=True)
    pdf.cell(0, 8, f"Unique Connections: {stats.get('unique_connections', 'N/A')}", ln=True)
    pdf.ln(8)

    # Severity summary
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Severity Breakdown", ln=True)
    pdf.set_font("Helvetica", "", 10)

    sev_counts = Counter(a.get("Severity", "UNKNOWN") for a in alerts_list)
    for sev, count in sev_counts.most_common():
        pdf.cell(0, 7, f"  {sev}: {count} alerts", ln=True)
    pdf.ln(5)

    # Alerts table
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Alert Details", ln=True)
    pdf.ln(3)

    # Table header
    pdf.set_font("Helvetica", "B", 8)
    col_widths = [35, 30, 18, 107]
    headers = ["Timestamp", "Type", "Severity", "Message"]
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, h, border=1, align="C")
    pdf.ln()

    # Table rows (limit to 100 for PDF size)
    pdf.set_font("Helvetica", "", 7)
    for alert in alerts_list[:100]:
        ts = _sanitize_for_pdf(str(alert.get("Timestamp", ""))[:19])
        atype = _sanitize_for_pdf(str(alert.get("Type", ""))[:20])
        sev = _sanitize_for_pdf(str(alert.get("Severity", "")))
        msg = _sanitize_for_pdf(str(alert.get("Message", ""))[:70])

        pdf.cell(col_widths[0], 6, ts, border=1)
        pdf.cell(col_widths[1], 6, atype, border=1)
        pdf.cell(col_widths[2], 6, sev, border=1, align="C")
        pdf.cell(col_widths[3], 6, msg, border=1)
        pdf.ln()

    if len(alerts_list) > 100:
        pdf.ln(3)
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 8, f"... and {len(alerts_list) - 100} more alerts (truncated)", ln=True)

    return pdf.output()
