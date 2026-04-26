import streamlit as st
import pandas as pd
import threading
import time
import datetime
import os
import sys
import numpy as np
from collections import deque, Counter

# Windows Unicode console fix
if hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8')
    except Exception: pass

# ── Local IDS Imports ───────────────────────────────────────────
import sniffer
from logger import AlertLogger
from detector import Detector
from scapy.all import sniff as scapy_sniff
from ids_helpers import (
    get_ip_geolocation, enrich_ip_with_geo,
    detect_pps_anomaly, detect_port_anomaly,
    send_email_alert, analyze_pcap_file,
    run_simulation, generate_pdf_report,
)

# ── Page Config (MUST be first st command) ──────────────────────
st.set_page_config(page_title="Network IDS Dashboard", layout="wide", page_icon="🛡️")

# ── Shared State (Thread-Safe) ──────────────────────────────────
@st.cache_resource
def get_shared_state():
    class SharedState:
        def __init__(self):
            self.packet_q = deque(maxlen=200)
            self.alert_q = deque(maxlen=1000)
            self.detector_stats = {"unique_sources":0,"unique_connections":0,"total_alerts":0}
            self.total_packets = 0
            self.pps_history = deque([0]*60, maxlen=60)
            self.last_packet_count = 0
            self.ip_counter = Counter()
            self.port_counter = Counter()
            self.thread = None
            self.stop_event = None
            self.sniffer = None
            self.start_time = None
            self.blocked_ips = set()
            self.alert_timestamps = deque(maxlen=500)
        def reset(self):
            self.packet_q.clear(); self.alert_q.clear()
            self.detector_stats = {"unique_sources":0,"unique_connections":0,"total_alerts":0}
            self.total_packets = 0
            self.pps_history = deque([0]*60, maxlen=60)
            self.last_packet_count = 0
            self.ip_counter.clear(); self.port_counter.clear()
            self.start_time = time.time()
            self.blocked_ips.clear(); self.alert_timestamps.clear()
    return SharedState()

state = get_shared_state()

# ── Custom Subclasses ───────────────────────────────────────────
class UIAlertLogger(AlertLogger):
    def alert(self, alert_type, message, severity="HIGH"):
        super().alert(alert_type, message, severity)
        ts = self._timestamp()
        alert_data = {"Timestamp": ts, "Type": alert_type, "Severity": severity, "Message": message}
        state.alert_q.appendleft(alert_data)
        state.alert_timestamps.appendleft(ts)
        # Auto-block HIGH severity source IPs (simulated IPS)
        if severity == "HIGH":
            import re
            ips = re.findall(r'\d+\.\d+\.\d+\.\d+', message)
            if ips:
                state.blocked_ips.add(ips[0])

class UIDetector(Detector):
    def analyse(self, packet_info):
        super().analyse(packet_info)
        state.packet_q.appendleft(packet_info)
        src = packet_info.get("src_ip")
        if src: state.ip_counter[src] += 1
        dp = packet_info.get("dst_port")
        if dp: state.port_counter[dp] += 1
        state.detector_stats = self.get_stats()

# ── Background Thread ───────────────────────────────────────────
def run_sniffer_thread(stop_event):
    def custom_sniff(*args, **kwargs):
        kwargs["stop_filter"] = lambda p: stop_event.is_set()
        return scapy_sniff(*args, **kwargs)
    sniffer.sniff = custom_sniff
    logger = UIAlertLogger()
    detector = UIDetector(logger)
    s = sniffer.PacketSniffer(detector, logger)
    state.sniffer = s
    try: s.start()
    except Exception as e: logger.alert("SNIFFER_ERROR", f"Thread Error: {e}", "HIGH")

# ══════════════════════════════════════════════════════════════════
#  CUSTOM CSS — Dark Cybersecurity Theme
# ══════════════════════════════════════════════════════════════════
st.markdown("""<style>
@keyframes blink { 0%{opacity:1} 50%{opacity:0.2} 100%{opacity:1} }
@keyframes pulse { 0%{box-shadow:0 0 5px #ff4b4b} 50%{box-shadow:0 0 20px #ff4b4b} 100%{box-shadow:0 0 5px #ff4b4b} }
.live-badge {
    color:#ff4b4b; font-weight:bold; font-size:1.1em;
    animation: blink 1.2s linear infinite;
    background: rgba(255,75,75,0.1); padding:6px 14px;
    border-radius:20px; border:1px solid rgba(255,75,75,0.3);
}
.offline-badge {
    color:#666; font-weight:bold; padding:6px 14px;
    border-radius:20px; border:1px solid #333;
}
.threat-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border-left: 4px solid #ff4b4b; padding:10px 14px;
    border-radius:8px; margin:4px 0; font-size:0.85em; color:#e0e0e0;
}
.threat-card-med { border-left-color: #ffa100; }
.threat-card-low { border-left-color: #00b4d8; }
.section-title { color:#00b4d8; font-size:1.1em; font-weight:bold; margin:10px 0 5px 0; }
</style>""", unsafe_allow_html=True)

# ── Session State Init ──────────────────────────────────────────
for key, val in [("is_running", False), ("last_alert_count", 0),
                 ("email_enabled", False), ("sim_results", None)]:
    if key not in st.session_state:
        st.session_state[key] = val

# ── PPS Update ──────────────────────────────────────────────────
current_pps = 0
if st.session_state.is_running and state.sniffer:
    current_packets = state.sniffer.packet_count
    current_pps = current_packets - state.last_packet_count
    state.pps_history.append(current_pps)
    state.last_packet_count = current_packets
    state.total_packets = current_packets
    # Anomaly detection
    anomaly = detect_pps_anomaly(list(state.pps_history), current_pps)
    if anomaly:
        state.alert_q.appendleft(anomaly)
        state.alert_timestamps.appendleft(anomaly["Timestamp"])

# ══════════════════════════════════════════════════════════════════
#  HEADER
# ══════════════════════════════════════════════════════════════════
hdr1, hdr2 = st.columns([3, 1])
with hdr1:
    st.title("🛡️ Network Intrusion Detection System")
    st.caption("Real-time SOC-style monitoring • Anomaly Detection • Threat Intelligence")
with hdr2:
    st.write("")
    if st.session_state.is_running:
        st.markdown('<div class="live-badge">🔴 LIVE MONITORING</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="offline-badge">⏹️ SYSTEM OFFLINE</div>', unsafe_allow_html=True)

st.markdown("---")

# ── Controls Row ────────────────────────────────────────────────
cc1, cc2, ci1, ci2, ci3, ci4 = st.columns([1,1,1,1,1,1])
with cc1:
    if st.button("▶ Start IDS", disabled=st.session_state.is_running, use_container_width=True):
        state.reset(); state.stop_event = threading.Event()
        st.session_state.is_running = True; st.session_state.last_alert_count = 0
        state.thread = threading.Thread(target=run_sniffer_thread, args=(state.stop_event,), daemon=True)
        state.thread.start(); st.rerun()
with cc2:
    if st.button("🛑 Stop IDS", disabled=not st.session_state.is_running, use_container_width=True):
        if state.stop_event: state.stop_event.set()
        st.session_state.is_running = False; st.rerun()

runtime_str = "00:00:00"
if st.session_state.is_running and state.start_time:
    runtime_str = str(datetime.timedelta(seconds=int(time.time() - state.start_time)))

ci1.metric("Status", "🟢 Running" if st.session_state.is_running else "🔴 Stopped")
ci2.metric("Interface", "Default")
ci3.metric("Runtime", runtime_str)
ci4.metric("PPS", f"{current_pps}")

# ── Alert toast ─────────────────────────────────────────────────
total_alerts = state.detector_stats.get("total_alerts", 0) + len([
    a for a in state.alert_q if a.get("Type") in ("ANOMALY_DETECTED",)
    and "[SIMULATED]" not in a.get("Message", "")
])
if len(state.alert_q) > st.session_state.last_alert_count:
    diff = len(state.alert_q) - st.session_state.last_alert_count
    if diff > 0:
        st.toast(f"🚨 {diff} New Alert(s)!", icon="🚨")
    st.session_state.last_alert_count = len(state.alert_q)

st.markdown("")

# ══════════════════════════════════════════════════════════════════
#  TABS
# ══════════════════════════════════════════════════════════════════
tab_dash, tab_alerts, tab_analytics, tab_sim, tab_settings = st.tabs([
    "🛡️ Dashboard", "🚨 Alerts", "📊 Analytics", "🔬 Simulation", "⚙️ Settings"
])

alerts_list = list(state.alert_q)

# ══════════════════════════════════════════════════════════════════
#  TAB 1: DASHBOARD
# ══════════════════════════════════════════════════════════════════
with tab_dash:
    # Metrics row
    m1,m2,m3,m4 = st.columns(4)
    m1.metric("Total Packets", f"{state.total_packets:,}",
              delta=f"+{current_pps}/s" if current_pps > 0 else None, delta_color="off")
    m2.metric("Total Alerts", len(alerts_list),
              delta="⚠ Active" if len(alerts_list)>0 else None, delta_color="inverse")
    m3.metric("Unique IPs", state.detector_stats.get("unique_sources",0))
    m4.metric("Blocked IPs", len(state.blocked_ips))

    st.markdown("")
    d1, d2 = st.columns([2,1])

    with d1:
        # PPS Chart
        st.markdown('<div class="section-title">📈 Network Traffic (Packets/sec)</div>', unsafe_allow_html=True)
        chart_df = pd.DataFrame({"PPS": list(state.pps_history)})
        st.area_chart(chart_df, height=180, use_container_width=True, color="#00b4d8")

        # Alerts over time
        st.markdown('<div class="section-title">📊 Alerts Over Time</div>', unsafe_allow_html=True)
        if alerts_list:
            ts_list = [a.get("Timestamp","") for a in alerts_list if a.get("Timestamp")]
            if ts_list:
                ts_df = pd.DataFrame({"ts": pd.to_datetime(ts_list, errors="coerce")}).dropna()
                if not ts_df.empty:
                    ts_df["minute"] = ts_df["ts"].dt.floor("min")
                    aot = ts_df.groupby("minute").size().reset_index(name="Alerts")
                    st.bar_chart(aot.set_index("minute"), height=150, use_container_width=True, color="#ff4b4b")
                else:
                    st.info("Collecting alert timestamps...")
            else:
                st.info("No alert timestamps yet.")
        else:
            st.info("No alerts yet.")

    with d2:
        # Severity Pie
        st.markdown('<div class="section-title">🎯 Severity Distribution</div>', unsafe_allow_html=True)
        if alerts_list:
            sev_counts = Counter(a.get("Severity","UNKNOWN") for a in alerts_list)
            sev_df = pd.DataFrame(list(sev_counts.items()), columns=["Severity","Count"])
            st.bar_chart(sev_df.set_index("Severity"), height=180, color="#ffa100")
        else:
            st.info("No data.")

        # Top Attackers with Geo
        st.markdown('<div class="section-title">🔥 Top Attackers</div>', unsafe_allow_html=True)
        if state.ip_counter:
            top5 = state.ip_counter.most_common(5)
            rows = []
            for ip, count in top5:
                geo = enrich_ip_with_geo(ip)
                rows.append({"IP": ip, "Packets": count, "Location": geo})
            df_top = pd.DataFrame(rows)
            st.dataframe(df_top, hide_index=True, use_container_width=True,
                         column_config={"Packets": st.column_config.ProgressColumn(
                             "Packets", format="%d", min_value=0,
                             max_value=int(df_top["Packets"].max()) if not df_top.empty else 100)})
        else:
            st.info("No traffic yet.")

        # Live Threat Feed
        st.markdown('<div class="section-title">🔔 Live Threat Feed</div>', unsafe_allow_html=True)
        recent = alerts_list[:8]
        if recent:
            for a in recent:
                sev = a.get("Severity","LOW")
                cls = "threat-card" if sev=="HIGH" else ("threat-card threat-card-med" if sev=="MEDIUM" else "threat-card threat-card-low")
                st.markdown(f'<div class="{cls}"><b>[{sev}]</b> {a.get("Type","")} — {a.get("Message","")[:80]}</div>', unsafe_allow_html=True)
        else:
            st.info("No threats detected.")

# ══════════════════════════════════════════════════════════════════
#  TAB 2: ALERTS
# ══════════════════════════════════════════════════════════════════
with tab_alerts:
    st.subheader("🚨 Alert Management")
    f1,f2,f3 = st.columns([1,1,1.5])
    sev_filter = f1.selectbox("Severity", ["All","HIGH","MEDIUM","LOW"])
    all_types = sorted(set(a["Type"] for a in alerts_list)) if alerts_list else []
    type_filter = f2.multiselect("Alert Type", options=all_types, default=[])
    search_q = f3.text_input("Search IP / Keyword", placeholder="e.g. 192.168.1.1")

    if alerts_list:
        df_a = pd.DataFrame(alerts_list)
        if sev_filter != "All": df_a = df_a[df_a["Severity"]==sev_filter]
        if type_filter: df_a = df_a[df_a["Type"].isin(type_filter)]
        if search_q:
            mask = (df_a["Message"].str.contains(search_q, case=False, na=False) |
                    df_a["Type"].str.contains(search_q, case=False, na=False))
            df_a = df_a[mask]

        def hl_row(row):
            s = row["Severity"]
            if s=="HIGH": return ['background-color:rgba(255,75,75,0.15);color:#ff4b4b;font-weight:bold']*len(row)
            if s=="MEDIUM": return ['background-color:rgba(255,161,0,0.15);color:#ffa100;font-weight:bold']*len(row)
            if s=="LOW": return ['background-color:rgba(0,180,216,0.15);color:#00b4d8']*len(row)
            return ['']*len(row)

        st.dataframe(df_a.style.apply(hl_row, axis=1), use_container_width=True, height=350)

        # Exports
        ex1, ex2, ex3 = st.columns(3)
        with ex1:
            st.download_button("📥 Export CSV", df_a.to_csv(index=False).encode('utf-8'),
                               "ids_alerts.csv", "text/csv", use_container_width=True)
        with ex2:
            if os.path.exists("alerts.log"):
                with open("alerts.log","rb") as f:
                    st.download_button("📥 Download alerts.log", f, "alerts.log",
                                       "text/plain", use_container_width=True)
        with ex3:
            try:
                pdf_bytes = generate_pdf_report(alerts_list, state.detector_stats)
                st.download_button("📥 Download PDF Report", pdf_bytes,
                                   "ids_report.pdf", "application/pdf", use_container_width=True)
            except Exception:
                st.button("📥 PDF (unavailable)", disabled=True, use_container_width=True)
    else:
        st.info("No alerts generated yet. Start the IDS to begin monitoring.")

    # Log Viewer
    st.markdown("---")
    st.subheader("📜 System Log Viewer")
    try:
        if os.path.exists("alerts.log"):
            with open("alerts.log","r") as f:
                lines = f.readlines()
            st.text_area("alerts.log (last 25 lines)", "".join(lines[-25:]), height=150)
        else:
            st.info("alerts.log will appear after first alert.")
    except Exception as e:
        st.error(f"Log read error: {e}")

# ══════════════════════════════════════════════════════════════════
#  TAB 3: ANALYTICS
# ══════════════════════════════════════════════════════════════════
with tab_analytics:
    st.subheader("📊 Smart Analytics")
    a1,a2,a3 = st.columns(3)

    # Most Active IP
    if state.ip_counter:
        top_ip, top_count = state.ip_counter.most_common(1)[0]
        a1.metric("🏆 Most Active IP", top_ip, delta=f"{top_count} packets")
    else:
        a1.metric("🏆 Most Active IP", "N/A")

    # Most Targeted Port
    if state.port_counter:
        top_port, port_count = state.port_counter.most_common(1)[0]
        a2.metric("🎯 Most Targeted Port", str(top_port), delta=f"{port_count} hits")
    else:
        a2.metric("🎯 Most Targeted Port", "N/A")

    # Total alert types
    a3.metric("📋 Alert Types", len(set(a["Type"] for a in alerts_list)) if alerts_list else 0)

    st.markdown("")
    an1, an2 = st.columns(2)

    with an1:
        st.markdown('<div class="section-title">📊 Alerts by Type</div>', unsafe_allow_html=True)
        if alerts_list:
            type_counts = Counter(a["Type"] for a in alerts_list)
            tc_df = pd.DataFrame(list(type_counts.items()), columns=["Type","Count"])
            st.bar_chart(tc_df.set_index("Type"), height=250, color="#00b4d8")
        else:
            st.info("No data yet.")

    with an2:
        st.markdown('<div class="section-title">🌐 Live Packet Stream</div>', unsafe_allow_html=True)
        pkts = list(state.packet_q)[:50]
        if pkts:
            df_p = pd.DataFrame(pkts)
            df_p["Source"] = df_p.apply(
                lambda x: f"{x['src_ip']}:{x['src_port']}" if x.get('src_port') else str(x.get('src_ip','')), axis=1)
            df_p["Dest"] = df_p.apply(
                lambda x: f"{x['dst_ip']}:{x['dst_port']}" if x.get('dst_port') else str(x.get('dst_ip','')), axis=1)
            st.dataframe(df_p[["protocol","Source","Dest","size"]].rename(
                columns={"protocol":"Proto","size":"Size"}), use_container_width=True, height=250)
        else:
            st.info("No packets yet.")

    # Blocked IPs Panel (Simulated IPS)
    st.markdown("---")
    st.subheader("🚫 Blocked IPs (Simulated IPS)")
    if state.blocked_ips:
        blocked_rows = []
        for ip in list(state.blocked_ips)[:20]:
            geo = enrich_ip_with_geo(ip)
            blocked_rows.append({"IP Address": ip, "Location": geo, "Status": "🔒 BLOCKED"})
        st.dataframe(pd.DataFrame(blocked_rows), hide_index=True, use_container_width=True)
    else:
        st.info("No IPs blocked yet. HIGH severity alerts auto-block source IPs.")

# ══════════════════════════════════════════════════════════════════
#  TAB 4: SIMULATION
# ══════════════════════════════════════════════════════════════════
with tab_sim:
    st.subheader("🔬 Attack Simulation & PCAP Analysis")
    st.caption("Generate synthetic attacks or analyze captured traffic files.")

    sim1, sim2 = st.columns(2)
    with sim1:
        st.markdown('<div class="section-title">⚡ Attack Simulation</div>', unsafe_allow_html=True)
        st.markdown("Simulate attacks to test detection rules. All events are labeled `[SIMULATED]`.")

        s1,s2,s3 = st.columns(3)
        with s1:
            if st.button("💥 Packet Flood", use_container_width=True):
                result = run_simulation("flood", state,
                    lambda a: state.alert_q.appendleft(a), state.ip_counter)
                st.session_state.sim_results = result
                st.rerun()
        with s2:
            if st.button("🔍 Port Scan", use_container_width=True):
                result = run_simulation("port_scan", state,
                    lambda a: state.alert_q.appendleft(a), state.ip_counter)
                st.session_state.sim_results = result
                st.rerun()
        with s3:
            if st.button("⛔ Blacklist Hit", use_container_width=True):
                result = run_simulation("blacklist", state,
                    lambda a: state.alert_q.appendleft(a), state.ip_counter)
                st.session_state.sim_results = result
                st.rerun()

        if st.session_state.sim_results:
            r = st.session_state.sim_results
            st.success(f"✅ Simulation complete: {r.get('packets_generated',0)} packets → {r.get('alerts_triggered',0)} alerts")
            if r.get("alerts"):
                st.dataframe(pd.DataFrame(r["alerts"]), use_container_width=True, height=200)

    with sim2:
        st.markdown('<div class="section-title">📁 PCAP File Analysis</div>', unsafe_allow_html=True)
        st.markdown("Upload a `.pcap` file to analyze with the IDS detection engine.")
        uploaded = st.file_uploader("Choose a PCAP file", type=["pcap","pcapng"], label_visibility="collapsed")
        if uploaded:
            with st.spinner("Analyzing PCAP file..."):
                pcap_alerts, pcap_packets = analyze_pcap_file(uploaded.read())
            st.success(f"✅ Analyzed {len(pcap_packets)} packets → {len(pcap_alerts)} alerts")
            if pcap_alerts:
                st.dataframe(pd.DataFrame(pcap_alerts), use_container_width=True, height=200)
            if pcap_packets:
                with st.expander("📦 View Parsed Packets"):
                    df_pcap = pd.DataFrame(pcap_packets[:100])
                    st.dataframe(df_pcap, use_container_width=True, height=200)

# ══════════════════════════════════════════════════════════════════
#  TAB 5: SETTINGS
# ══════════════════════════════════════════════════════════════════
with tab_settings:
    st.subheader("⚙️ Configuration")

    st.markdown('<div class="section-title">📧 Email Alerts (HIGH Severity)</div>', unsafe_allow_html=True)
    email_on = st.toggle("Enable Email Alerts", value=st.session_state.email_enabled)
    st.session_state.email_enabled = email_on

    if email_on:
        with st.form("email_config"):
            e1,e2 = st.columns(2)
            smtp_server = e1.text_input("SMTP Server", value="smtp.gmail.com")
            smtp_port = e2.number_input("SMTP Port", value=587, min_value=1, max_value=65535)
            sender = e1.text_input("Sender Email", placeholder="your.email@gmail.com")
            password = e2.text_input("App Password", type="password", placeholder="xxxx xxxx xxxx xxxx")
            recipient = e1.text_input("Recipient Email", placeholder="recipient@example.com")
            if st.form_submit_button("💾 Save & Test"):
                if all([smtp_server, sender, password, recipient]):
                    test_alert = {"Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                  "Type": "TEST_ALERT", "Severity": "HIGH",
                                  "Message": "This is a test alert from the Network IDS."}
                    ok = send_email_alert(smtp_server, smtp_port, sender, password, recipient, test_alert)
                    if ok: st.success("✅ Test email sent!")
                    else: st.error("❌ Failed. Check credentials and allow 'less secure apps' or use App Password.")
                else:
                    st.warning("Please fill in all fields.")
    else:
        st.info("Email alerts are disabled. Toggle above to configure SMTP.")

    st.markdown("---")
    st.markdown('<div class="section-title">ℹ️ System Information</div>', unsafe_allow_html=True)
    si1,si2,si3 = st.columns(3)
    si1.metric("Python Version", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    si2.metric("Alert Queue Size", f"{len(state.alert_q)}/1000")
    si3.metric("Packet Buffer", f"{len(state.packet_q)}/200")

# ── Auto-Refresh ────────────────────────────────────────────────
if st.session_state.is_running:
    time.sleep(1.5)
    st.rerun()
