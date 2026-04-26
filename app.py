import streamlit as st
import pandas as pd
import threading
import time
import datetime
from collections import deque, Counter
import sys
import os

# Windows Unicode console fix
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# ── Local IDS Imports ───────────────────────────────────────────
import sniffer
from logger import AlertLogger
from detector import Detector
from scapy.all import sniff as scapy_sniff

# ── Shared State (Thread-Safe) ──────────────────────────────────
@st.cache_resource
def get_shared_state():
    class SharedState:
        def __init__(self):
            self.packet_q = deque(maxlen=200)
            self.alert_q = deque(maxlen=1000)
            self.detector_stats = {
                "unique_sources": 0,
                "unique_connections": 0,
                "total_alerts": 0
            }
            self.total_packets = 0
            self.pps_history = deque([0]*60, maxlen=60)
            self.last_packet_count = 0
            self.ip_counter = Counter()
            self.thread = None
            self.stop_event = None
            self.sniffer = None
            self.start_time = None

        def reset(self):
            self.packet_q.clear()
            self.alert_q.clear()
            self.detector_stats = {
                "unique_sources": 0,
                "unique_connections": 0,
                "total_alerts": 0
            }
            self.total_packets = 0
            self.pps_history = deque([0]*60, maxlen=60)
            self.last_packet_count = 0
            self.ip_counter.clear()
            self.start_time = time.time()

    return SharedState()

state = get_shared_state()

# ── Custom Subclasses for Interception ──────────────────────────
class UIAlertLogger(AlertLogger):
    def alert(self, alert_type: str, message: str, severity: str = "HIGH"):
        super().alert(alert_type, message, severity)
        state.alert_q.appendleft({
            "Timestamp": self._timestamp(),
            "Type": alert_type,
            "Severity": severity,
            "Message": message
        })

class UIDetector(Detector):
    def analyse(self, packet_info: dict):
        super().analyse(packet_info)
        state.packet_q.appendleft(packet_info)
        src_ip = packet_info.get("src_ip")
        if src_ip:
            state.ip_counter[src_ip] += 1
        state.detector_stats = self.get_stats()

# ── Background Thread Function ──────────────────────────────────
def run_sniffer_thread(stop_event):
    def custom_sniff(*args, **kwargs):
        kwargs["stop_filter"] = lambda p: stop_event.is_set()
        return scapy_sniff(*args, **kwargs)
    
    sniffer.sniff = custom_sniff
    
    logger = UIAlertLogger()
    detector = UIDetector(logger)
    s = sniffer.PacketSniffer(detector, logger)
    state.sniffer = s
    
    try:
        s.start()
    except Exception as e:
        logger.alert("SNIFFER_ERROR", f"Thread Error: {e}", "HIGH")

# ── UI Configuration ────────────────────────────────────────────
st.set_page_config(page_title="Network IDS Dashboard", layout="wide", page_icon="🛡️")

# Custom CSS for Animations & UI Styling
st.markdown("""
    <style>
    @keyframes blink {
        0% { opacity: 1; }
        50% { opacity: 0; }
        100% { opacity: 1; }
    }
    .live-indicator {
        color: #ff4b4b;
        font-weight: bold;
        animation: blink 1.5s linear infinite;
        display: inline-block;
        padding: 5px 10px;
        border-radius: 5px;
        background-color: rgba(255, 75, 75, 0.1);
    }
    .status-panel {
        background-color: #1e1e1e;
        padding: 15px;
        border-radius: 10px;
        margin-bottom: 20px;
        border: 1px solid #333;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session running state
if "is_running" not in st.session_state:
    st.session_state.is_running = False

if "last_alert_count" not in st.session_state:
    st.session_state.last_alert_count = 0

# Update Packets Per Second (PPS) if running
current_pps = 0
if st.session_state.is_running and state.sniffer:
    current_packets = state.sniffer.packet_count
    current_pps = current_packets - state.last_packet_count
    state.pps_history.append(current_pps)
    state.last_packet_count = current_packets
    state.total_packets = current_packets

# ── Header ──────────────────────────────────────────────────────
colA, colB = st.columns([3, 1])
with colA:
    st.title("🛡️ Network Intrusion Detection System")
    st.markdown("Real-time monitoring and alert dashboard.")
with colB:
    st.write("") # Spacer
    if st.session_state.is_running:
        st.markdown('<div class="live-indicator">🔴 LIVE RECORDING</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div style="color:#888; font-weight:bold; padding: 5px 10px;">⏹️ OFFLINE</div>', unsafe_allow_html=True)

st.markdown("---")

# ── System Info Panel & Controls ────────────────────────────────
with st.container():
    c_ctrl1, c_ctrl2, c_info1, c_info2, c_info3 = st.columns([1, 1, 1, 1, 1])
    
    with c_ctrl1:
        if st.button("▶ Start IDS", disabled=st.session_state.is_running, use_container_width=True):
            state.reset()
            state.stop_event = threading.Event()
            st.session_state.is_running = True
            st.session_state.last_alert_count = 0
            state.thread = threading.Thread(target=run_sniffer_thread, args=(state.stop_event,), daemon=True)
            state.thread.start()
            st.rerun()
            
    with c_ctrl2:
        if st.button("🛑 Stop IDS", disabled=not st.session_state.is_running, use_container_width=True):
            if state.stop_event:
                state.stop_event.set()
            st.session_state.is_running = False
            st.rerun()
            
    # Calculate Runtime
    runtime_str = "00:00:00"
    if st.session_state.is_running and state.start_time:
        elapsed = int(time.time() - state.start_time)
        runtime_str = str(datetime.timedelta(seconds=elapsed))
        
    c_info1.metric("Status", "Running" if st.session_state.is_running else "Stopped")
    c_info2.metric("Interface", "Default")
    c_info3.metric("Runtime", runtime_str)

st.markdown("<br>", unsafe_allow_html=True)

# ── Live Metrics ────────────────────────────────────────────────
total_alerts = state.detector_stats.get("total_alerts", 0)

# Alert Visual Feedback (Toast)
if total_alerts > st.session_state.last_alert_count:
    diff = total_alerts - st.session_state.last_alert_count
    st.toast(f"🚨 {diff} New Alert(s) Detected!", icon="🚨")
    st.session_state.last_alert_count = total_alerts

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Packets", state.total_packets, delta=f"+{current_pps} pps" if current_pps > 0 else None, delta_color="off")
m2.metric("Total Alerts", total_alerts, delta="Threat Detected!" if total_alerts > 0 else None, delta_color="inverse")
m3.metric("Unique Source IPs", state.detector_stats.get("unique_sources", 0))
m4.metric("Unique Connections", state.detector_stats.get("unique_connections", 0))

st.markdown("<br>", unsafe_allow_html=True)

# ── Main Dashboard Layout ───────────────────────────────────────
c1, c2 = st.columns([2, 1])

with c1:
    st.subheader("🚨 Alerts Panel")
    
    # Advanced Filtering
    f1, f2, f3 = st.columns([1, 1, 1.5])
    sev_filter = f1.selectbox("Severity", ["All", "HIGH", "MEDIUM", "LOW"])
    
    # Extract unique alert types for multiselect
    alerts_list = list(state.alert_q)
    all_types = list(set([a["Type"] for a in alerts_list])) if alerts_list else []
    type_filter = f2.multiselect("Alert Type", options=all_types, default=[])
    
    search_query = f3.text_input("Search IP / Keyword", placeholder="e.g. 192.168.1.1")
    
    if alerts_list:
        df_alerts = pd.DataFrame(alerts_list)
        
        if sev_filter != "All":
            df_alerts = df_alerts[df_alerts["Severity"] == sev_filter]
        
        if type_filter:
            df_alerts = df_alerts[df_alerts["Type"].isin(type_filter)]
            
        if search_query:
            mask = (df_alerts["Message"].str.contains(search_query, case=False, na=False) |
                    df_alerts["Type"].str.contains(search_query, case=False, na=False))
            df_alerts = df_alerts[mask]
        
        # Color formatting for full row
        def highlight_row(row):
            val = row['Severity']
            if val == "HIGH": 
                return ['background-color: rgba(255, 75, 75, 0.2); color: #ff4b4b; font-weight: bold'] * len(row)
            elif val == "MEDIUM": 
                return ['background-color: rgba(255, 161, 0, 0.2); color: #ffa100; font-weight: bold'] * len(row)
            elif val == "LOW": 
                return ['background-color: rgba(0, 180, 216, 0.2); color: #00b4d8; font-weight: bold'] * len(row)
            return [''] * len(row)
            
        styled_alerts = df_alerts.style.apply(highlight_row, axis=1)
        st.dataframe(styled_alerts, use_container_width=True, height=250)
        
    else:
        st.info("No alerts generated yet. System is monitoring...")
        
    st.markdown("<br>", unsafe_allow_html=True)
    st.subheader("📈 Network Traffic (Packets/sec)")
    chart_data = pd.DataFrame({"PPS": list(state.pps_history)})
    st.line_chart(chart_data, height=200, use_container_width=True, color="#00b4d8")

with c2:
    st.subheader("🔥 Top Attackers (Active IPs)")
    if state.ip_counter:
        top_ips = state.ip_counter.most_common(5)
        df_top = pd.DataFrame(top_ips, columns=["IP Address", "Packets"])
        
        st.dataframe(
            df_top,
            column_config={
                "Packets": st.column_config.ProgressColumn(
                    "Packets",
                    help="Traffic volume by IP",
                    format="%d",
                    min_value=0,
                    max_value=int(df_top["Packets"].max()) if not df_top.empty else 100,
                ),
            },
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No data yet.")

    st.markdown("<br>", unsafe_allow_html=True)

    st.subheader("🌐 Live Packet Stream")
    packets_list = list(state.packet_q)[:100]
    if packets_list:
        df_pkts = pd.DataFrame(packets_list)
        df_pkts["Source"] = df_pkts.apply(lambda x: f"{x['src_ip']}:{x['src_port']}" if x.get('src_port') is not None else str(x.get('src_ip')), axis=1)
        df_pkts["Dest"] = df_pkts.apply(lambda x: f"{x['dst_ip']}:{x['dst_port']}" if x.get('dst_port') is not None else str(x.get('dst_ip')), axis=1)
        
        df_pkts = df_pkts[["protocol", "Source", "Dest", "size"]]
        df_pkts.rename(columns={"protocol": "Proto", "size": "Size"}, inplace=True)
        st.dataframe(df_pkts, use_container_width=True, height=200)
    else:
        st.info("No packets captured yet.")

st.markdown("---")

# ── Log Viewer & Exports ────────────────────────────────────────
st.subheader("📜 System Logs & Exports")
log_col, export_col1, export_col2 = st.columns([4, 1, 1])

with log_col:
    try:
        if os.path.exists("alerts.log"):
            with open("alerts.log", "r") as f:
                log_lines = f.readlines()
                st.text_area("Latest `alerts.log` Entries", "".join(log_lines[-30:]), height=150)
        else:
            st.info("`alerts.log` not found. It will be created when alerts occur.")
    except Exception as e:
        st.error(f"Error reading logs: {e}")

with export_col1:
    if alerts_list:
        csv_data = pd.DataFrame(alerts_list).to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Alerts (CSV)",
            data=csv_data,
            file_name="ids_alerts.csv",
            mime="text/csv",
            use_container_width=True
        )

with export_col2:
    if os.path.exists("alerts.log"):
        with open("alerts.log", "rb") as f:
            st.download_button(
                label="📥 Download alerts.log",
                data=f,
                file_name="alerts.log",
                mime="text/plain",
                use_container_width=True
            )

# ── Auto-Refresh Loop ───────────────────────────────────────────
if st.session_state.is_running:
    time.sleep(1.5)
    st.rerun()
