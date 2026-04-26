🛡️ Network Intrusion Detection System (IDS)

A real-time Network Intrusion Detection System (IDS) built using Python and Scapy, with an interactive Streamlit dashboard for monitoring, visualization, and alerting.

📌 Overview

This project captures live network traffic, analyzes packets using rule-based detection, and generates alerts for suspicious activities such as:

🚨 Packet Flood (DoS-like behavior)
🔌 Suspicious Port Access (SSH, Telnet, RDP, etc.)
🔄 Repeated Connections (Brute-force / Port scanning)
🚫 Blacklisted IP Communication

The system provides a real-time dashboard UI to visualize traffic and alerts.

🎯 Features

🔍 Core IDS Features

Real-time packet sniffing using Scapy
Rule-based intrusion detection
Detection of multiple attack patterns
Configurable thresholds and rules
Alert logging with timestamps

💻 UI Dashboard (Streamlit)

 📊 Live metrics (packets, alerts, IPs, connections)
 🚨 Alerts panel with filtering & search
 📡 Live packet stream
 📈 Real-time traffic graph
 🌍 Top attackers (most active IPs)
 📁 Log viewer + download option
 ▶️ Start / Stop IDS controls
 
🧠 Concepts Covered

Packet Sniffing
TCP/IP Protocol Stack
Ports & Services
Network Security (IDS)
Traffic Analysis
Rule-Based Detection Systems

🏗️ Project Structure

network_ids/
│
├── main.py           # Entry point
├── sniffer.py        # Packet capture using Scapy
├── detector.py       # Detection logic (rules)
├── logger.py         # Alert logging
├── config.py         # Configurable rules & thresholds
├── test_detector.py  # Unit tests
├── alerts.log        # Generated log file
├── app.py            # Streamlit UI dashboard
└── README.md
```
⚙️ Installation

1. Clone the repository

git clone https://github.com/srushtim1307/Network_Intrusion_Detection.git
cd network-ids
```

2. Install dependencies
pip install scapy streamlit

3. (Linux only)

sudo apt install libpcap-dev

🚀 How to Run

▶️ Run IDS (Terminal Mode)

sudo python main.py
💻 Run UI Dashboard

streamlit run app.py

🧪 Testing the System

✅ Generate Normal Traffic

Open browser (YouTube, Google)
Observe live packets

🚨 Simulate Attacks
🔌 Suspicious Port Access

ssh localhost

🔄 Repeated Connections

for i in {1..60}; do curl http://localhost; done

🌊 Packet Flood

ping -f 127.0.0.1   # Linux
ping -t 127.0.0.1   # Windows

🚫 Blacklisted IP

Add IP in `config.py`
Generate traffic from that IP

📊 Sample Alerts

```
[HIGH] PACKET_FLOOD – Too many packets from single IP
[MEDIUM] SUSPICIOUS_PORT – Access to port 22 (SSH)
[MEDIUM] REPEATED_CONNECTION – Possible brute-force attack
[HIGH] BLACKLISTED_IP – Known malicious IP detected
```

🧩 How It Works

```
Network Traffic → Sniffer → Detector → Logger → Dashboard
```

1. Sniffer captures packets
2. Detector applies rules
3. Logger generates alerts
4. Dashboard displays results

⚠️ Requirements

Python 3.10+
Administrator / Root privileges (for packet sniffing)
Internet or local network traffic

🚀 Future Improvements

🤖 Machine Learning-based detection
🌐 IP Geolocation
📡 PCAP file analysis mode
🔔 Email / Slack alerts
🖥️ Advanced web dashboard (React)


🎓 Viva / Explanation

This project demonstrates how a **rule-based Intrusion Detection System (IDS)** works by monitoring network traffic, analyzing packet behavior, and detecting suspicious patterns in real time.


## 📜 License

This project is for educational purposes.
