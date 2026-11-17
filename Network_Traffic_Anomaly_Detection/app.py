
import streamlit as st
import pandas as pd
import plotly.express as px
import tempfile

from pathlib import Path
from pcap_analyzer import analyze_pcap, capture_live_traffic


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="NetWatch - Network Traffic Anomaly Detection",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp{background:radial-gradient(circle at 12% 0%,#17243a 0%,#0b1220 42%,#080d17 100%);color:#e8eef8}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#101b2d,#0b1321);border-right:1px solid #263d59}
h1,h2,h3{color:#f4f8ff!important}
div[data-testid="stMetric"]{background:linear-gradient(145deg,#192a42,#0e192a);border:1px solid #294765;padding:18px 20px;border-radius:15px;box-shadow:0 8px 24px #0003}
div[data-testid="stMetric"] label{color:#a9bfd9!important}
div[data-testid="stMetric"] [data-testid="stMetricValue"]{color:#f5f9ff!important;font-weight:750}
div[data-testid="stExpander"]{border:1px solid #294765;border-radius:12px;background:#111d2f99}
div[data-testid="stDataFrame"]{border:1px solid #294765;border-radius:12px;overflow:hidden}
.nw-hero{padding:26px 28px;border:1px solid #31577b;border-radius:18px;background:linear-gradient(110deg,#16304e,#0d192b);margin:8px 0 22px;box-shadow:0 14px 34px #0003}
.nw-eyebrow{color:#70c7ff;font-size:12px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}
.nw-hero h1{margin:7px 0 5px;font-size:36px}
.nw-hero p{color:#b8cbe1;margin:0;font-size:15px}
.nw-status{display:inline-block;margin-top:15px;padding:6px 11px;border-radius:30px;background:#1cbe8720;border:1px solid #37dca455;color:#75edc1;font-size:12px;font-weight:700}
.nw-section-note{color:#91a9c5;font-size:13px;margin-top:-8px;margin-bottom:14px}
.stButton>button,.stDownloadButton>button{border-radius:10px;border:1px solid #59a6f066;font-weight:650}
hr{border-color:#7399c333}
</style>
""", unsafe_allow_html=True)


# ==================================================
# REQUIRED COLUMNS
# ==================================================

REQUIRED = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "destination_port",
    "packet_count",
    "bytes"
]


# ==================================================
# SAFE DETECTION TEST DATA
# ==================================================

def create_test_data():

    demo_time = pd.Timestamp.now(tz="UTC").floor("min")

    records = [

        # High packet count
        {
            "timestamp": demo_time,
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "protocol": "TCP",
            "destination_port": 443,
            "packet_count": 350,
            "bytes": 20000
        },

        # High data volume
        {
            "timestamp": demo_time,
            "source_ip": "192.0.2.30",
            "destination_ip": "192.0.2.40",
            "protocol": "TCP",
            "destination_port": 443,
            "packet_count": 20,
            "bytes": 180000
        },

        # Configured port
        {
            "timestamp": demo_time,
            "source_ip": "192.0.2.50",
            "destination_ip": "192.0.2.60",
            "protocol": "TCP",
            "destination_port": 4444,
            "packet_count": 10,
            "bytes": 1000
        }
    ]

    # Simulated port scan
    for port in range(10000, 10015):

        records.append({
            "timestamp": demo_time,
            "source_ip": "192.0.2.70",
            "destination_ip": "192.0.2.80",
            "protocol": "TCP",
            "destination_port": port,
            "packet_count": 3,
            "bytes": 300
        })

    # Combined indicators: High severity
    records.append({
        "timestamp": demo_time,
        "source_ip": "192.0.2.90",
        "destination_ip": "192.0.2.100",
        "protocol": "TCP",
        "destination_port": 4444,
        "packet_count": 450,
        "bytes": 200000
    })

    return pd.DataFrame(records)


# ==================================================
# PCAP UPLOAD ANALYSIS
# ==================================================

def load_pcap(uploaded_file):

    suffix = Path(uploaded_file.name).suffix

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=suffix,
            delete=False
        ) as temp_file:

            temp_file.write(uploaded_file.getvalue())
            temp_path = temp_file.name

        with st.spinner("Analysing Wireshark capture..."):

            result = analyze_pcap(temp_path)

        return result

    finally:

        if temp_path and Path(temp_path).exists():
            Path(temp_path).unlink(missing_ok=True)


# ==================================================
# ANOMALY DETECTION ENGINE
# ==================================================

def detect_anomalies(
    df,
    packet_limit,
    byte_limit,
    unusual_ports,
    port_scan_limit
):

    df = df.copy()

    df["reasons"] = ""
    df["risk_score"] = 0

    # Rule 1: High packet count
    packet_alert = df["packet_count"] > packet_limit

    df.loc[packet_alert, "reasons"] += "High packet count; "
    df.loc[packet_alert, "risk_score"] += 1

    # Rule 2: High data volume
    volume_alert = df["bytes"] > byte_limit

    df.loc[volume_alert, "reasons"] += "High data volume; "
    df.loc[volume_alert, "risk_score"] += 1

    # Rule 3: Configured destination port
    port_alert = df["destination_port"].isin(unusual_ports)

    df.loc[port_alert, "reasons"] += "Flagged destination port; "
    df.loc[port_alert, "risk_score"] += 1

    # Rule 4: Possible port scan
    df["scan_window"] = df["timestamp"].dt.floor("min")

    valid_ports = df[
        df["destination_port"].between(1, 65535)
    ]

    scan_groups = (
        valid_ports.groupby(
            [
                "scan_window",
                "source_ip",
                "destination_ip"
            ]
        )["destination_port"]
        .nunique()
        .reset_index(name="unique_ports")
    )

    scan_groups = scan_groups[
        scan_groups["unique_ports"] >= port_scan_limit
    ]

    scan_keys = set(
        zip(
            scan_groups["scan_window"],
            scan_groups["source_ip"],
            scan_groups["destination_ip"]
        )
    )

    df["possible_port_scan"] = [
        (
            timestamp,
            source,
            destination
        ) in scan_keys
        for timestamp, source, destination in zip(
            df["scan_window"],
            df["source_ip"],
            df["destination_ip"]
        )
    ]

    scan_alert = df["possible_port_scan"]

    df.loc[scan_alert, "reasons"] += "Possible port scan; "
    df.loc[scan_alert, "risk_score"] += 2

    df.drop(columns=["scan_window"], inplace=True)

    df["reasons"] = df["reasons"].str.rstrip("; ")

    # Severity classification
    def get_severity(score):

        if score == 0:
            return "Normal"

        elif score == 1:
            return "Low"

        elif score == 2:
            return "Medium"

        return "High"

    df["severity"] = df["risk_score"].apply(get_severity)

    df["status"] = df["severity"].apply(
        lambda value:
        "Normal" if value == "Normal"
        else "Suspicious"
    )

    return df


# ==================================================
# APPLICATION HEADER
# ==================================================

st.markdown("""
<div class="nw-hero">
  <div class="nw-eyebrow">Security Operations • Network Intelligence</div>
  <h1>🛡️ NetWatch</h1>
  <p>Network Traffic Anomaly Detection & Monitoring Platform</p>
  <span class="nw-status">● ANALYSIS ENGINE READY</span>
</div>
""", unsafe_allow_html=True)

st.info(
    "NetWatch identifies unusual traffic patterns. "
    "Alerts require investigation and do not prove an attack."
)


# ==================================================
# SIDEBAR SETTINGS
# ==================================================

with st.sidebar:

    st.header("⚙️ Detection Settings")

    packet_limit = st.slider(
        "High packet-count threshold",
        50,
        1000,
        300,
        25
    )

    byte_limit = st.slider(
        "High data-volume threshold (bytes)",
        10000,
        500000,
        150000,
        10000
    )

    unusual_ports_text = st.text_input(
        "Ports to flag",
        "23, 4444, 5555, 6667"
    )

    unusual_ports = []

    for item in unusual_ports_text.split(","):

        try:
            port = int(item.strip())

            if 1 <= port <= 65535:
                unusual_ports.append(port)

        except ValueError:
            pass

    port_scan_limit = st.slider(
        "Port scan detection threshold",
        5,
        30,
        15
    )

    st.markdown("---")

    st.write("Wi-Fi Interface: Interface 4")

    st.caption(
        "Change the interface number in app.py "
        "if your network adapter changes."
    )


# ==================================================
# SELECT TRAFFIC SOURCE
# ==================================================

st.header("📡 Select Traffic Source")

source_mode = st.radio(
    "Choose your analysis mode:",
    [
        "Wireshark PCAP / PCAPNG",
        "Live Wi-Fi Monitoring",
        "Network traffic CSV",
        "Sample dataset",
        "Safe Detection Test Mode"
    ],
    horizontal=False
)


df = None


# ==================================================
# OPTION 1: PCAP / PCAPNG
# ==================================================

if source_mode == "Wireshark PCAP / PCAPNG":

    st.subheader("📂 Upload Wireshark Capture")

    uploaded_pcap = st.file_uploader(
        "Upload PCAP or PCAPNG file",
        type=["pcap", "pcapng"],
        key="pcap_upload"
    )

    if uploaded_pcap is not None:

        try:
            df = load_pcap(uploaded_pcap)

            st.success(
                "Wireshark capture analysed successfully!"
            )

        except Exception as error:

            st.error(f"PCAP analysis failed: {error}")
            st.stop()

    else:

        st.info("Upload a Wireshark capture to continue.")
        st.stop()


# ==================================================
# OPTION 2: LIVE WI-FI MONITORING
# ==================================================

elif source_mode == "Live Wi-Fi Monitoring":

    st.subheader("📶 Live Network Monitoring")

    st.write(
        "Capture actual network packets from your Wi-Fi adapter."
    )

    st.warning(
        "This feature captures traffic on your selected interface. "
        "Use it only on networks and devices you are authorized to monitor."
    )

    duration = st.slider(
        "Capture duration (seconds)",
        min_value=10,
        max_value=60,
        value=15,
        step=5
    )

    st.write("Selected network interface: Wi-Fi (Interface 4)")

    if st.button(
        "▶ Start Live Monitoring",
        type="primary",
        use_container_width=True
    ):

        try:

            with st.spinner(
                f"Capturing network traffic for {duration} seconds..."
            ):

                df = capture_live_traffic(
                    "4",
                    duration
                )

            if df.empty:

                st.warning(
                    "No IP traffic records were found during this capture."
                )

                st.stop()

            st.success(
                "Live network capture completed successfully!"
            )

            st.metric(
                "Packets captured",
                int(df["packet_count"].sum())
            )

            st.metric(
                "Traffic records",
                len(df)
            )

            st.subheader("Captured Network Traffic")

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True
            )

        except Exception as error:

            st.error(
                f"Live monitoring failed: {error}"
            )

            st.info(
                "Check that Wireshark and Npcap are installed, "
                "and that the selected interface is available. "
                "If permission is denied, try running the terminal "
                "as Administrator."
            )

            st.stop()

    else:

        st.info(
            "Click Start Live Monitoring to capture network traffic."
        )

        st.stop()


# ==================================================
# OPTION 3: CSV UPLOAD
# ==================================================

elif source_mode == "Network traffic CSV":

    st.subheader("📄 Upload Network Traffic CSV")

    uploaded_csv = st.file_uploader(
        "Choose CSV file",
        type=["csv"],
        key="csv_upload"
    )

    if uploaded_csv is not None:

        try:
            df = pd.read_csv(uploaded_csv)

        except Exception as error:

            st.error(f"Could not read CSV: {error}")
            st.stop()

    else:

        st.info("Upload a CSV file to continue.")
        st.stop()


# ==================================================
# OPTION 4: SAMPLE DATASET
# ==================================================

elif source_mode == "Sample dataset":

    sample_path = (
        Path(__file__).parent
        / "data"
        / "sample_traffic.csv"
    )

    if sample_path.exists():

        df = pd.read_csv(sample_path)

        st.info("Using the included sample traffic dataset.")

    else:

        st.error("Sample dataset not found.")
        st.stop()


# ==================================================
# OPTION 5: SAFE DETECTION TEST MODE
# ==================================================

elif source_mode == "Safe Detection Test Mode":

    st.warning(
        "Simulated traffic is being used. "
        "No real network traffic or attacks are generated."
    )

    df = create_test_data()

    st.success("Safe Detection Test Mode activated!")


# ==================================================
# VALIDATE TRAFFIC DATA
# ==================================================

if df is None or df.empty:

    st.warning("No traffic records available.")
    st.stop()


missing = [
    column for column in REQUIRED
    if column not in df.columns
]

if missing:

    st.error(
        "Missing required columns: "
        + ", ".join(missing)
    )

    st.stop()


df = df.copy()

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce",
    utc=True
)

for column in [
    "destination_port",
    "packet_count",
    "bytes"
]:

    df[column] = pd.to_numeric(
        df[column],
        errors="coerce"
    )


df = df.dropna(
    subset=[
        "timestamp",
        "source_ip",
        "destination_ip",
        "destination_port",
        "packet_count",
        "bytes"
    ]
)

if df.empty:

    st.error("No valid network traffic records found.")
    st.stop()


df["destination_port"] = df["destination_port"].astype(int)

df["packet_count"] = df["packet_count"].clip(lower=0)

df["bytes"] = df["bytes"].clip(lower=0)


# ==================================================
# RUN ANOMALY DETECTION
# ==================================================

df = detect_anomalies(
    df,
    packet_limit,
    byte_limit,
    unusual_ports,
    port_scan_limit
)


# ==================================================
# DASHBOARD METRICS
# ==================================================

st.header("📊 Security Operations Overview")
st.markdown('<div class="nw-section-note">A summary of the selected traffic source and detected risk indicators.</div>', unsafe_allow_html=True)

total = len(df)

suspicious = int(
    (df["status"] == "Suspicious").sum()
)

normal = total - suspicious

detection_rate = (
    suspicious / total * 100
    if total > 0
    else 0
)

high_count = int(
    (df["severity"] == "High").sum()
)

medium_count = int(
    (df["severity"] == "Medium").sum()
)

low_count = int(
    (df["severity"] == "Low").sum()
)


c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Records", total)

c2.metric("Normal Records", normal)

c3.metric("Suspicious Records", suspicious)

c4.metric("Detection Rate", f"{detection_rate:.1f}%")


# ==================================================
# SEVERITY OVERVIEW
# ==================================================

st.subheader("🚨 Alert Severity Overview")

s1, s2, s3 = st.columns(3)

s1.metric("🔴 High Severity", high_count)

s2.metric("🟠 Medium Severity", medium_count)

s3.metric("🟡 Low Severity", low_count)

if suspicious == 0:
    st.success("No records triggered the configured anomaly rules in this dataset.")
else:
    st.warning(f"{suspicious} record(s) triggered anomaly rules. Review the detection results below.")


with st.expander("Understand the risk scoring system"):

    st.write(
        """
        NetWatch assigns risk points using four rules:

        1. High packet count: +1 point
        2. High data volume: +1 point
        3. Configured destination port: +1 point
        4. Possible port scan: +2 points

        Severity:

        - 0 points = Normal
        - 1 point = Low
        - 2 points = Medium
        - 3 or more points = High

        These are preliminary risk levels, not confirmed attacks.
        """
    )


# ==================================================
# TRAFFIC BY PROTOCOL
# ==================================================

st.header("📈 Network Intelligence & Traffic Analytics")
st.markdown('<div class="nw-section-note">Explore protocol distribution, severity levels and traffic trends.</div>', unsafe_allow_html=True)

left, right = st.columns(2)

with left:

    st.subheader("Traffic by Protocol")

    protocol_counts = (
        df["protocol"]
        .astype(str)
        .value_counts()
        .rename_axis("protocol")
        .reset_index(name="records")
    )

    fig_protocol = px.pie(
        protocol_counts,
        names="protocol",
        values="records",
        hole=0.45,
        title="Protocol Distribution"
    )

    st.plotly_chart(
        fig_protocol,
        use_container_width=True
    )


# ==================================================
# SEVERITY CHART
# ==================================================

with right:

    st.subheader("Severity Distribution")

    severity_order = [
        "Normal",
        "Low",
        "Medium",
        "High"
    ]

    severity_counts = (
        df["severity"]
        .value_counts()
        .reindex(
            severity_order,
            fill_value=0
        )
        .rename_axis("severity")
        .reset_index(name="records")
    )

    fig_severity = px.bar(
        severity_counts,
        x="severity",
        y="records",
        color="severity",
        title="Alert Severity Distribution",
        category_orders={
            "severity": severity_order
        },
        color_discrete_map={
            "Normal": "green",
            "Low": "yellow",
            "Medium": "orange",
            "High": "red"
        }
    )

    st.plotly_chart(
        fig_severity,
        use_container_width=True
    )


# ==================================================
# TRAFFIC OVER TIME
# ==================================================

st.subheader("Network Traffic Over Time")

timeline = (
    df.set_index("timestamp")
    .resample("5min")
    .agg(
        records=("source_ip", "count"),
        total_bytes=("bytes", "sum")
    )
    .reset_index()
)

fig_timeline = px.line(
    timeline,
    x="timestamp",
    y="records",
    markers=True,
    title="Traffic Records Over Time"
)

st.plotly_chart(
    fig_timeline,
    use_container_width=True
)


# ==================================================
# NETWORK INTELLIGENCE SNAPSHOTS
# ==================================================

st.subheader("🧭 Network Intelligence Snapshots")
snap1, snap2, snap3 = st.columns(3)
top_source = df["source_ip"].astype(str).value_counts().head(1)
top_destination = df["destination_ip"].astype(str).value_counts().head(1)
top_protocol = df["protocol"].astype(str).value_counts().head(1)
snap1.metric("Top Talker (Source)", top_source.index[0] if not top_source.empty else "N/A")
snap2.metric("Most Contacted Destination", top_destination.index[0] if not top_destination.empty else "N/A")
snap3.metric("Most Used Protocol", top_protocol.index[0] if not top_protocol.empty else "N/A")

# ==================================================
# DETECTION RESULTS
# ==================================================

st.header("🔍 Threat Detection Centre")
st.markdown('<div class="nw-section-note">Review flagged connections, risk scores and alert reasons.</div>', unsafe_allow_html=True)

severity_filter = st.selectbox(
    "Filter by severity",
    [
        "All",
        "High",
        "Medium",
        "Low",
        "Normal"
    ]
)

if severity_filter == "All":

    view = df.copy()

else:

    view = df[
        df["severity"] == severity_filter
    ]


display_columns = REQUIRED + [
    "risk_score",
    "severity",
    "status",
    "reasons"
]

st.caption(f"Showing {len(view)} of {len(df)} traffic record(s).")
if view.empty:
    st.info("No records match the selected severity filter.")
else:
    st.dataframe(
        view[display_columns],
        use_container_width=True,
        hide_index=True
    )


# ==================================================
# DOWNLOAD REPORTS
# ==================================================

st.header("📥 Export & Incident Reports")
st.markdown('<div class="nw-section-note">Export suspicious records or the complete analysis.</div>', unsafe_allow_html=True)

suspicious_df = df[
    df["status"] == "Suspicious"
]

report_columns = REQUIRED + [
    "risk_score",
    "severity",
    "status",
    "reasons"
]

report = suspicious_df[
    report_columns
].to_csv(index=False).encode("utf-8")

st.download_button(
    "⬇️ Download Suspicious Traffic Report",
    data=report,
    file_name="netwatch_suspicious_report.csv",
    mime="text/csv"
)


all_report = df[
    display_columns
].to_csv(index=False).encode("utf-8")

st.download_button(
    "⬇️ Download Complete Traffic Analysis",
    data=all_report,
    file_name="netwatch_complete_analysis.csv",
    mime="text/csv"
)


# ==================================================
# FOOTER
# ==================================================

st.markdown("---")

st.caption(
    "NetWatch | Network Traffic Anomaly Detection System"
)

st.caption(
    "Educational cybersecurity project. "
    "Rule-based alerts require further investigation."
)
