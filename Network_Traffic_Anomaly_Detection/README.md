# NetWatch — Network Traffic Anomaly Detection System

A beginner-friendly cybersecurity learning project. It reads network-traffic records from a CSV file and applies transparent rules to flag records for review.

## What it does
- Loads a sample CSV or a CSV uploaded by the user.
- Checks packet count, byte volume, and selected destination ports.
- Labels records Normal or Suspicious.
- Shows summary metrics and charts.
- Exports flagged records to a CSV report.

## Important limitation
This first version does **not** capture live network packets and does **not** prove that a record is malicious. The rules are simple educational heuristics. A flagged record should be investigated, not treated as a confirmed attack.

## Windows 11 setup

1. Install Python 3.11 or newer from https://www.python.org/downloads/
   During installation, tick **Add Python to PATH**.
2. Extract this ZIP.
3. Open the extracted `Network_Traffic_Anomaly_Detection` folder.
4. Click the folder address bar, type `cmd`, and press Enter.
5. Run:

   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   py -m pip install -r requirements.txt
   py generate_sample.py
   streamlit run app.py
   ```

6. The dashboard opens in your browser, usually at `http://localhost:8501`.

If `py` is not recognized, try `python` instead.

## CSV format
Required columns:
`timestamp, source_ip, destination_ip, protocol, destination_port, packet_count, bytes`

Example:
`2026-11-17T10:00:00,192.168.1.10,8.8.8.8,UDP,53,12,1200`

## Detection rules
- High packet count: greater than the chosen threshold.
- High data volume: bytes greater than the chosen threshold.
- Flagged destination port: destination port is in the sidebar list (default: 23, 4444, 5555, 6667).

These rules can produce false positives and false negatives. Thresholds should be tuned for the network being studied.

## Project explanation
"NetWatch is a CSV-based network traffic analysis dashboard. It examines fields such as protocol, destination port, packet count and bytes. It applies simple configurable rules to flag unusual records, visualizes the results, and exports a report for further investigation. It is an educational prototype, not a production intrusion detection system."

## Files
- `app.py`: dashboard and detection rules.
- `generate_sample.py`: creates safe synthetic sample data.
- `data/sample_traffic.csv`: sample records.
- `requirements.txt`: Python packages.
