
import csv
import io
import re
import shutil
import subprocess
import tempfile

from pathlib import Path

import pandas as pd


def find_tshark():
    """Locate the Wireshark TShark executable."""

    found = shutil.which("tshark")

    if found:
        return found

    possible_paths = [
        Path(r"C:\Program Files\Wireshark\tshark.exe"),
        Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
    ]

    for path in possible_paths:
        if path.exists():
            return str(path)

    raise FileNotFoundError(
        "TShark not found. Please check your Wireshark installation."
    )


def get_interfaces():
    """List available network interfaces using TShark."""

    tshark = find_tshark()

    result = subprocess.run(
        [tshark, "-D"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Could not list network interfaces."
        )

    interfaces = []

    for line in result.stdout.splitlines():
        match = re.match(r"^\s*\d+\.\s+(.+)$", line)

        if match:
            interface = match.group(1).strip()
            interfaces.append(interface)

    if not interfaces:
        raise RuntimeError(
            "No network interfaces found. Check your Wireshark/Npcap installation."
        )

    return interfaces


def analyze_pcap(pcap_path):
    """Extract and aggregate network packets from a PCAP or PCAPNG file."""

    tshark = find_tshark()

    fields = [
        "frame.time_epoch",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "frame.protocols",
        "tcp.dstport",
        "udp.dstport",
        "frame.len",
    ]

    command = [
        tshark,
        "-r", str(pcap_path),
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=,",
        "-E", "quote=d",
    ]

    for field in fields:
        command.extend(["-e", field])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "TShark extraction failed."
        )

    if not result.stdout.strip():
        raise ValueError("No packets were found in the capture.")

    packets = pd.read_csv(
        io.StringIO(result.stdout),
        header=None,
        names=fields,
        dtype=str,
        keep_default_na=False,
        quoting=csv.QUOTE_ALL
    )

    if packets.empty:
        raise ValueError("No packet records were extracted.")

    # Extract source IP addresses.
    packets["source_ip"] = packets["ip.src"].replace("", pd.NA)
    packets["source_ip"] = packets["source_ip"].fillna(
        packets["ipv6.src"].replace("", pd.NA)
    )

    # Extract destination IP addresses.
    packets["destination_ip"] = packets["ip.dst"].replace("", pd.NA)
    packets["destination_ip"] = packets["destination_ip"].fillna(
        packets["ipv6.dst"].replace("", pd.NA)
    )

    # Extract TCP or UDP destination ports.
    packets["destination_port"] = packets["tcp.dstport"].replace("", pd.NA)
    packets["destination_port"] = packets["destination_port"].fillna(
        packets["udp.dstport"].replace("", pd.NA)
    )

    packets["destination_port"] = pd.to_numeric(
        packets["destination_port"],
        errors="coerce"
    ).fillna(0).astype(int)

    # Extract packet sizes.
    packets["bytes"] = pd.to_numeric(
        packets["frame.len"],
        errors="coerce"
    ).fillna(0)

    # Convert packet timestamps.
    packets["timestamp"] = pd.to_datetime(
        pd.to_numeric(packets["frame.time_epoch"], errors="coerce"),
        unit="s",
        utc=True,
        errors="coerce"
    )

    # Get the final protocol in the protocol stack.
    packets["protocol"] = (
        packets["frame.protocols"]
        .replace("", "unknown")
        .str.split(":")
        .str[-1]
        .str.upper()
    )

    # Keep valid IP traffic records.
    packets = packets.dropna(
        subset=["timestamp", "source_ip", "destination_ip"]
    )

    if packets.empty:
        raise ValueError(
            "No valid IPv4 or IPv6 traffic was found in the capture."
        )

    # Group packets into one-minute traffic windows.
    packets["time_window"] = packets["timestamp"].dt.floor("min")

    traffic = (
        packets.groupby(
            [
                "time_window",
                "source_ip",
                "destination_ip",
                "protocol",
                "destination_port",
            ],
            dropna=False
        )
        .agg(
            packet_count=("bytes", "size"),
            bytes=("bytes", "sum")
        )
        .reset_index()
        .rename(columns={"time_window": "timestamp"})
    )

    return traffic[
        [
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "destination_port",
            "packet_count",
            "bytes",
        ]
    ]


def capture_live_traffic(interface, duration_seconds=15):
    """
    Capture traffic on a selected interface for a limited duration,
    then analyse the resulting PCAPNG file.
    """

    tshark = find_tshark()

    if not 10 <= int(duration_seconds) <= 60:
        raise ValueError("Capture duration must be between 10 and 60 seconds.")

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".pcapng",
            delete=False
        ) as temp_file:
            temp_path = temp_file.name

        command = [
            tshark,
            "-i", interface,
            "-a", f"duration:{int(duration_seconds)}",
            "-w", temp_path
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=int(duration_seconds) + 45
        )

        if result.returncode != 0:
            message = result.stderr.strip()

            if "permission" in message.lower() or "access" in message.lower():
                raise RuntimeError(
                    "Capture permission denied. Close the app and run "
                    "your terminal as Administrator, then try again."
                )

            raise RuntimeError(
                message or "Live packet capture failed."
            )

        if not Path(temp_path).exists() or Path(temp_path).stat().st_size == 0:
            raise ValueError("The capture file is empty.")

        return analyze_pcap(temp_path)

    finally:
        if temp_path and Path(temp_path).exists():
            Path(temp_path).unlink(missing_ok=True)
