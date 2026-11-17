import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
out = Path("data/sample_traffic.csv")
out.parent.mkdir(exist_ok=True)

protocols = ["TCP", "UDP", "ICMP"]
normal_ports = [53, 80, 443, 123, 25, 110, 143, 22]
flagged_ports = [23, 4444, 5555, 6667]
sources = [f"192.168.1.{i}" for i in range(10, 31)]
destinations = ["8.8.8.8", "1.1.1.1", "142.250.72.14", "93.184.216.34"]

start = datetime.now().replace(second=0, microsecond=0) - timedelta(hours=2)
rows = []
for i in range(160):
    suspicious = (i % 17 == 0)
    port = random.choice(flagged_ports) if suspicious else random.choice(normal_ports)
    packets = random.randint(350, 900) if suspicious else random.randint(1, 120)
    byte_count = random.randint(180000, 420000) if suspicious else random.randint(300, 20000)
    rows.append({
        "timestamp": (start + timedelta(minutes=i)).isoformat(timespec="seconds"),
        "source_ip": random.choice(sources),
        "destination_ip": random.choice(destinations),
        "protocol": random.choice(protocols),
        "destination_port": port,
        "packet_count": packets,
        "bytes": byte_count,
    })

with out.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
print(f"Created {out} with {len(rows)} sample records.")
