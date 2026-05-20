import csv
from collections import Counter
from typing import List, Tuple

def analyze_traffic(csv_file: str, threshold: int) -> List[Tuple[str, int]]:
    ip_counter = Counter()

    with open(csv_file, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            src_ip = (row.get("ip.src") or "").strip().strip('"')
            if src_ip:
                ip_counter[src_ip] += 1

    print("\n========== TRAFFIC SUMMARY ==========\n")
    suspicious_hosts = []

    for ip, count in ip_counter.items():
        print(f"{ip}: {count} packets")
        if count > threshold:
            suspicious_hosts.append((ip, count))

    if not suspicious_hosts:
        print("\n[+] No suspicious activity detected")

    return suspicious_hosts
