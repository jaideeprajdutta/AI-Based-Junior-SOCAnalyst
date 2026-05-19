import subprocess
import csv
import json
import os
import uuid
import requests

from datetime import datetime
from collections import Counter

# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = "eth0"
CAPTURE_DURATION = 100
THRESHOLD = 40

PCAP_DIR = "pcaps"
CSV_DIR = "csv"
ALERT_DIR = "alerts"

PCAP_FILE = os.path.join(PCAP_DIR, "traffic.pcap")
CSV_FILE = os.path.join(CSV_DIR, "traffic.csv")

AIRIA_API_URL = "INSERT_AIRIA_API_URL"
AIRIA_API_KEY = "INSERT_AIRIA_API_KEY"

DESTINATION_HOST = "Internal-server"
DESTINATION_IP = "192.168.0.206"

# ============================================================
# DIRECTORY SETUP
# ============================================================

os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)
os.makedirs(ALERT_DIR, exist_ok=True)

# ============================================================
# HELPER
# ============================================================

def run_command(cmd, description):
    print(f"\n[+] {description}")
    subprocess.run(cmd, check=True)

# ============================================================
# STEP 1 - CAPTURE TRAFFIC
# ============================================================

def capture_traffic():

    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    capture_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", f"icmp and dst host {DESTINATION_IP}",
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", PCAP_FILE
    ]

    run_command(
        capture_cmd,
        f"Capturing ICMP traffic on {INTERFACE} for {CAPTURE_DURATION}s"
    )

    if not os.path.exists(PCAP_FILE):
        raise RuntimeError("PCAP capture failed")

    print(f"[+] Capture saved: {PCAP_FILE}")

# ============================================================
# STEP 2 - CONVERT PCAP TO CSV
# ============================================================

def convert_to_csv():

    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    convert_cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d"
    ]

    with open(CSV_FILE, "w", newline="") as outfile:
        subprocess.run(convert_cmd, stdout=outfile, check=True)

    print(f"[+] CSV created: {CSV_FILE}")

# ============================================================
# STEP 3 - ANALYZE TRAFFIC
# ============================================================

def analyze_traffic():

    ip_counter = Counter()

    with open(CSV_FILE, newline="") as csvfile:

        reader = csv.DictReader(csvfile)

        for row in reader:

            src_ip = (row.get("ip.src") or "").strip().strip('"')

            if src_ip:
                ip_counter[src_ip] += 1

    print("\n========== TRAFFIC SUMMARY ==========\n")

    suspicious_hosts = []

    for ip, count in ip_counter.items():

        print(f"{ip}: {count} packets")

        if count > THRESHOLD:
            suspicious_hosts.append((ip, count))

    if not suspicious_hosts:
        print("\n[+] No suspicious activity detected")

    return suspicious_hosts

# ============================================================
# ALERT CLASSIFICATION
# ============================================================

def classify_alert(packet_count):

    if packet_count >= 100:
        return "Potential ICMP Flood"

    elif packet_count >= 50:
        return "Suspicious Network Volume"

    else:
        return "Informational"

# ============================================================
# SEVERITY CALCULATION
# ============================================================

def calculate_severity(packet_count):

    if packet_count >= 100:
        return "High"

    elif packet_count >= 50:
        return "Medium"

    else:
        return "Low"

# ============================================================
# STEP 4 - GENERATE ALERT
# ============================================================

def generate_alert(src_ip, packet_count):

    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"

    alert_type = classify_alert(packet_count)

    severity = calculate_severity(packet_count)

    alert = {
        "alert_id": alert_id,

        "timestamp": datetime.utcnow().isoformat() + "Z",

        "alert_type": alert_type,

        "indicator_type": "ip",
        "indicator_value": src_ip,

        "source_host": "Unknown",
        "source_ip": src_ip,

        "destination_host": DESTINATION_HOST,
        "destination_ip": DESTINATION_IP,

        "protocol": "ICMP",

        "severity": severity,

        "evidence": {
            "packet_count": packet_count,
            "time_window_seconds": CAPTURE_DURATION,
            "data_source": os.path.basename(PCAP_FILE)
        },

        "analyst_question":
            "Is this expected activity or suspicious scanning/noise?"
    }

    alert_path = os.path.join(ALERT_DIR, f"{alert_id}.json")

    with open(alert_path, "w") as f:
        json.dump(alert, f, indent=4)

    print(f"\n[+] Alert created: {alert_path}")

    return alert

# ============================================================
# STEP 5 - SEND TO AIRIA
# ============================================================

def send_to_airia(alert):

    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": AIRIA_API_KEY
    }

    payload = {
        "userInput": json.dumps(alert),
        "asyncOutput": False
    }

    print("[+] Sending alert to Airia...")

    response = requests.post(
        AIRIA_API_URL,
        headers=headers,
        json=payload,
        timeout=120
    )

    response.raise_for_status()

    print(f"[+] Airia response status: {response.status_code}")

    try:

        data = response.json()

        print("\n========== AIRIA RESPONSE ==========\n")
        print(json.dumps(data, indent=2))

    except Exception:

        print("\n========== AIRIA RESPONSE ==========\n")
        print(response.text)

# ============================================================
# MAIN WORKFLOW
# ============================================================

def main():

    try:

        capture_traffic()

        convert_to_csv()

        suspicious_hosts = analyze_traffic()

        if not suspicious_hosts:

            print("\n[+] No alerts generated")
            return

        print(
            f"\n[+] {len(suspicious_hosts)} suspicious host(s) detected"
        )

        for ip, count in suspicious_hosts:

            alert = generate_alert(ip, count)

            send_to_airia(alert)

        print("\n[+] Workflow completed successfully")

    except subprocess.CalledProcessError as e:

        print(f"\n[!] TShark error: {e}")

    except requests.RequestException as e:

        print(f"\n[!] API communication error: {e}")

    except Exception as e:

        print(f"\n[!] Unexpected error: {e}")

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()