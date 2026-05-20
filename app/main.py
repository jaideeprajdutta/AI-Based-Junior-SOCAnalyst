import subprocess
import json
import os
import uuid
import requests
import time
import socket
import csv
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = os.getenv("SOC_INTERFACE", "eth0")
CAPTURE_DURATION = int(os.getenv("SOC_CAPTURE_DURATION", "100"))
THRESHOLD = int(os.getenv("SOC_THRESHOLD", "40"))

PCAP_DIR = "pcaps"
CSV_DIR = "csv"
ALERT_DIR = "alerts"

PCAP_FILE = os.path.join(PCAP_DIR, "traffic.pcap")
CSV_FILE = os.path.join(CSV_DIR, "traffic.csv")

AIRIA_API_URL = os.getenv("AIRIA_API_URL")
AIRIA_API_KEY = os.getenv("AIRIA_API_KEY")

if not AIRIA_API_URL or not AIRIA_API_KEY:
    raise Exception("Missing AIRIA API credentials in environment variables")

DESTINATION_HOST = os.getenv("SOC_DESTINATION_HOST", "Internal-server")
DESTINATION_IP = os.getenv("SOC_DESTINATION_IP", "192.168.0.206")

# ============================================================
# DIRECTORY SETUP
# ============================================================

os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)
os.makedirs(ALERT_DIR, exist_ok=True)

# ============================================================
# INLINE CORE LOGIC FUNCTIONS (Self-Contained)
# ============================================================

def is_connected():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def run_command(cmd, description):
    print(f"\n[+] {description}")
    subprocess.run(cmd, check=True)

def analyze_traffic(csv_path, threshold):
    ip_counter = Counter()
    if not os.path.exists(csv_path):
        return []

    with open(csv_path, newline="") as csvfile:
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

def classify_alert(packet_count):
    if packet_count >= 100:
        return "Potential ICMP Flood"
    elif packet_count >= 50:
        return "Suspicious Network Volume"
    else:
        return "Informational"

def calculate_severity(packet_count):
    if packet_count >= 100:
        return "High"
    elif packet_count >= 50:
        return "Medium"
    else:
        return "Low"

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
# STEP 4 - GENERATE ALERT (Optimized for AI Prompt Verification)
# ============================================================

def generate_alert(src_ip, packet_count):
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"
    alert_type = classify_alert(packet_count)
    severity = calculate_severity(packet_count)

    # Validated dictionary schema that mirrors your exact AI constraints
    alert = {
        "alert_id": alert_id,
        "timestamp": int(time.time()), 
        "alert_type": alert_type,
        "indicator_type": "IP Address", 
        "indicator_value": src_ip,
        "source_host": f"Host-{src_ip.replace('.', '_')}", 
        "source_ip": src_ip,
        "destination_host": DESTINATION_HOST,
        "destination_ip": DESTINATION_IP,
        "protocol": "ICMP",
        "severity": severity,
        "evidence": {
            "packet_count": int(packet_count),
            "time_window_seconds": int(CAPTURE_DURATION)
        }
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
    try:
        response = requests.post(
            AIRIA_API_URL,
            headers=headers,
            json=payload,
            timeout=120
        )
        response.raise_for_status()
        print(f"[+] Airia response status: {response.status_code}")
        data = response.json()
        print("\n========== AIRIA RESPONSE ==========\n")
        print(json.dumps(data, indent=2))
    except requests.exceptions.ConnectionError as e:
        print(f"\n[!] Connection Error: Could not reach Airia API.")
        print(f"    Details: {e}")
        print("    HINT: Check internet access or resolution of 'api.airia.ai'.")
    except Exception as e:
        print(f"\n[!] Error processing Airia response: {e}")

# ============================================================
# MAIN WORKFLOW
# ============================================================

def process_cycle():
    capture_traffic()
    convert_to_csv()
    suspicious_hosts = analyze_traffic(CSV_FILE, THRESHOLD)

    if not suspicious_hosts:
        print("\n[+] No alerts generated in this cycle")
        return

    print(f"\n[+] {len(suspicious_hosts)} suspicious host(s) detected")
    for ip, count in suspicious_hosts:
        alert = generate_alert(ip, count)
        send_to_airia(alert)

def main():
    if not is_connected():
        print("\n[!] WARNING: No internet connectivity detected.")
        print("    The system will capture traffic but will fail to call the Airia API.")

    print("\n[***] SOC ANALYST SERVER STARTED [***]")
    print(f"[*] Monitoring {INTERFACE} for ICMP pings to {DESTINATION_IP}")
    print(f"[*] Threshold: {THRESHOLD} packets | Cycle: {CAPTURE_DURATION}s")

    while True:
        try:
            print(f"\n--- Starting new capture cycle at {datetime.now().strftime('%H:%M:%S')} ---")
            process_cycle()
            print("\n[+] Cycle completed. Sleeping for 5s...")
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n[!] SOC Server stopped by user.")
            break
        except Exception as e:
            print(f"\n[!] Cycle Error: {e}")
            print("[*] Retrying in 10s...")
            time.sleep(10)

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()