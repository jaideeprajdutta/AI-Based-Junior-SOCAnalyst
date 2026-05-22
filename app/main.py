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
import logging
from dotenv import load_dotenv

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("soc_monitor.log")
    ]
)
logger = logging.getLogger(__name__)

load_dotenv()

# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = os.getenv("SOC_INTERFACE", "eth0")
CAPTURE_DURATION = int(os.getenv("SOC_CAPTURE_DURATION", "60"))
THRESHOLD = int(os.getenv("SOC_THRESHOLD", "10"))

PCAP_DIR = "pcaps"
CSV_DIR = "csv"
ALERT_DIR = "alerts"

PCAP_FILE = os.path.join(PCAP_DIR, "traffic.pcap")
CSV_FILE = os.path.join(CSV_DIR, "traffic.csv")

# Placeholder for Public Release
AIRIA_API_URL = os.getenv("AIRIA_API_URL", "https://api.airia.ai/v2/PipelineExecution/YOUR_PIPELINE_ID")
AIRIA_API_KEY = os.getenv("AIRIA_API_KEY", "YOUR_AIRIA_API_KEY")

if not AIRIA_API_URL or "YOUR_PIPELINE_ID" in AIRIA_API_URL:
    print("[!] Warning: AIRIA_API_URL is not configured.")

if not AIRIA_API_KEY or AIRIA_API_KEY == "YOUR_AIRIA_API_KEY":
    print("[!] Warning: AIRIA_API_KEY is not configured.")

DESTINATION_HOST = os.getenv("SOC_DESTINATION_HOST", "Internal-Server")
DESTINATION_IP = os.getenv("SOC_DESTINATION_IP", "192.168.1.X")

# ============================================================
# DIRECTORY SETUP
# ============================================================

os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)
os.makedirs(ALERT_DIR, exist_ok=True)

# ============================================================
# CORE LOGIC FUNCTIONS
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

    # Using a buffer/generator pattern for efficient line-by-line processing
    try:
        with open(csv_path, newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                src_ip = (row.get("ip.src") or "").strip().strip('"')
                if src_ip:
                    ip_counter[src_ip] += 1
    except Exception as e:
        logger.error(f"Error processing CSV buffer: {e}")
        return []

    logger.info("========== TRAFFIC SUMMARY ==========")
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
        return "Potential Denial of Service (DoS)"
    elif packet_count >= 50:
        return "Suspicious Traffic Volume"
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
# WORKFLOW STEPS
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

def generate_alert(src_ip, packet_count):
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"
    alert_type = classify_alert(packet_count)
    severity = calculate_severity(packet_count)

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

from app.utils import send_to_airia

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
        send_to_airia(alert, AIRIA_API_URL, AIRIA_API_KEY)

def check_tshark():
    try:
        subprocess.run(["tshark", "-v"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("tshark is not installed or not in PATH. Please install Wireshark/tshark.")
        exit(1)

def validate_config():
    global THRESHOLD
    try:
        THRESHOLD = int(os.getenv("SOC_THRESHOLD", "10"))
        if THRESHOLD <= 0:
            raise ValueError
    except ValueError:
        logger.error("Invalid SOC_THRESHOLD. Must be a positive integer. Defaulting to 10.")
        THRESHOLD = 10

def main():
    validate_config()
    check_tshark()
    if not is_connected():
        print("\n[!] WARNING: No internet connectivity detected.")
        print("    The system will capture traffic but will fail to call the AI API.")

    print("\n" + "="*40)
    print("  LOCAL NETWORK MONITORING SOC STARTED  ")
    print("="*40)
    print(f"[*] Monitoring: {INTERFACE}")
    print(f"[*] Target: {DESTINATION_IP}")
    print(f"[*] Threshold: {THRESHOLD} packets / {CAPTURE_DURATION}s")

    while True:
        try:
            print(f"\n--- Starting capture cycle: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
            process_cycle()
            print("\n[+] Cycle completed. Waiting for next interval...")
            time.sleep(10)
        except KeyboardInterrupt:
            print("\n[!] Service stopped by user.")
            break
        except Exception as e:
            print(f"\n[!] Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
