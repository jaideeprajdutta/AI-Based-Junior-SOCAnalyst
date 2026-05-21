import json
import os
import uuid
import time

def simulate_alert():
    """Simulates an alert payload for integration testing."""
    mock_src_ip = "192.168.1.100"
    mock_packet_count = 150
    
    alert = {
        "alert_id": f"TEST-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": int(time.time()), 
        "alert_type": "Simulated DoS",
        "indicator_type": "IP Address", 
        "indicator_value": mock_src_ip,
        "source_ip": mock_src_ip,
        "destination_ip": "192.168.1.254",
        "protocol": "ICMP",
        "severity": "High",
        "evidence": {
            "packet_count": mock_packet_count,
            "time_window_seconds": 60
        }
    }
    
    print(f"[TEST] Generated Mock Alert: {json.dumps(alert, indent=2)}")
    return alert

if __name__ == "__main__":
    simulate_alert()
    print("[TEST] Pipeline simulation successful.")
