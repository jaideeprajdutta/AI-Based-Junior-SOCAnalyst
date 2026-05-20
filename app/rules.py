def classify_alert(packet_count: int) -> str:
    if packet_count >= 100:
        return "Potential ICMP Flood"
    elif packet_count >= 50:
        return "Suspicious Network Volume"
    else:
        return "Informational"

def calculate_severity(packet_count: int) -> str:
    if packet_count >= 100:
        return "High"
    elif packet_count >= 50:
        return "Medium"
    else:
        return "Low"
