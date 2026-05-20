def classify_alert(packet_count: int) -> str:
    """Classify the alert type based on packet count."""
    if packet_count >= 100:
        return "Potential ICMP Flood"
    elif packet_count >= 50:
        return "Suspicious Network Volume"
    else:
        return "Informational"

def calculate_severity(packet_count: int) -> str:
    """Calculate severity level based on packet count."""
    if packet_count >= 100:
        return "High"
    elif packet_count >= 50:
        return "Medium"
    else:
        return "Low"
