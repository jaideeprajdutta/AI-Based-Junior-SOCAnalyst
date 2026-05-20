from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime

class AlertEvidence(BaseModel):
    packet_count: int
    time_window_seconds: int
    data_source: str

class AlertModel(BaseModel):
    alert_id: str
    timestamp: str
    alert_type: str
    indicator_type: str = "ip"
    indicator_value: str
    source_host: str = "Unknown"
    source_ip: str
    destination_host: str
    destination_ip: str
    protocol: str = "ICMP"
    severity: str
    evidence: AlertEvidence
    analyst_question: str = "Is this expected activity or suspicious scanning/noise?"
