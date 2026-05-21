# AI-Based Local Network Monitoring & SOC Analyst

A robust, local network monitoring solution that captures suspicious traffic and leverages AI for intelligent threat triage and incident response.

## Overview
This tool monitors local network traffic for potential threats (specifically focusing on ICMP flood patterns) using `tshark`. When suspicious activity is detected based on configurable thresholds, it generates detailed JSON alerts and offloads them to an AI-powered analysis engine (Airia) for automated triage, risk scoring, and mitigation strategy generation.

### Key Features
- **Real-time Traffic Capture:** Uses `tshark` for high-performance packet analysis.
- **Automated Triage:** Converts raw network data into actionable security alerts.
- **AI-Powered Analysis:** Integrates with Airia AI to provide executive summaries and MITRE ATT&CK mappings.
- **Configurable Thresholds:** Easily adjust monitoring sensitivity via environment variables.

## Prerequisites
- **Python 3.8+**
- **Wireshark/tshark:** Ensure `tshark` is installed and available in your system PATH.
  - *Linux:* `sudo apt install tshark`
  - *macOS:* `brew install wireshark`
  - *Windows:* Install Wireshark and include tshark in PATH.
- **Airia AI Account:** An active API key and Pipeline ID from [Airia.ai](https://airia.ai).

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/AI-Based-Junior-SOC.git
   cd AI-Based-Junior-SOC
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables:**
   Copy the example configuration file and fill in your details:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and provide your specific network interface, destination IP, and Airia API credentials.

## Usage

1. **Start the SOC Monitor:**
   ```bash
   python app/main.py
   ```

2. **Monitoring Process:**
   - The script will continuously capture traffic on the specified interface.
   - If traffic exceeds the defined `SOC_THRESHOLD`, an alert is generated in the `alerts/` directory.
   - The alert is then sent to the AI engine for detailed analysis.
   - Analysis reports are printed to the console and stored locally.

## License
MIT License
