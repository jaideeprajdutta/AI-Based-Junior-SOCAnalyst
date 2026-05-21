import json
import logging
import requests

logger = logging.getLogger(__name__)

def send_to_airia(alert, api_url, api_key):
    """
    Offloads the alert payload to the AIRIA AI Core for threat analysis.
    """
    if "YOUR_AIRIA_API_KEY" in api_key or not api_key:
        logger.warning("Skipping AIRIA API call: API Key not configured.")
        return None

    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": api_key
    }

    payload = {
        "userInput": json.dumps(alert),
        "asyncOutput": False
    }

    logger.info(f"Sending alert {alert.get('alert_id')} to AI Core...")
    try:
        response = requests.post(
            api_url,
            headers=headers,
            json=payload,
            timeout=120
        )
        response.raise_for_status()
        
        analysis = response.json()
        logger.info("AI analysis received successfully.")
        return analysis

    except Exception as e:
        logger.error(f"Error during AI analysis: {e}")
        return None
