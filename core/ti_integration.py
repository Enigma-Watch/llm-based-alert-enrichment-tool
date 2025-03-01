# ti_integration.py
import requests
from .utils import logger, get_env_variable     # Changed
import json

class ThreatIntel:
    def __init__(self):
        self.threatstream_api_key = get_env_variable("THREATSTREAM_API_KEY")
        self.threatstream_url = get_env_variable("THREATSTREAM_URL")

    def query_threatstream(self, indicator_type, indicator_value):
        """Queries Anomali ThreatStream for reputation data."""
        url = f"{self.threatstream_url}/api/v2/{indicator_type}/{indicator_value}/"
        headers = {"Authorization": f"API_KEY {self.threatstream_api_key}"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            logger.info(f"ThreatStream response for {indicator_type} {indicator_value}: {data}")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying ThreatStream for {indicator_type} {indicator_value}: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from ThreatStream response: {e}")
            return None

    def get_reputation(self, entity_type, entity_value):
        """Gets the reputation for a given entity from ThreatStream."""
        if entity_type in ["ip_addresses", "domains", "filenames"]:
            # Map entity types to ThreatStream indicator types
            threatstream_type = {
                "ip_addresses": "ip",
                "domains": "domain",
                "filenames": "file"  # Adjust if ThreatStream uses a different type for files
            }.get(entity_type)

            if threatstream_type:
                reputation_data = self.query_threatstream(threatstream_type, entity_value)
                return reputation_data
            else:
                logger.warning(f"Unsupported entity type for ThreatStream: {entity_type}")
                return None
        else:
            logger.warning(f"Unsupported entity type: {entity_type}")
            return None


# Example Usage (for testing)
if __name__ == "__main__":
    logger.info("Starting Threat Intelligence Integration Test...")
    threat_intel = ThreatIntel()
    ip_address = "8.8.8.8"  # Replace with a test IP
    domain = "example.com"  # Replace with a test domain

    ip_reputation = threat_intel.get_reputation("ip_addresses", ip_address)
    if ip_reputation:
        print(f"Reputation for IP {ip_address}: {ip_reputation}")
    else:
        print(f"Could not retrieve reputation for IP {ip_address}")

    domain_reputation = threat_intel.get_reputation("domains", domain)
    if domain_reputation:
        print(f"Reputation for domain {domain}: {domain_reputation}")
    else:
        print(f"Could not retrieve reputation for domain {domain}")
    logger.info("Threat Intelligence Integration Test Completed.")
