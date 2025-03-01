# core/ti_connectors.py
from abc import ABC, abstractmethod
import os
import requests
from core.utils import logger

class ThreatIntelConnector(ABC):
    @abstractmethod
    def get_reputation(self, entity):
        """
        Abstract method to retrieve the reputation of an entity from a threat intelligence source.
        """
        pass

class ThreatStreamConnector(ThreatIntelConnector):
    def __init__(self):
        """
        Initializes the ThreatStream connector with credentials from environment variables.
        """
        self.api_key = os.getenv("THREATSTREAM_API_KEY")
        self.url = os.getenv("THREATSTREAM_URL")

        if not all([self.api_key, self.url]):
            logger.error("Missing ThreatStream credentials in environment variables.")
            raise ValueError("Missing ThreatStream credentials in environment variables.")

    def get_reputation(self, entity):
        """
        Retrieves the reputation of an entity from ThreatStream.

        Args:
            entity (str): The entity to lookup (e.g., IP address, domain).

        Returns:
            dict: A dictionary containing the reputation data, or None if not found.
        """
        # Placeholder: Implement ThreatStream API call to get entity reputation
        logger.info(f"Retrieving ThreatStream reputation for entity: {entity}")
        return {"threatstream_score": 75}  # Example reputation score

class MISPConnector(ThreatIntelConnector):
    def __init__(self):
        """
        Initializes the MISP connector with credentials from environment variables.
        """
        self.misp_url = os.getenv("MISP_URL")
        self.misp_key = os.getenv("MISP_KEY")
        if not all([self.misp_url, self.misp_key]):
            logger.error("Missing MISP credentials in environment variables.")
            raise ValueError("Missing MISP credentials in environment variables.")

    def get_reputation(self, entity):
         """
         Retrieves the reputation of an entity from MISP.
         Args:
             entity (str): The entity to lookup (e.g., IP address, domain).
         Returns:
             dict: A dictionary containing the reputation data from MISP.
         """
         logger.info(f"Retrieving MISP reputation for entity: {entity}")
         return {"misp_score": 60}  # Example reputation score

class AlienVaultOTXConnector(ThreatIntelConnector):
    def __init__(self):
        """
        Initializes the AlienVault OTX connector with credentials from environment variables.
        """
        self.otx_key = os.getenv("OTX_KEY")
        if not self.otx_key:
            logger.error("Missing AlienVault OTX API key in environment variables.")
            raise ValueError("Missing AlienVault OTX API key in environment variables.")

    def get_reputation(self, entity):
        """
        Retrieves the reputation of an entity from AlienVault OTX.
        Args:
            entity (str): The entity to lookup (e.g., IP address, domain).
        Returns:
            dict: A dictionary containing the reputation data from AlienVault OTX.
        """
        logger.info(f"Retrieving AlienVault OTX reputation for entity: {entity}")
        return {"otx_score": 50}  # Example reputation score

class VirusTotalConnector(ThreatIntelConnector):
    def __init__(self):
         """
         Initializes the VirusTotal connector with credentials from environment variables.
         """
         self.vt_key = os.getenv("VT_KEY")
         if not self.vt_key:
             logger.error("Missing VirusTotal API key in environment variables.")
             raise ValueError("Missing VirusTotal API key in environment variables.")

    def get_reputation(self, entity):
         """
         Retrieves the reputation of an entity from VirusTotal.
         Args:
             entity (str): The entity to lookup (e.g., IP address, domain).
         Returns:
             dict: A dictionary containing the reputation data from VirusTotal.
         """
         logger.info(f"Retrieving VirusTotal reputation for entity: {entity}")
         return {"virustotal_score": 80}  # Example reputation score
