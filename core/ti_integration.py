# core/ti_integration.py
import os
from core.ti_connectors import ThreatStreamConnector, MISPConnector, AlienVaultOTXConnector, VirusTotalConnector
from core.utils import logger
import json

class ThreatIntel:
    def get_reputation(self, ti_source, entity):
        """
        Retrieves the reputation of an entity from the specified threat intelligence source.

        Args:
            ti_source (str): The name of the threat intelligence source to use (e.g., ThreatStream, MISP).
            entity (str): The entity to lookup (e.g., IP address, domain).

        Returns:
            dict: A dictionary containing the reputation data, or None if not found.
        """
        try:
            if ti_source == "ThreatStream":
                connector = ThreatStreamConnector()
            elif ti_source == "MISP":
                connector = MISPConnector()
            elif ti_source == "AlienVault OTX":
                connector = AlienVaultOTXConnector()
            elif ti_source == "VirusTotal":
                connector = VirusTotalConnector()
            else:
                logger.warning(f"Unsupported threat intelligence source: {ti_source}")
                return None

            reputation = connector.get_reputation(entity)
            return reputation

        except Exception as e:
            logger.error(f"Error retrieving threat intelligence data from {ti_source}: {e}")
            return None