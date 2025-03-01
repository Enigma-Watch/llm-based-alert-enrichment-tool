# core/main.py
import os
from core.alert_connectors import SentinelConnector, SplunkConnector, ElasticSearchConnector, QRadarConnector
from core.llm_enrichment import LLMEnrichment
from core.ti_integration import ThreatIntel
from core.mitre_mapping import MitreMapper
from core.risk_scoring import RiskScorer
from core.utils import logger

def enrich_alert(alert_id, alert_source, ti_source, llm_source):
    """
    Enriches a specific alert from various platforms with threat intelligence and MITRE ATT&CK data.

    Args:
        alert_id (str): The ID of the alert to enrich.
        alert_source (str): The source platform of the alert (e.g., Sentinel, Splunk).
        ti_source (str): The threat intelligence source to use (e.g., ThreatStream, MISP).
        llm_source (str): The LLM source to use (e.g., OpenAI, Rule-Based).

    Returns:
        dict: A dictionary containing the enriched alert data, or None if an error occurred.
    """
    logger.info(f"Starting enrichment process for alert ID: {alert_id} from source: {alert_source}")
    try:
        # 1. Instantiate the appropriate connector based on alert_source
        if alert_source == "Sentinel":
            connector = SentinelConnector()
            alert = connector.get_alert(alert_id)  # Assuming a get_alert method
            alert_description = alert.get("properties", {}).get("description", "")
        elif alert_source == "Splunk":
            connector = SplunkConnector()
            alert = connector.get_alert(alert_id)
            alert_description = alert.get("description", "")  # Assuming 'description' field
        elif alert_source == "Elasticsearch":
            connector = ElasticSearchConnector()
            alert = connector.get_alert(alert_id)
            alert_description = alert.get("_source", {}).get("description", "")  # Adjust based on ES data
        elif alert_source == "QRadar":
            connector = QRadarConnector()
            alert = connector.get_alert(alert_id)
            alert_description = alert.get("description", "")
        elif alert_source == "CSV File":
            #Since CSV file requires ALERT_DESCRIPTION.
            alert_description = os.getenv("ALERT_DESCRIPTION","") #Pull from environment variables.
            if not alert_description:
                logger.warning(f"No description extracted from alert {alert_id}.")
                return None
            alert = {"description": alert_description} # For display purposes

        else:
            logger.error(f"Unsupported alert source: {alert_source}")
            return None

        if not alert:
            logger.warning(f"Alert with ID {alert_id} not found in {alert_source}.")
            return None

        #alert_properties = alert.get("properties", {})
        #alert_description = alert_properties.get("description", "") # Old call - depreciated.
        alert_description = alert.get("description", "") # Generic description.
        if not alert_description:
            logger.warning(f"No description for alert {alert_id} in {alert_source}.")
            return None

        # 2. LLM-Based Entity Extraction
        llm = LLMEnrichment()
        entities = llm.extract_entities(alert_description)
        if not entities:
            logger.warning(f"No entities extracted from alert {alert_id}.")
            return None

        # 3. Threat Intelligence Enrichment
        threat_intel = ThreatIntel()
        threat_intel_reputations = {}
        for entity_type, entity_list in entities.items():
            if entity_type in ["ip_addresses", "domains"]:  # Only query IPs and Domains for TI
                for entity in entity_list:
                    threat_intel_reputations[entity] = threat_intel.get_reputation(ti_source, entity)

        # 4. MITRE ATT&CK Mapping
        mitre_mapper = MitreMapper()
        mitre_techniques = mitre_mapper.map_to_mitre(entities)

        # 5. Risk Scoring
        risk_scorer = RiskScorer()
        alert_severity = "Medium"  # Replace with actual alert severity from the source
        risk_score = risk_scorer.calculate_risk_score(
            alert_severity, threat_intel_reputations, mitre_techniques
        )

        # Create a dictionary with the enriched data
        enriched_data = {
            "alert_id": alert_id,
            "extracted_entities": entities,
            "threat_intel_reputations": threat_intel_reputations,
            "mitre_techniques": mitre_techniques,
            "risk_score": risk_score,
        }

        logger.info(f"Successfully enriched alert {alert_id} from {alert_source}.")
        return enriched_data

    except Exception as e:
        logger.error(f"Error enriching alert {alert_id} from {alert_source}: {e}")
        return None

def main():
    """
    Main function (currently a placeholder, adapt as needed)
    """
    logger.info("Starting Alert Enrichment...")
    # Add any initialization or setup logic here
    logger.info("Alert Enrichment completed.")

if __name__ == "__main__":
    main()
