# main.py
from .sentinel_connector import SentinelConnector 
from .llm_enrichment import LLMEnrichment        
from .ti_integration import ThreatIntel           
from .mitre_mapping import MitreMapper            
from .utils import logger                         


def enrich_alert(alert_id):
    """
    Enriches a specific Sentinel alert with threat intelligence and MITRE ATT&CK data.

    Args:
        alert_id (str): The ID of the Sentinel alert to enrich.

    Returns:
        dict: A dictionary containing the enriched alert data, or None if an error occurred.
    """
    logger.info(f"Starting enrichment process for alert ID: {alert_id}")
    try:
        # Initialize components (make sure to pass in configurations)
        sentinel = SentinelConnector()
        llm = LLMEnrichment()
        threat_intel = ThreatIntel()
        mitre_mapper = MitreMapper()
        risk_scorer = RiskScorer()

        # Get the specific alert from Sentinel
        alerts = sentinel.get_alerts() #Get all alerts
        alert = next((alert for alert in alerts if alert.get("name") == alert_id), None) #Find our alert.

        if not alert:
            logger.warning(f"Alert with ID {alert_id} not found in Sentinel.")
            return None

        alert_properties = alert.get("properties", {})
        alert_description = alert_properties.get("description", "")
        alert_severity = alert_properties.get("severity", "Low")

        # 1. LLM-Based Entity Extraction
        entities = llm.extract_entities(alert_description)
        if not entities:
            logger.warning(f"No entities extracted from alert {alert_id}.")
            return None

        # 2. Threat Intelligence Enrichment
        threat_intel_reputations = {}
        for entity_type, entity_list in entities.items():
            if entity_type in ["ip_addresses", "domains"]:
                for entity in entity_list:
                    threat_intel_reputations[entity] = threat_intel.get_reputation(entity_type, entity)

        # 3. MITRE ATT&CK Mapping
        mitre_techniques = mitre_mapper.map_to_mitre(entities)

        # 4. Risk Scoring
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

        #You *could* update Sentinel here, but its better to leave that to the UI.

        logger.info(f"Successfully enriched alert {alert_id}.")
        return enriched_data

    except Exception as e:
        logger.error(f"Error enriching alert {alert_id}: {e}")
        return None


def main():
    """Main function to orchestrate the SIAP workflow (command line version - depreciated in favor of UI)."""
    logger.info("Starting Sentinel Intelligence Augmentation and Prioritization (SIAP)...")

    # Initialize components
    sentinel = SentinelConnector()
    llm = LLMEnrichment()
    threat_intel = ThreatIntel()
    mitre_mapper = MitreMapper()
    risk_scorer = RiskScorer()

    # Get alerts from Sentinel
    alerts = sentinel.get_alerts()

    if not alerts:
        logger.warning("No alerts found in Sentinel. Exiting.")
        return

    for alert in alerts:
        try:
            alert_id = alert.get("name")  # Assuming 'name' field contains the alert ID
            alert_properties = alert.get("properties", {})
            alert_description = alert_properties.get("description", "")
            alert_severity = alert_properties.get("severity", "Low")  # Default to Low if not found

            logger.info(f"Processing alert: {alert_id} - {alert_description[:50]}...")  # Log first 50 chars

            # 1. LLM-Based Entity Extraction
            entities = llm.extract_entities(alert_description)
            if not entities:
                logger.warning(f"No entities extracted from alert {alert_id}.")
                continue  # Skip to the next alert

            # 2. Threat Intelligence Enrichment
            threat_intel_reputations = {}
            for entity_type, entity_list in entities.items():
                if entity_type in ["ip_addresses", "domains"]:  # Only query IPs and Domains for TI
                    for entity in entity_list:
                        threat_intel_reputations[entity] = threat_intel.get_reputation(entity_type, entity)

            # 3. MITRE ATT&CK Mapping
            mitre_techniques = mitre_mapper.map_to_mitre(entities)

            # 4. Risk Scoring
            risk_score = risk_scorer.calculate_risk_score(
                alert_severity, threat_intel_reputations, mitre_techniques
            )

            logger.info(f"Risk score for alert {alert_id}: {risk_score}")

            # 5. Update Sentinel Alert with Enriched Data
            update_properties = {
                "properties": {
                    "confidenceLevel": int(risk_score),  # Or another appropriate field
                    "customDetails": {  # Add custom details to the alert (optional)
                        "llm_extracted_entities": str(entities), # Convert dict to string
                        "threat_intel_data": str(threat_intel_reputations),  # Convert dict to string
                        "mitre_techniques": str(mitre_techniques), # Convert list to string
                        "risk_score": str(risk_score), #Convert float to string
                    },
                    # Add MITRE ATT&CK techniques to the alert's "tactics" property (optional)
                    "tactics": mitre_techniques  # This expects a list of tactic names.
                }
            }
            if sentinel.update_alert(alert_id, update_properties):
                logger.info(f"Successfully updated alert {alert_id} in Sentinel.")
            else:
                logger.error(f"Failed to update alert {alert_id} in Sentinel.")

        except Exception as e:
            logger.error(f"Error processing alert {alert_id}: {e}")

    logger.info("Sentinel Intelligence Augmentation and Prioritization (SIAP) completed.")

if __name__ == "__main__":
    main()
