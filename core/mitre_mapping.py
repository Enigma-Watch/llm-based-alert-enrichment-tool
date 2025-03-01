# mitre_mapping.py
from .utils import logger                        # Changed
import json

class MitreMapper:
    def __init__(self, mapping_file="mitre_attack_mapping.json"):
        """
        Initializes the MitreMapper with a mapping file.

        Args:
            mapping_file (str): Path to the JSON file containing the mapping
                                 between keywords/entities and MITRE ATT&CK techniques.
        """
        self.mapping = self._load_mapping(mapping_file)

    def _load_mapping(self, mapping_file):
        """Loads the mapping from a JSON file."""
        try:
            with open(mapping_file, "r") as f:
                mapping = json.load(f)
            logger.info(f"Successfully loaded MITRE ATT&CK mapping from {mapping_file}")
            return mapping
        except FileNotFoundError:
            logger.error(f"MITRE ATT&CK mapping file not found: {mapping_file}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from MITRE ATT&CK mapping file: {e}")
            return {}

    def map_to_mitre(self, entities):
        """
        Maps extracted entities to MITRE ATT&CK techniques based on the loaded mapping.

        Args:
            entities (dict): A dictionary of extracted entities from the alert,
                             e.g., {"ip_addresses": ["8.8.8.8"], "domains": ["example.com"]}

        Returns:
            list: A list of MITRE ATT&CK techniques (IDs) associated with the entities.
                  Returns an empty list if no techniques are found.
        """
        techniques = set()

        for entity_type, entity_list in entities.items():
            if entity_list:  # Check if the entity list is not empty
                for entity in entity_list:
                    # Convert entity to lowercase for case-insensitive matching
                    entity_lower = entity.lower()

                    for technique, keywords in self.mapping.items():
                        if entity_type in keywords:
                            # Check if the keyword list is not empty before iterating
                            if keywords[entity_type]:
                                for keyword in keywords[entity_type]:
                                    if keyword.lower() in entity_lower:  # Case-insensitive matching
                                        techniques.add(technique)

        return list(techniques)


# Example Usage (for testing)
if __name__ == "__main__":
    logger.info("Starting MITRE Mapping Test...")

    # Create a dummy mitre_attack_mapping.json file for testing
    dummy_mapping = {
        "T1071": {"ip_addresses": ["8.8.8.8"], "domains": ["example.com"]},
        "T1566": {"domains": ["phishing.com"], "usernames": ["john.doe"]}
    }

    with open("mitre_attack_mapping.json", "w") as f:
        json.dump(dummy_mapping, f, indent=4)

    mapper = MitreMapper()
    entities = {"ip_addresses": ["8.8.8.8"], "domains": ["test.example.com"], "usernames":["test.john.doe"]} # Added data to usernames
    mitre_techniques = mapper.map_to_mitre(entities)

    if mitre_techniques:
        print("MITRE ATT&CK Techniques:", mitre_techniques)
    else:
        print("No MITRE ATT&CK techniques found for the given entities.")

    logger.info("MITRE Mapping Test Completed.")
