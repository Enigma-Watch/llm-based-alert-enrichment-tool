# llm_enrichment.py
import openai
from .utils import logger, get_env_variable     # Changed


class LLMEnrichment:
    def __init__(self):
        openai.api_key = get_env_variable("OPENAI_API_KEY")  # Ensure API key is set
        self.model_name = "gpt-3.5-turbo"  # Or your preferred model

    def extract_entities(self, alert_description):
        """Extracts key entities from the alert description using an LLM."""
        try:
            prompt = f"""
            Extract the following entities from this security alert description:
            - IP Addresses
            - Domains
            - Usernames
            - Filenames
            - CVEs (if any)

            Alert Description:
            {alert_description}

            Return the entities as a JSON object.  If an entity type is not present, return null for the value.  Example:
            {{
                "ip_addresses": ["192.168.1.1", "10.0.0.1"],
                "domains": ["example.com", "malicious.net"],
                "usernames": ["john.doe", "admin"],
                "filenames": ["malware.exe", "document.pdf"],
                "cves": ["CVE-2023-1234", "CVE-2022-5678"]
            }}
            """

            response = openai.ChatCompletion.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,  # Adjust for more or less randomness
            )

            llm_output = response["choices"][0]["message"]["content"]
            logger.info(f"LLM Output: {llm_output}")  # Log the LLM output
            # Parse the LLM output as JSON
            try:
                entities = json.loads(llm_output)
                return entities
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from LLM output: {e}")
                return None


        except Exception as e:
            logger.error(f"Error during LLM entity extraction: {e}")
            return None

# Example Usage (for testing)
if __name__ == "__main__":
    logger.info("Starting LLM Enrichment Test...")
    llm_enrichment = LLMEnrichment()
    test_description = "Possible phishing attempt detected. User john.doe clicked a link to malicious.net, which downloaded malware.exe.  The file communicated with IP 192.168.1.1.  This may be related to CVE-2023-1234."
    entities = llm_enrichment.extract_entities(test_description)

    if entities:
        print("Extracted Entities:", entities)
    else:
        print("No entities extracted or an error occurred.")
    logger.info("LLM Enrichment Test Completed.")
