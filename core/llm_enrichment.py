# core/llm_enrichment.py
import os
from core.llm_connectors import OpenAIConnector, RuleBasedConnector
from core.utils import logger

class LLMEnrichment:
    def extract_entities(self, text):
        """
        Extracts entities from text using the specified language model source.

        Args:
            text (str): The text to extract entities from.

        Returns:
            dict: A dictionary containing the extracted entities, or None if an error occurred.
        """
        try:
            llm_source = os.getenv("LLM_SOURCE")
            if llm_source == "OpenAI":
                connector = OpenAIConnector()
            elif llm_source == "Rule-Based":
                connector = RuleBasedConnector()
            else:
                logger.warning(f"Unsupported LLM source: {llm_source}")
                return None

            entities = connector.extract_entities(text)
            return entities

        except Exception as e:
            logger.error(f"Error extracting entities using LLM: {e}")
            return None