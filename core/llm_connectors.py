# core/llm_connectors.py
from abc import ABC, abstractmethod
import os
import openai
from core.utils import logger

class LLMConnector(ABC):
    @abstractmethod
    def extract_entities(self, text):
        """
        Abstract method to extract entities from text using a language model.
        """
        pass

class OpenAIConnector(LLMConnector):
    def __init__(self):
        """
        Initializes the OpenAI connector with API key from environment variables.
        """
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            logger.error("Missing OpenAI API key in environment variables.")
            raise ValueError("Missing OpenAI API key in environment variables.")

    def extract_entities(self, text):
        """
        Extracts entities from text using OpenAI's GPT-3.5 Turbo model.

        Args:
            text (str): The text to extract entities from.

        Returns:
            dict: A dictionary containing the extracted entities, or None if an error occurred.
        """
        # Placeholder: Implement OpenAI API call to extract entities
        logger.info(f"Extracting entities from text using OpenAI: {text[:50]}...")  # Log first 50 chars

        # Dummy Data
        extracted_entities = {
            "ip_addresses": ["192.168.1.1", "10.0.0.1"],
            "domains": ["example.com", "test.net"],
            "file_hashes": ["a1b2c3d4e5f6", "7890abcdef12"],
        }
        return extracted_entities

class RuleBasedConnector(LLMConnector):
    def __init__(self):
        """
        Initializes the RuleBased connector with rules.
        """
        pass

    def extract_entities(self, text):
        """
        Extracts entities from text using rules.
        Args:
            text (str): The text to extract entities from.

        Returns:
            dict: A dictionary containing the extracted entities, or None if an error occurred.
        """
        # Placeholder: Implement your own custom entity extraction
        logger.info(f"Extracting entities from text using rules: {text[:50]}...")  # Log first 50 chars
        extracted_entities = {
            "ip_addresses": ["127.0.0.1"],
            "domains": ["localhost", "test.com"],
            "file_hashes": [],
        }
        return extracted_entities
