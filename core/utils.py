# utils.py
import logging
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def setup_logging(log_file="siap.log"):
    """Sets up logging configuration."""
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(module)s - %(message)s",
    )
    return logging.getLogger()

def get_env_variable(variable_name):
    """Retrieves an environment variable and handles missing variables."""
    value = os.getenv(variable_name)
    if value is None:
        logger = logging.getLogger(__name__)
        logger.error(f"Missing environment variable: {variable_name}")
        raise ValueEpiprror(f"Missing environment variable: {variable_name}")
    return value

# Initialize logger
logger = setup_logging()