# Alert Enrichment and Prioritization Tool

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)  <!-- Replace with your license badge -->
[![Streamlit App](https://img.shields.io/badge/Streamlit-App-orange)](https://share.streamlit.io/your_username/your_repo)  <!-- Replace with your Streamlit Share link if deployed -->

## Overview

The Alert Enrichment and Prioritization Tool is a Streamlit application designed to streamline the process of analyzing and responding to security alerts. It integrates with various Security Information and Event Management (SIEM) platforms, Threat Intelligence (TI) sources, and Large Language Models (LLMs) to enrich alerts with contextual information, prioritize them based on risk, and provide analysts with actionable insights.

## Key Features

*   **Multi-Source Alert Ingestion:** Supports ingestion of alerts from multiple SIEM platforms, including:
    *   Microsoft Sentinel
    *   Splunk
    *   Elasticsearch
    *   QRadar
    *   CSV File Upload
*   **Flexible Threat Intelligence Integration:** Enriches alerts with threat intelligence data from various sources, including:
    *   ThreatStream
    *   MISP
    *   AlienVault OTX
    *   VirusTotal
    *   (Option to disable TI integration)
*   **AI-Powered Entity Extraction:** Leverages Large Language Models (LLMs) to automatically extract key entities (IP addresses, domains, file hashes, etc.) from alert descriptions. Supports:
    *   OpenAI (GPT-3.5 Turbo)
    *   Rule-Based Entity Extraction
    *   (Option to disable LLM enrichment)
*   **Automated Risk Scoring:** Calculates a risk score for each alert based on severity, threat intelligence reputation, and MITRE ATT&CK mappings.
*   **Customizable UI Themes:** Offers multiple UI themes (light mode, dark mode, blue mode) to suit user preferences.
*   **Easy Configuration:** Provides a user-friendly sidebar for configuring API keys, connection settings, and risk scoring weights.

## Architecture

The application follows a modular architecture, with distinct components for:

*   **UI (Streamlit):** Handles user interaction, configuration, and result display.
*   **Core Logic:** Implements the alert enrichment and prioritization logic.
*   **Connectors:** Provides interfaces and implementations for connecting to different SIEM platforms, TI sources, and LLMs.

## Getting Started

### Prerequisites

*   Python 3.8+
*   Streamlit
*   An account and API keys for the SIEM, TI, and LLM services you want to use (if applicable).

### Installation

1.  **Clone the repository:**

    ```
    git clone https://github.com/your_username/your_repo.git  # Replace with your repository URL
    cd your_repo
    ```

2.  **Create a virtual environment:**

    ```
    python -m venv .venv
    ```

3.  **Activate the virtual environment:**

    *   **On Windows:**

        ```
        .venv\Scripts\activate
        ```

    *   **On macOS and Linux:**

        ```
        source .venv/bin/activate
        ```

4.  **Install dependencies:**

    ```
    pip install -r requirements.txt
    ```

5.  **Configure environment variables:**

    *   Create a `.env` file in the root directory of the project.
    *   Add your API keys and connection settings to the `.env` file. See the `.env.example` file for a template.

### Running the App

