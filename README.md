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

    ```
    streamlit run ui/app.py
    ```

This will start the Streamlit app in your web browser.

### Configuration

The application is configured via the sidebar in the Streamlit UI. You can configure the following:

*   **UI Theme:** Select a theme (light, dark, blue) for the application interface.
*   **Alert Source:** Choose the SIEM platform or alert source:
    *   **Sentinel:** Provide Tenant ID, Client ID, Client Secret, Workspace ID, Resource Group, and Subscription ID.
    *   **Splunk:** Provide Host, Port, and Token.
    *   **Elasticsearch:** Provide Host, Port, User, and Password.
    *   **QRadar:** Provide Host and Token.
    *   **CSV File:** Upload a CSV file containing alert data and specify the column containing descriptions for entity extraction and risk scoring.
*   **Threat Intelligence:** Select the Threat Intelligence source:
    *   **ThreatStream:** Provide API Key and URL.
    *   **MISP:** Provide URL and Key.
    *   **AlienVault OTX:** Provide API Key.
    *   **VirusTotal:** Provide API Key.
    *   **None:** Disable threat intelligence integration.
*   **LLM Enrichment:** Select the LLM source:
    *   **OpenAI:** Provide API Key.
    *   **Rule-Based:** Configure custom rules in the code.
    *   **None:** Disable LLM enrichment.
*   **Risk Scoring Weights:** Adjust the weights for alert severity, threat intelligence reputation, and MITRE ATT&CK techniques in the risk calculation.
*   **Logging Level:** Select the desired logging level (DEBUG, INFO, WARNING, ERROR).

## Usage

1.  **Enter Alert ID:** In the main panel, enter the ID of the alert you want to enrich.
2.  **Click "Enrich Alert":** The application will retrieve the alert data, extract entities, enrich it with threat intelligence, map it to MITRE ATT&CK techniques, and calculate a risk score.
3.  **View Results:** The enriched alert data, extracted entities, threat intelligence reputations, MITRE techniques, and risk score will be displayed in the main panel.

## Customization

*   **Adding a New Connector:** To add support for a new SIEM, TI source, or LLM, you'll need to create a new connector class that implements the appropriate interface (`AlertConnector`, `ThreatIntelConnector`, or `LLMConnector`).
*   **Customizing Risk Scoring:** You can modify the risk scoring logic in `core/risk_scoring.py` to suit your specific requirements.
*   **Adding/Modifying CSS Themes:** You can change the CSS themes in the `style/style.css` file.

## Contributing

Contributions are welcome! Please follow these steps:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes and commit them with descriptive messages.
4.  Push your changes to your fork.
5.  Submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

[Rajshekar Vijay] - [rajshekarvijay@protonmail.com] - [https://www.linkedin.com/in/rajshekarv]

## Acknowledgements

*   Streamlit for providing a great framework for building data apps.
*   The MITRE Corporation for the ATT&CK framework.
*   The open-source community for the various libraries and resources used in this project.


