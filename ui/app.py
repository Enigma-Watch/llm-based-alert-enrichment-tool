import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
import os
from core import main 
from core.utils import logger, setup_logging
import logging
import base64

# --- 1. Streamlit Configuration ---
st.set_page_config(
    page_title="Alert Enrichment and Prioritization Tool",
    page_icon=":mag:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- 2. Custom CSS (More Polished) ---
def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style/style.css")

# --- 3. Theme Selection ---
st.sidebar.header("UI Theme")
theme_selection = st.sidebar.selectbox("Select Theme", ["light-mode", "dark-mode", "blue-mode"], help="Choose the color theme for the application")

# --- Apply the theme using st.markdown ---
st.markdown(
    f"""
    <style>
    .stApp {{
        background-color: var(--{theme_selection}-background) !important;
        color: var(--{theme_selection}-text) !important;
    }}
    /* Override Streamlit's default button style */
    .stButton>button {{
        background-color: var(--{theme_selection}-button) !important;
        color: white !important;
        border: none !important;
        padding: 10px 20px !important;
        text-align: center !important;
        text-decoration: none !important;
        display: inline-block !important;
        font-size: 16px !important;
        margin: 4px 2px !important;
        cursor: pointer !important;
        border-radius: 5px !important;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# --- 4.  Main Content Area ---
st.title("Alert Enrichment and Prioritization Tool :mag:")  # Generic title
st.subheader("Unlock Hidden Insights:  Enrich and Prioritize Alerts with AI-Powered Threat Intelligence")

# --- 5. Configuration Panel (in Sidebar) ---
with st.sidebar:
    st.header("Configuration Panel")
    st.markdown("Customize the tool to your environment:")

    # --- A. Alert Source Configuration ---
    st.subheader("Alert Source")
    alert_source = st.selectbox("Select Alert Source", ["Sentinel", "Splunk", "Elasticsearch", "QRadar", "CSV File"], help="Choose your SIEM platform or alert source")

    # Configuration options for each alert source
    if alert_source == "Sentinel":
        st.subheader("Sentinel Configuration")
        sentinel_tenant_id = st.text_input("Tenant ID", type="password", value=os.getenv("SENTINEL_TENANT_ID", ""), help="Your Azure Sentinel Tenant ID")
        sentinel_client_id = st.text_input("Client ID", type="password", value=os.getenv("SENTINEL_CLIENT_ID", ""), help="Your Azure Sentinel Client ID")
        sentinel_client_secret = st.text_input("Client Secret", type="password", value=os.getenv("SENTINEL_CLIENT_SECRET", ""), help="Your Azure Sentinel Client Secret")
        sentinel_workspace_id = st.text_input("Workspace ID", type="password", value=os.getenv("SENTINEL_WORKSPACE_ID", ""), help="Your Sentinel Workspace ID")
        sentinel_resource_group = st.text_input("Resource Group", value=os.getenv("SENTINEL_RESOURCE_GROUP", ""), help="Your Sentinel Resource Group")
        sentinel_subscription_id = st.text_input("Subscription ID", value=os.getenv("SENTINEL_SUBSCRIPTION_ID", ""), help="Your Azure Subscription ID")

    elif alert_source == "Splunk":
        st.subheader("Splunk Configuration")
        splunk_host = st.text_input("Host", value=os.getenv("SPLUNK_HOST", ""), help="Splunk Host")
        splunk_port = st.text_input("Port", value=os.getenv("SPLUNK_PORT", ""), help="Splunk Port")
        splunk_token = st.text_input("Token", type="password", value=os.getenv("SPLUNK_TOKEN", ""), help="Splunk Token")

    elif alert_source == "Elasticsearch":
        st.subheader("Elasticsearch Configuration")
        es_host = st.text_input("Host", value=os.getenv("ES_HOST", ""), help="Elasticsearch Host")
        es_port = st.text_input("Port", value=os.getenv("ES_PORT", ""), help="Elasticsearch Port")
        es_user = st.text_input("User", value=os.getenv("ES_USER", ""), help="Elasticsearch User")
        es_password = st.text_input("Password", type="password", value=os.getenv("ES_PASSWORD", ""), help="Elasticsearch Password")

    elif alert_source == "QRadar":
        st.subheader("QRadar Configuration")
        qradar_host = st.text_input("Host", value=os.getenv("QRADAR_HOST", ""), help="QRadar Host")
        qradar_token = st.text_input("Token", type="password", value=os.getenv("QRADAR_TOKEN", ""), help="QRadar Token")

    elif alert_source == "CSV File":
        st.subheader("CSV Configuration")
        csv_file = st.file_uploader("Upload CSV File", type=["csv"], help="Upload a CSV file containing alert data")
        # To Do, ensure it exists.
        csv_id_field = st.text_input("Unique ID field name", value = os.getenv("CSV_ID_FIELD",""), help = "Provide a unique ID field name to identify specific alerts in the CSV file.")
        csv_description_field = st.text_input("Description field name", value = os.getenv("CSV_DESCRIPTION_FIELD",""), help = "Provide a description field name to feed the LLM to extract entities.")
        #Add other fields here.

    # --- B. Threat Intelligence Configuration ---
    st.subheader("Threat Intelligence")
    ti_source = st.selectbox("Select Threat Intelligence Source", ["ThreatStream", "MISP", "AlienVault OTX", "VirusTotal", "None"], help="Choose your Threat Intelligence platform")

    if ti_source == "ThreatStream":
        st.subheader("ThreatStream Configuration")
        threatstream_api_key = st.text_input("API Key", type="password", value=os.getenv("THREATSTREAM_API_KEY", ""), help="Your ThreatStream API Key")
        threatstream_url = st.text_input("URL", value=os.getenv("THREATSTREAM_URL", ""), help="Your ThreatStream API URL")

    elif ti_source == "MISP":
        st.subheader("MISP Configuration")
        misp_url = st.text_input("URL", value=os.getenv("MISP_URL", ""), help="Your MISP URL")
        misp_key = st.text_input("Key", value=os.getenv("MISP_KEY", ""), help="Your MISP Key")

    elif ti_source == "AlienVault OTX":
        st.subheader("AlienVault OTX Configuration")
        otx_key = st.text_input("API Key", type="password", value=os.getenv("OTX_KEY", ""), help="Your AlienVault OTX API Key")

    elif ti_source == "VirusTotal":
        st.subheader("VirusTotal Configuration")
        vt_key = st.text_input("API Key", type="password", value=os.getenv("VT_KEY", ""), help="Your VirusTotal API Key")

    elif ti_source == "None":
        st.info("No Threat Intelligence source selected. Enrichment will be limited.")

    # --- C. LLM Configuration ---
    st.subheader("LLM Enrichment")
    llm_source = st.selectbox("Select LLM Source", ["OpenAI", "Rule-Based", "None"], help="Choose your LLM provider")

    if llm_source == "OpenAI":
        st.subheader("OpenAI Configuration")
        openai_api_key = st.text_input("API Key", type="password", value=os.getenv("OPENAI_API_KEY", ""), help="Your OpenAI API Key (or Azure OpenAI Key)")

    elif llm_source == "Rule-Based":
        st.info("Rule-based entity extraction selected.  Configure custom rules in the code.")

    elif llm_source == "None":
        st.info("No LLM selected. Entity extraction will be limited.")

    # --- D. Risk Scoring Weights ---
    st.subheader("Risk Scoring Weights")
    severity_weight = st.slider("Severity Weight", 0.0, 1.0, 0.4, help="Weight for alert severity in risk calculation")
    threat_intel_weight = st.slider("Threat Intel Weight", 0.0, 1.0, 0.3, help="Weight for threat intelligence reputation in risk calculation")
    mitre_attack_weight = st.slider("MITRE Attack Weight", 0.0, 1.0, 0.3, help="Weight for MITRE ATT&CK techniques in risk calculation")

    # --- E. Logging Level ---
    st.subheader("Logging Level")
    log_level = st.selectbox("Select Logging Level", ["DEBUG", "INFO", "WARNING", "ERROR"], help="Choose the desired logging level")

# --- 6.  Main Content Area: Alert Processing Section ---
#st.markdown(f"<div class='{theme_selection}'>", unsafe_allow_html=True)
st.header("Alert Enrichment")
alert_id = st.text_input("Enter Alert ID", help="Enter the Alert ID from the selected platform to enrich")

if st.button("Enrich Alert", help="Click to enrich the specified Alert"):
    if not alert_id:
        st.warning("Please enter an Alert ID.")
    else:
        # --- Call Your SIAP logic ---
        try:
            # --- A. Set environment variables for the current run. ---
            # Conditionally set environment variables based on what was selected.
            os.environ["ALERT_SOURCE"] = alert_source #Store what ALert Source was selected.

            #Sentinel
            os.environ["SENTINEL_TENANT_ID"] = sentinel_tenant_id if alert_source == "Sentinel" and 'sentinel_tenant_id' in locals() else ""
            os.environ["SENTINEL_CLIENT_ID"] = sentinel_client_id if alert_source == "Sentinel" and 'sentinel_client_id' in locals() else ""
            os.environ["SENTINEL_CLIENT_SECRET"] = sentinel_client_secret if alert_source == "Sentinel" and 'sentinel_client_secret' in locals() else ""
            os.environ["SENTINEL_WORKSPACE_ID"] = sentinel_workspace_id if alert_source == "Sentinel" and 'sentinel_workspace_id' in locals() else ""
            os.environ["SENTINEL_RESOURCE_GROUP"] = sentinel_resource_group if alert_source == "Sentinel" and 'sentinel_resource_group' in locals() else ""
            os.environ["SENTINEL_SUBSCRIPTION_ID"] = sentinel_subscription_id if alert_source == "Sentinel" and 'sentinel_subscription_id' in locals() else ""

            #Splunk
            os.environ["SPLUNK_HOST"] = splunk_host if alert_source == "Splunk" and 'splunk_host' in locals() else ""
            os.environ["SPLUNK_PORT"] = splunk_port if alert_source == "Splunk" and 'splunk_port' in locals() else ""
            os.environ["SPLUNK_TOKEN"] = splunk_token if alert_source == "Splunk" and 'splunk_token' in locals() else ""

            #ElasticSearch
            os.environ["ES_HOST"] = es_host if alert_source == "Elasticsearch" and 'es_host' in locals() else ""
            os.environ["ES_PORT"] = es_port if alert_source == "Elasticsearch" and 'es_port' in locals() else ""
            os.environ["ES_USER"] = es_user if alert_source == "Elasticsearch" and 'es_user' in locals() else ""
            os.environ["ES_PASSWORD"] = es_password if alert_source == "Elasticsearch" and 'es_password' in locals() else ""

             #QRadar
            os.environ["QRADAR_HOST"] = qradar_host if alert_source == "QRadar" and 'qradar_host' in locals() else ""
            os.environ["QRADAR_TOKEN"] = qradar_token if alert_source == "QRadar" and 'qradar_token' in locals() else ""

            #Threat Intels
            os.environ["TI_SOURCE"] = ti_source #Store what TI Source was selected.
            os.environ["THREATSTREAM_API_KEY"] = threatstream_api_key if ti_source == "ThreatStream" and 'threatstream_api_key' in locals() else ""
            os.environ["THREATSTREAM_URL"] = threatstream_url if ti_source == "ThreatStream" and 'threatstream_url' in locals() else ""
            os.environ["MISP_URL"] = misp_url if ti_source == "MISP" and 'misp_url' in locals() else ""
            os.environ["MISP_KEY"] = misp_key if ti_source == "MISP" and 'misp_key' in locals() else ""
            os.environ["OTX_KEY"] = otx_key if ti_source == "AlienVault OTX" and 'otx_key' in locals() else ""
            os.environ["VT_KEY"] = vt_key if ti_source == "VirusTotal" and 'vt_key' in locals() else ""

            #LLMs
            os.environ["LLM_SOURCE"] = llm_source #Store what LLM Source was selected.
            os.environ["OPENAI_API_KEY"] = openai_api_key if llm_source == "OpenAI" and 'openai_api_key' in locals() else ""

            #CSV - Store what fields you need here.
            if alert_source == "CSV File" and csv_file is not None: #Check if the file exists.
                os.environ["CSV_ID_FIELD"] = csv_id_field  if 'csv_id_field' in locals() else ""
                os.environ["CSV_DESCRIPTION_FIELD"] = csv_description_field if 'csv_description_field' in locals() else ""
                #Read the CSV here.
                #To Do: Check for CSV read errors.
                try:
                    csv_data = pd.read_csv(csv_file)
                except Exception as e:
                    st.error(f"There was a CSV Read error: {e}")
                #Find the alert and set the alert description and all alert details.
                try:
                    #Check if the field are empty.
                    if not csv_id_field or not csv_description_field:
                        st.error(f"The ID field or the Description field is empty")
                    else:
                        csv_alert = csv_data[csv_data[csv_id_field] == alert_id] #Find alert.
                        if csv_alert.empty:
                            st.error(f"Alert ID {alert_id} was not found in the CSV file.")
                        else:
                            os.environ["ALERT_DESCRIPTION"] = csv_alert[csv_description_field].iloc[0] #Load it to the env.
                            #Add other key environment variables here.
                except Exception as e:
                    st.error(f"CSV Processing error: {e}")
            else:
                os.environ["ALERT_DESCRIPTION"] = "" #Reset variable since it may be left over from other runs.

            # --- B. Set the logging level ---
            log_level_mapping = {
                "DEBUG": logging.DEBUG,
                "INFO": logging.INFO,
                "WARNING": logging.WARNING,
                "ERROR": logging.ERROR,
            }
            log_level_value = log_level_mapping.get(log_level, logging.INFO)  # Default to INFO
            logger.setLevel(log_level_value)  # Set the level for the root logger

            setup_logging()  # Re-initialize logging.
            enriched_data = main.enrich_alert(alert_id, alert_source, ti_source, llm_source)  # Pass configuration to main logic

            # --- C. Display Results ---
            if enriched_data:
                st.subheader("Enriched Alert Data")

                # Use columns for a better layout
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Alert ID:** {enriched_data['alert_id']}")
                    st.write(f"**Risk Score:** {enriched_data['risk_score']:.2f}") #Format risk score
                with col2:
                    # You could add a gauge or progress bar here to visualize the risk score
                    st.progress(int(enriched_data['risk_score']), text=f"Risk: {int(enriched_data['risk_score'])}/100")

                with st.expander("Extracted Entities"):
                    st.json(enriched_data['extracted_entities'])

                with st.expander("Threat Intelligence Reputations"):
                    st.json(enriched_data['threat_intel_reputations'])

                with st.expander("MITRE Techniques"):
                    st.write(enriched_data['mitre_techniques'])

            else:
                st.error("Failed to enrich alert. Check logs for details.")

        except Exception as e:
            st.error(f"An error occurred: {e}")
            logger.exception(e)  # Log the exception.

#st.markdown("</div>", unsafe_allow_html=True)

# --- 7. Footer (Optional) ---
st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    Developed by Rajshekar Vijay
    [LinkedIn Profile](https://www.linkedin.com/in/rajshekarv) | [GitHub Repository](https://github.com/Enigma-Watch)
    """
)

local_css("style/style.css")

