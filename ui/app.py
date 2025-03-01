import sys
import os
# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
import os
from siap import main  # Assuming your main logic is in siap/main.py
from siap.utils import logger, setup_logging
import logging
import base64  # For background images

# --- 1. Streamlit Configuration ---
st.set_page_config(
    page_title="SIAP: Sentinel Intelligence Augmentation & Prioritization",
    page_icon=":mag:",  # A magnifying glass icon - adjust as desired
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- 2. Custom CSS (More Polished) ---
def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style/style.css")  # Create a style.css file in a 'style' directory

# --- 3. Add a Background Image (Optional) ---
def set_bg_hack(main_bg):
    """
    A function to set background of any streamlit page
    """
    main_bg_ext = "png"

    st.markdown(
         f"""
         <style>
         .stApp {{
             background: url(data:image/{main_bg_ext};base64,{base64.b64encode(open(main_bg, "rb").read()).decode()});
             background-size: cover
         }}
         </style>
         """,
         unsafe_allow_html=True
     )

#set_bg_hack('images/security_background.png') # Put your image in an 'images' folder
                                                 # and uncomment this line

# --- 4.  Improved Title and Subheader ---
st.title("SIAP: Sentinel Intelligence Augmentation & Prioritization :mag:")
st.subheader("Unlock Hidden Insights:  Enrich and Prioritize Sentinel Alerts with AI-Powered Threat Intelligence")

# --- 5. Sidebar Configuration ---
with st.sidebar:
    st.header("Configuration Panel")
    st.markdown("Customize SIAP to your environment:")

    # API Keys (Sensitive data, don't expose)
    st.subheader("API Credentials")
    sentinel_tenant_id = st.text_input("Sentinel Tenant ID", type="password", value=os.getenv("SENTINEL_TENANT_ID", ""), help="Your Azure Sentinel Tenant ID")
    sentinel_client_id = st.text_input("Sentinel Client ID", type="password", value=os.getenv("SENTINEL_CLIENT_ID", ""), help="Your Azure Sentinel Client ID")
    sentinel_client_secret = st.text_input("Sentinel Client Secret", type="password", value=os.getenv("SENTINEL_CLIENT_SECRET", ""), help="Your Azure Sentinel Client Secret")
    openai_api_key = st.text_input("OpenAI API Key", type="password", value=os.getenv("OPENAI_API_KEY", ""), help="Your OpenAI API Key (or Azure OpenAI Key)")
    threatstream_api_key = st.text_input("ThreatStream API Key", type="password", value=os.getenv("THREATSTREAM_API_KEY", ""), help="Your ThreatStream API Key")
    threatstream_url = st.text_input("ThreatStream URL", value=os.getenv("THREATSTREAM_URL", ""), help="Your ThreatStream API URL")
    sentinel_workspace_id = st.text_input("Sentinel Workspace ID", type="password", value=os.getenv("SENTINEL_WORKSPACE_ID", ""), help="Your Sentinel Workspace ID")
    sentinel_resource_group = st.text_input("Sentinel Resource Group", value=os.getenv("SENTINEL_RESOURCE_GROUP", ""), help="Your Sentinel Resource Group")
    sentinel_subscription_id = st.text_input("Sentinel Subscription ID", value=os.getenv("SENTINEL_SUBSCRIPTION_ID", ""), help="Your Azure Subscription ID")

    # Risk Scoring Weights
    st.subheader("Risk Scoring Weights")
    severity_weight = st.slider("Severity Weight", 0.0, 1.0, 0.4, help="Weight for alert severity in risk calculation")
    threat_intel_weight = st.slider("Threat Intel Weight", 0.0, 1.0, 0.3, help="Weight for threat intelligence reputation in risk calculation")
    mitre_attack_weight = st.slider("MITRE Attack Weight", 0.0, 1.0, 0.3, help = "Weight for MITRE ATT&CK techniques in risk calculation")

    # Logging Level
    st.subheader("Logging Level")
    log_level = st.selectbox("Select Logging Level", ["DEBUG", "INFO", "WARNING", "ERROR"], help="Choose the desired logging level")

# --- 6.  Main Content Area: Alert Processing Section ---
st.header("Alert Enrichment")
alert_id = st.text_input("Enter Sentinel Alert ID", help="Enter the Alert ID from Microsoft Sentinel to enrich")

if st.button("Enrich Alert", help="Click to enrich the specified Sentinel Alert"):
    if not alert_id:
        st.warning("Please enter a Sentinel Alert ID.")
    else:
        # --- Call Your SIAP logic ---
        try:
            # --- A. Set environment variables for the current run. ---
            os.environ["SENTINEL_TENANT_ID"] = sentinel_tenant_id
            os.environ["SENTINEL_CLIENT_ID"] = sentinel_client_id
            os.environ["SENTINEL_CLIENT_SECRET"] = sentinel_client_secret
            os.environ["OPENAI_API_KEY"] = openai_api_key
            os.environ["THREATSTREAM_API_KEY"] = threatstream_api_key
            os.environ["THREATSTREAM_URL"] = threatstream_url
            os.environ["SENTINEL_WORKSPACE_ID"] = sentinel_workspace_id
            os.environ["SENTINEL_RESOURCE_GROUP"] = sentinel_resource_group
            os.environ["SENTINEL_SUBSCRIPTION_ID"] = sentinel_subscription_id

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
            enriched_data = main.enrich_alert(alert_id)  # Replace with your actual enrichment function

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

                if st.button("Update Sentinel with Enriched Data", help="Update the Sentinel alert with the enriched data"):
                    # sentinel = SentinelConnector() #Re-initialize
                    from sentinel_connector import SentinelConnector
                    sentinel = SentinelConnector()
                    update_properties = {
                        "properties": {
                            "confidenceLevel": int(enriched_data['risk_score']),  # Or another appropriate field
                            "customDetails": {  # Add custom details to the alert (optional)
                                "llm_extracted_entities": str(enriched_data['extracted_entities']),  # Convert dict to string
                                "threat_intel_data": str(enriched_data['threat_intel_reputations']),  # Convert dict to string
                                "mitre_techniques": str(enriched_data['mitre_techniques']),  # Convert list to string
                                "risk_score": str(enriched_data['risk_score']),  # Convert float to string
                            },
                            # Add MITRE ATT&CK techniques to the alert's "tactics" property (optional)
                            "tactics": enriched_data['mitre_techniques']  # This expects a list of tactic names.
                        }
                    }
                    if sentinel.update_alert(alert_id, update_properties):
                        st.success(f"Successfully updated alert {alert_id} in Sentinel.")
                    else:
                        st.error(f"Failed to update alert {alert_id} in Sentinel.")

            else:
                st.error("Failed to enrich alert. Check logs for details.")

        except Exception as e:
            st.error(f"An error occurred: {e}")
            logger.exception(e)  # Log the exception.

# --- 7. Footer (Optional) ---
st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    Developed by Rajshekar Vijay
    [LinkedIn Profile](www.linkedin.com/in/rajshekarv) | [GitHub Repository](https://github.com/Enigma-Watch)
    """
)
          
# Run the streamlit app.
# if __name__ == "__main__": #Not needed in streamlit.
# main()
