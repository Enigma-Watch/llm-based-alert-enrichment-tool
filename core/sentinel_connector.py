# sentinel_connector.py
from azure.identity import ClientSecretCredential # type: ignore
from azure.graphrbac import GraphRbacManagementClient # type: ignore
import requests
import json
from .utils import logger, get_env_variable  # Import logger from utils.py  # Changed



class SentinelConnector:
    def __init__(self):
        self.tenant_id = get_env_variable("SENTINEL_TENANT_ID")
        self.client_id = get_env_variable("SENTINEL_CLIENT_ID")
        self.client_secret = get_env_variable("SENTINEL_CLIENT_SECRET")
        
        # Replace with your Workspace ID and Resource Group Name
        self.workspace_id = "your_sentinel_workspace_id"
        self.resource_group_name = "your_sentinel_resource_group"
        self.subscription_id = "your_azure_subscription_id"
        self.alerts_api_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_id}/providers/Microsoft.SecurityInsights/alerts?api-version=2023-02-01-preview"
        self.access_token = self._get_access_token()

    def _get_access_token(self):
        """Authenticates with Azure and retrieves an access token."""
        try:
            credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            # Use the credential to get a token for the Microsoft Graph API
            token = credential.get_token("https://management.azure.com/.default")
            return token.token
        except Exception as e:
            logger.error(f"Error getting access token: {e}")
            raise

    def get_alerts(self):
        """Retrieves alerts from Microsoft Sentinel."""
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.get(self.alerts_api_url, headers=headers)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            alerts = response.json().get("value", [])
            logger.info(f"Successfully retrieved {len(alerts)} alerts from Sentinel.")
            return alerts
        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving alerts from Sentinel: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response from Sentinel: {e}")
            return []

    def update_alert(self, alert_id, properties):
        """Updates a Sentinel alert with the provided properties."""
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        alert_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_id}/providers/Microsoft.SecurityInsights/alerts/{alert_id}?api-version=2023-02-01-preview"  # Corrected URL

        try:
            response = requests.patch(alert_url, headers=headers, json=properties)
            response.raise_for_status()
            logger.info(f"Successfully updated alert {alert_id} in Sentinel.")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Error updating alert {alert_id} in Sentinel: {e}")
            return False

# Example Usage (for testing):
if __name__ == "__main__":
    logger.info("Starting Sentinel Connector Test...")
    sentinel = SentinelConnector()
    alerts = sentinel.get_alerts()
    if alerts:
        print(f"Found {len(alerts)} alerts.")
        # Example: Print the display name of the first alert
        print(f"First alert display name: {alerts[0].get('properties', {}).get('displayName', 'N/A')}")

        #Example of updating an alert.  You need to have an alert to test this.  Uncomment and modify with a real alert ID
        # alert_id_to_update = "your_alert_id_here" #Replace with a valid alert id
        # update_properties = {"properties": {"status": "Resolved"}} #Example changing status.
        # if sentinel.update_alert(alert_id_to_update, update_properties):
        #     print(f"Alert {alert_id_to_update} updated successfully.")
        # else:
        #     print(f"Failed to update alert {alert_id_to_update}.")
    else:
        print("No alerts found.")
    logger.info("Sentinel Connector Test Completed.")
