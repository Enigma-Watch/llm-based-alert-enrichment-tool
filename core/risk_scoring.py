# risk_scoring.py
from .utils import logger  

class RiskScorer:
    def __init__(self, weights=None):
        """
        Initializes the RiskScorer with custom weights.

        Args:
            weights (dict, optional): A dictionary containing weights for different
                                      factors. Defaults to None (using default weights).
        """
        # Default weights (can be customized)
        self.weights = weights or {
            "severity": 0.4,
            "threat_intel": 0.3,
            "mitre_attack": 0.3,
        }

    def calculate_risk_score(self, severity, threat_intel_reputation, mitre_techniques):
        """
        Calculates the risk score based on severity, threat intelligence reputation,
        and MITRE ATT&CK techniques.

        Args:
            severity (str): Severity of the alert (e.g., "High", "Medium", "Low").
            threat_intel_reputation (dict): Threat intelligence reputation data.
            mitre_techniques (list): List of MITRE ATT&CK techniques.

        Returns:
            float: The calculated risk score (between 0 and 100).
        """
        try:
            # Severity score mapping
            severity_scores = {
                "High": 80,
                "Medium": 50,
                "Low": 20,
                "Informational": 10,  # Added informational
            }

            severity_score = severity_scores.get(severity, 0)  # Default to 0 if not found

            # Threat intelligence score (adjust based on your TIP data)
            threat_intel_score = 0
            if threat_intel_reputation:
                # Example: If ThreatStream marks it as malicious, give a high score
                if threat_intel_reputation.get("is_malicious"):
                    threat_intel_score = 70
                elif threat_intel_reputation.get("confidence") > 70:  # Adjust confidence threshold
                    threat_intel_score = 50
                else:
                    threat_intel_score = 30

            # MITRE ATT&CK score (adjust based on the number of techniques)
            mitre_score = min(len(mitre_techniques) * 10, 100)  # Cap at 100

            # Apply weights
            risk_score = (
                self.weights["severity"] * severity_score
                + self.weights["threat_intel"] * threat_intel_score
                + self.weights["mitre_attack"] * mitre_score
            )

            logger.info(f"Calculated risk score: {risk_score}")
            return risk_score

        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 0


# Example Usage (for testing)
if __name__ == "__main__":
    logger.info("Starting Risk Scoring Test...")
    scorer = RiskScorer()

    # Example data
    severity = "High"
    threat_intel_reputation = {"is_malicious": True, "confidence": 90}
    mitre_techniques = ["T1071", "T1566"]

    risk_score = scorer.calculate_risk_score(severity, threat_intel_reputation, mitre_techniques)
    print(f"Risk Score: {risk_score}")
    logger.info("Risk Scoring Test Completed.")
