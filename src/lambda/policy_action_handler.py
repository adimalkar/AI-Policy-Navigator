import json
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class PolicyActionHandler:
    """
    Core Lambda handler for Amazon Bedrock Agent Action Groups.
    Processes structured event payloads emitted by Bedrock Agents,
    executes policy validation rules, and formats standardized OpenAPI responses.
    """

    def __init__(self):
        # In-memory policy rules catalog (can be extended to DynamoDB/S3)
        self.policy_catalog = {
            "DATA_RETENTION": {
                "max_days": 90,
                "encryption_required": True,
                "classification": ["CONFIDENTIAL", "RESTRICTED", "INTERNAL"]
            },
            "ACCESS_CONTROL": {
                "mfa_mandatory": True,
                "session_timeout_minutes": 15,
                "least_privilege_enforced": True
            },
            "AI_MODEL_USAGE": {
                "require_pii_filtering": True,
                "approved_providers": ["anthropic", "amazon"]
            }
        }

    def evaluate_compliance(self, policy_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates whether provided configuration parameters adhere to organization standards.
        """
        policy_key = policy_type.upper()
        if policy_key not in self.policy_catalog:
            return {
                "compliant": False,
                "reason": f"Unknown policy category: {policy_type}. Valid categories: {list(self.policy_catalog.keys())}"
            }

        rules = self.policy_catalog[policy_key]
        violations = []

        if policy_key == "DATA_RETENTION":
            retention_days = parameters.get("retention_days", 0)
            encrypted = parameters.get("encrypted", False)

            if retention_days > rules["max_days"]:
                violations.append(f"Retention period ({retention_days} days) exceeds maximum allowed ({rules['max_days']} days).")
            if not encrypted:
                violations.append("Data encryption at rest is mandatory under enterprise retention policy.")

        elif policy_key == "ACCESS_CONTROL":
            mfa_enabled = parameters.get("mfa_enabled", False)
            if not mfa_enabled:
                violations.append("Multi-Factor Authentication (MFA) must be enabled.")
                
        elif policy_key == "AI_MODEL_USAGE":
            approved_models = ["anthropic.claude-3-sonnet-20240229-v1:0", "amazon.titan-text-express-v1"]
            model_id = parameters.get("model_id", "")
            pii_filtering = parameters.get("pii_filtering_enabled", False)
            
            if model_id not in approved_models:
                violations.append(f"Model {model_id} is not on the enterprise approved list.")
            if not pii_filtering:
                violations.append("PII filtering guardrails must be enabled for all Generative AI usage.")

        is_compliant = len(violations) == 0
        return {
            "compliant": is_compliant,
            "policy_type": policy_type,
            "violations": violations,
            "status": "APPROVED" if is_compliant else "REJECTED"
        }

    def handle_bedrock_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Entry point to parse Amazon Bedrock Agent OpenAPI action invocation event.
        """
        logger.info(f"Received Bedrock Agent Event: {json.dumps(event)}")

        action_group = event.get("actionGroup", "")
        api_path = event.get("apiPath", "")
        http_method = event.get("httpMethod", "POST")
        parameters = event.get("parameters", [])
        request_body = event.get("requestBody", {}).get("content", {}).get("application/json", {}).get("properties", [])

        # Parse parameter list into key-value map
        param_dict = {}
        for param in parameters:
            param_dict[param.get("name")] = param.get("value")
        for prop in request_body:
            param_dict[prop.get("name")] = prop.get("value")

        policy_type = param_dict.get("policy_type", "DATA_RETENTION")
        result = self.evaluate_compliance(policy_type, param_dict)

        # Standard Bedrock Agent action group response format
        response_body = {
            "application/json": {
                "body": json.dumps(result)
            }
        }

        action_response = {
            "actionGroup": action_group,
            "apiPath": api_path,
            "httpMethod": http_method,
            "httpStatusCode": 200,
            "responseBody": response_body
        }

        return {
            "messageVersion": "1.0",
            "response": action_response
        }


# Global handler instance
_handler = PolicyActionHandler()

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda entry point function."""
    return _handler.handle_bedrock_event(event)
