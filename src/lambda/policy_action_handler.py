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
            },
            "INFRASTRUCTURE_SECURITY": {
                "allow_public_s3": False,
                "min_tls_version": 1.2,
                "require_vpc_endpoints": True
            }
        }
        # In-memory approved compliance exceptions map
        self.active_exceptions: Dict[str, Dict[str, Any]] = {}

    def register_exception(
        self,
        policy_type: str,
        exception_id: str,
        justification: str,
        approved_by: str,
        expires_at: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Registers an approved enterprise compliance exception/waiver.
        """
        record = {
            "policy_type": policy_type.upper(),
            "exception_id": exception_id,
            "justification": justification,
            "approved_by": approved_by,
            "expires_at": expires_at,
            "active": True
        }
        self.active_exceptions[exception_id] = record
        return record

    def evaluate_compliance(
        self,
        policy_type: str,
        parameters: Dict[str, Any],
        exception_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validates whether provided configuration parameters adhere to organization standards.
        Checks for registered waivers/exceptions if an exception_id is provided.
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

        elif policy_key == "INFRASTRUCTURE_SECURITY":
            allow_public_s3 = parameters.get("allow_public_s3", True)
            tls_version = float(parameters.get("tls_version", 1.0))
            use_vpc_endpoint = parameters.get("use_vpc_endpoint", False)

            if allow_public_s3:
                violations.append("Public S3 bucket access is strictly prohibited under infrastructure security policy.")
            if tls_version < rules["min_tls_version"]:
                violations.append(f"TLS version ({tls_version}) does not meet minimum requirement ({rules['min_tls_version']}).")
            if rules["require_vpc_endpoints"] and not use_vpc_endpoint:
                violations.append("VPC endpoints are required for private internal AWS communications.")

        has_active_exception = False
        exception_note = None
        if exception_id and exception_id in self.active_exceptions:
            exc = self.active_exceptions[exception_id]
            if exc.get("active") and exc.get("policy_type") == policy_key:
                has_active_exception = True
                exception_note = f"Exception {exception_id} approved by {exc.get('approved_by')}: {exc.get('justification')}"

        is_compliant = len(violations) == 0 or has_active_exception
        status = "APPROVED_WITH_EXCEPTION" if (has_active_exception and len(violations) > 0) else ("APPROVED" if is_compliant else "REJECTED")

        return {
            "compliant": is_compliant,
            "policy_type": policy_type,
            "violations": violations,
            "status": status,
            "has_exception": has_active_exception,
            "exception_note": exception_note
        }

    def evaluate_multi_policy_audit(self, audit_request: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes a comprehensive multi-policy compliance audit across all domains.
        Computes aggregate compliance index, maps violations, and synthesizes remediation roadmap.
        """
        domain_results: Dict[str, Any] = {}
        total_policies = len(audit_request)
        compliant_count = 0
        all_violations: List[Dict[str, Any]] = []

        for p_type, params in audit_request.items():
            exc_id = params.get("exception_id")
            res = self.evaluate_compliance(p_type, params, exception_id=exc_id)
            domain_results[p_type] = res
            if res.get("compliant", False):
                compliant_count += 1
            for v in res.get("violations", []):
                all_violations.append({
                    "policy": p_type,
                    "violation": v,
                    "severity": "CRITICAL" if ("prohibited" in v or "mandatory" in v or "MFA" in v) else "HIGH"
                })

        compliance_score = round((compliant_count / total_policies) * 100.0, 1) if total_policies > 0 else 0.0

        return {
            "total_domains_audited": total_policies,
            "compliant_domains": compliant_count,
            "compliance_score_pct": compliance_score,
            "overall_status": "COMPLIANT" if compliant_count == total_policies else "ACTION_REQUIRED",
            "domain_results": domain_results,
            "total_violations": len(all_violations),
            "remediation_items": all_violations
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
