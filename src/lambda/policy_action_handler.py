import json
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_TRUE_STRINGS = {"true", "1", "yes", "on"}
_FALSE_STRINGS = {"false", "0", "no", "off", ""}


def _coerce_bool(value: Any) -> bool:
    """Parse boolean and stringified boolean values without treating 'false' as truthy."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUE_STRINGS:
            return True
        if normalized in _FALSE_STRINGS:
            return False
    raise ValueError(f"Invalid boolean value: {value!r}")


def _coerce_number(value: Any, *, as_int: bool = False) -> Any:
    """Parse numeric and stringified numeric values while rejecting booleans and non-finite floats."""
    if isinstance(value, bool):
        raise ValueError(f"Invalid numeric value: {value!r}")
    if as_int:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value.strip())
        raise ValueError(f"Invalid integer value: {value!r}")
    if isinstance(value, (int, float)):
        parsed = float(value)
    elif isinstance(value, str):
        parsed = float(value.strip())
    else:
        raise ValueError(f"Invalid numeric value: {value!r}")
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        raise ValueError(f"Invalid numeric value: {value!r}")
    return parsed


def _coerce_bedrock_value(value: Any, param_type: Optional[str] = None) -> Any:
    """Coerce Amazon Bedrock Agent string-serialized parameter values using declared OpenAPI types."""
    if value is None or not param_type:
        return value
    kind = str(param_type).strip().lower()
    try:
        if kind == "boolean":
            return _coerce_bool(value)
        if kind == "integer":
            return _coerce_number(value, as_int=True)
        if kind == "number":
            return _coerce_number(value, as_int=False)
        if kind == "array" and isinstance(value, str):
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else value
    except (ValueError, TypeError, json.JSONDecodeError):
        # Preserve raw value so policy validation can report a structured violation.
        return value
    return value


def _parse_bool_param(
    parameters: Dict[str, Any],
    key: str,
    default: bool,
    violations: List[str],
) -> Optional[bool]:
    """Read and validate a boolean parameter, appending a violation on invalid values."""
    raw = parameters.get(key, default)
    try:
        return _coerce_bool(raw)
    except ValueError:
        violations.append(f"Invalid {key} value ({raw!r}): must be a boolean.")
        return None


def _parse_number_param(
    parameters: Dict[str, Any],
    key: str,
    default: Any,
    violations: List[str],
    *,
    as_int: bool = False,
) -> Optional[Any]:
    """Read and validate a numeric parameter, appending a violation on invalid values."""
    raw = parameters.get(key, default)
    try:
        return _coerce_number(raw, as_int=as_int)
    except ValueError:
        expected = "an integer" if as_int else "a number"
        violations.append(f"Invalid {key} value ({raw!r}): must be {expected}.")
        return None


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
        if not isinstance(policy_type, str) or not policy_type.strip():
            return {
                "compliant": False,
                "reason": f"Unknown policy category: {policy_type}. Valid categories: {list(self.policy_catalog.keys())}"
            }

        policy_key = policy_type.strip().upper()
        if policy_key not in self.policy_catalog:
            return {
                "compliant": False,
                "reason": f"Unknown policy category: {policy_type}. Valid categories: {list(self.policy_catalog.keys())}"
            }

        rules = self.policy_catalog[policy_key]
        violations = []

        if policy_key == "DATA_RETENTION":
            retention_days = _parse_number_param(parameters, "retention_days", 0, violations, as_int=True)
            if retention_days is not None:
                if retention_days < 0:
                    violations.append(f"Retention period ({retention_days} days) must be non-negative.")
                elif retention_days > rules["max_days"]:
                    violations.append(f"Retention period ({retention_days} days) exceeds maximum allowed ({rules['max_days']} days).")

            encrypted = _parse_bool_param(parameters, "encrypted", False, violations)
            if encrypted is False:
                violations.append("Data encryption at rest is mandatory under enterprise retention policy.")

        elif policy_key == "ACCESS_CONTROL":
            mfa_enabled = _parse_bool_param(parameters, "mfa_enabled", False, violations)
            if mfa_enabled is False:
                violations.append("Multi-Factor Authentication (MFA) must be enabled.")

        elif policy_key == "AI_MODEL_USAGE":
            approved_models = ["anthropic.claude-3-sonnet-20240229-v1:0", "amazon.titan-text-express-v1"]
            model_id = parameters.get("model_id", "")

            if model_id not in approved_models:
                violations.append(f"Model {model_id} is not on the enterprise approved list.")
            pii_filtering = _parse_bool_param(parameters, "pii_filtering_enabled", False, violations)
            if pii_filtering is False:
                violations.append("PII filtering guardrails must be enabled for all Generative AI usage.")

        elif policy_key == "INFRASTRUCTURE_SECURITY":
            allow_public_s3 = _parse_bool_param(parameters, "allow_public_s3", True, violations)
            if allow_public_s3 is True:
                violations.append("Public S3 bucket access is strictly prohibited under infrastructure security policy.")

            tls_version = _parse_number_param(parameters, "tls_version", 1.0, violations, as_int=False)
            if tls_version is not None and tls_version < rules["min_tls_version"]:
                violations.append(f"TLS version ({tls_version}) does not meet minimum requirement ({rules['min_tls_version']}).")

            use_vpc_endpoint = _parse_bool_param(parameters, "use_vpc_endpoint", False, violations)
            if rules["require_vpc_endpoints"] and use_vpc_endpoint is False:
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
        parameters = event.get("parameters") or []
        request_body = (
            ((event.get("requestBody") or {}).get("content") or {})
            .get("application/json") or {}
        ).get("properties") or []

        # Parse parameter list and body properties into key-value map with OpenAPI type coercion
        param_dict: Dict[str, Any] = {}
        for item in [*parameters, *request_body]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not name:
                continue
            param_dict[name] = _coerce_bedrock_value(item.get("value"), item.get("type"))

        policy_type = param_dict.get("policy_type") or "DATA_RETENTION"
        exception_id = param_dict.get("exception_id")
        result = self.evaluate_compliance(policy_type, param_dict, exception_id=exception_id)
        status_code = 400 if "reason" in result else 200

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
            "httpStatusCode": status_code,
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
