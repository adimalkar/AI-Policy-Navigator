import importlib
import json
import unittest

policy_module = importlib.import_module("src.lambda.policy_action_handler")
PolicyActionHandler = policy_module.PolicyActionHandler
lambda_handler = policy_module.lambda_handler


class TestPolicyActionHandler(unittest.TestCase):
    def setUp(self):
        self.handler = PolicyActionHandler()

    def test_data_retention_compliance(self):
        # Compliant payload
        res = self.handler.evaluate_compliance("DATA_RETENTION", {"retention_days": 60, "encrypted": True})
        self.assertTrue(res["compliant"])
        self.assertEqual(res["status"], "APPROVED")

        # Non-compliant payload (days exceed 90, unencrypted)
        res_fail = self.handler.evaluate_compliance("DATA_RETENTION", {"retention_days": 180, "encrypted": False})
        self.assertFalse(res_fail["compliant"])
        self.assertEqual(res_fail["status"], "REJECTED")
        self.assertEqual(len(res_fail["violations"]), 2)

    def test_exception_handling(self):
        # Register exception for legacy system
        self.handler.register_exception(
            policy_type="DATA_RETENTION",
            exception_id="EXC-2026-001",
            justification="Legacy archival DB migration in flight",
            approved_by="Security Governance Lead"
        )

        # Evaluate with exception
        res = self.handler.evaluate_compliance(
            "DATA_RETENTION",
            {"retention_days": 365, "encrypted": False},
            exception_id="EXC-2026-001"
        )
        self.assertTrue(res["compliant"])
        self.assertEqual(res["status"], "APPROVED_WITH_EXCEPTION")
        self.assertTrue(res["has_exception"])
        self.assertIn("EXC-2026-001", res["exception_note"])

    def test_multi_policy_audit(self):
        audit_payload = {
            "ACCESS_CONTROL": {"mfa_enabled": True},
            "INFRASTRUCTURE_SECURITY": {"allow_public_s3": False, "tls_version": 1.3, "use_vpc_endpoint": True},
            "AI_MODEL_USAGE": {"model_id": "unapproved-gpt-model", "pii_filtering_enabled": False}
        }
        report = self.handler.evaluate_multi_policy_audit(audit_payload)
        self.assertEqual(report["total_domains_audited"], 3)
        self.assertEqual(report["compliant_domains"], 2)
        self.assertAlmostEqual(report["compliance_score_pct"], 66.7, places=1)
        self.assertEqual(report["overall_status"], "ACTION_REQUIRED")
        self.assertGreaterEqual(report["total_violations"], 2)

    def test_bedrock_event_stringified_parameters_rejected_properly(self):
        # Stringified "false" and "180" must not be treated as truthy or raise TypeError
        event = {
            "actionGroup": "PolicyActions",
            "apiPath": "/evaluate",
            "httpMethod": "POST",
            "parameters": [
                {"name": "policy_type", "type": "string", "value": "DATA_RETENTION"},
                {"name": "retention_days", "type": "integer", "value": "180"},
                {"name": "encrypted", "type": "boolean", "value": "false"},
            ],
            "requestBody": None,
        }
        response = self.handler.handle_bedrock_event(event)
        action_resp = response["response"]
        self.assertEqual(action_resp["httpStatusCode"], 200)
        body = json.loads(action_resp["responseBody"]["application/json"]["body"])
        self.assertFalse(body["compliant"])
        self.assertEqual(body["status"], "REJECTED")
        self.assertEqual(len(body["violations"]), 2)

    def test_bedrock_event_infrastructure_and_exception_forwarding(self):
        self.handler.register_exception(
            policy_type="INFRASTRUCTURE_SECURITY",
            exception_id="EXC-INFRA-42",
            justification="Temporary sandbox test",
            approved_by="Cloud Security",
        )
        event = {
            "actionGroup": "PolicyActions",
            "apiPath": "/evaluate",
            "httpMethod": "POST",
            "parameters": None,
            "requestBody": {
                "content": {
                    "application/json": {
                        "properties": [
                            {"name": "policy_type", "type": "string", "value": "INFRASTRUCTURE_SECURITY"},
                            {"name": "allow_public_s3", "type": "boolean", "value": "false"},
                            {"name": "tls_version", "type": "number", "value": "1.1"},
                            {"name": "use_vpc_endpoint", "type": "boolean", "value": "false"},
                            {"name": "exception_id", "type": "string", "value": "EXC-INFRA-42"},
                        ]
                    }
                }
            },
        }
        response = self.handler.handle_bedrock_event(event)
        action_resp = response["response"]
        self.assertEqual(action_resp["httpStatusCode"], 200)
        body = json.loads(action_resp["responseBody"]["application/json"]["body"])
        self.assertTrue(body["compliant"])
        self.assertEqual(body["status"], "APPROVED_WITH_EXCEPTION")
        self.assertTrue(body["has_exception"])
        self.assertEqual(len(body["violations"]), 2)

    def test_bedrock_event_unknown_policy_returns_400(self):
        event = {
            "actionGroup": "PolicyActions",
            "apiPath": "/evaluate",
            "httpMethod": "POST",
            "parameters": [
                {"name": "policy_type", "type": "string", "value": "NON_EXISTENT_POLICY"},
                {"name": None, "type": "string", "value": "ignored"},
            ],
        }
        response = self.handler.handle_bedrock_event(event)
        self.assertEqual(response["response"]["httpStatusCode"], 400)
        body = json.loads(response["response"]["responseBody"]["application/json"]["body"])
        self.assertFalse(body["compliant"])
        self.assertIn("Unknown policy category", body["reason"])

    def test_stringified_false_booleans_and_invalid_values_handled_safely(self):
        # ACCESS_CONTROL with string "false" must fail MFA check
        res_mfa = self.handler.evaluate_compliance("ACCESS_CONTROL", {"mfa_enabled": "false"})
        self.assertFalse(res_mfa["compliant"])
        self.assertEqual(res_mfa["status"], "REJECTED")

        # AI_MODEL_USAGE with string "false" must fail PII guardrail check
        res_ai = self.handler.evaluate_compliance(
            "AI_MODEL_USAGE",
            {"model_id": "anthropic.claude-3-sonnet-20240229-v1:0", "pii_filtering_enabled": "false"},
        )
        self.assertFalse(res_ai["compliant"])
        self.assertEqual(len(res_ai["violations"]), 1)

        # Invalid numeric/boolean values produce structured violations instead of crashing
        res_invalid_retention = self.handler.evaluate_compliance(
            "DATA_RETENTION",
            {"retention_days": "not-an-int", "encrypted": "maybe"},
        )
        self.assertFalse(res_invalid_retention["compliant"])
        self.assertEqual(len(res_invalid_retention["violations"]), 2)

        res_negative_retention = self.handler.evaluate_compliance(
            "DATA_RETENTION",
            {"retention_days": -10, "encrypted": True},
        )
        self.assertFalse(res_negative_retention["compliant"])
        self.assertEqual(len(res_negative_retention["violations"]), 1)

        res_invalid_tls = self.handler.evaluate_compliance(
            "INFRASTRUCTURE_SECURITY",
            {"allow_public_s3": "false", "tls_version": "nan", "use_vpc_endpoint": "true"},
        )
        self.assertFalse(res_invalid_tls["compliant"])
        self.assertEqual(len(res_invalid_tls["violations"]), 1)

    def test_lambda_handler_entrypoint(self):
        event = {
            "actionGroup": "PolicyActions",
            "apiPath": "/evaluate",
            "httpMethod": "POST",
            "parameters": [
                {"name": "policy_type", "type": "string", "value": "access_control"},
                {"name": "mfa_enabled", "type": "boolean", "value": "true"},
            ],
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["messageVersion"], "1.0")
        body = json.loads(response["response"]["responseBody"]["application/json"]["body"])
        self.assertTrue(body["compliant"])
        self.assertEqual(body["status"], "APPROVED")


if __name__ == "__main__":
    unittest.main()
