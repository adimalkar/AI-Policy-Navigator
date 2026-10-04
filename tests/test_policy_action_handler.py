import importlib
import unittest

policy_module = importlib.import_module("src.lambda.policy_action_handler")
PolicyActionHandler = policy_module.PolicyActionHandler


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


if __name__ == "__main__":
    unittest.main()
