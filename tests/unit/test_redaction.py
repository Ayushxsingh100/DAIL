import unittest

from evidence.redaction import REDACTED, REDACTION_POLICY_VERSION, Redactor


class TestRedaction(unittest.TestCase):
    def setUp(self) -> None:
        self.r = Redactor()

    def test_secret_keys_are_redacted(self) -> None:
        res = self.r.redact({"password": "hunter2", "db": {"master_password": "x", "engine": "postgres"}})
        self.assertEqual(res.payload["password"], REDACTED)
        self.assertEqual(res.payload["db"]["master_password"], REDACTED)
        self.assertEqual(res.payload["db"]["engine"], "postgres")
        self.assertEqual(res.redaction_count, 2)

    def test_llm_usage_metadata_is_not_treated_as_a_secret(self) -> None:
        """Doc 11 Section 27 requires recording token usage."""
        payload = {"max_tokens": 1000, "token_count": 812, "input_tokens": 500, "tokens_used": 9}
        res = self.r.redact(payload)
        self.assertEqual(res.payload, payload)
        self.assertEqual(res.redaction_count, 0)

    def test_literal_token_key_is_redacted(self) -> None:
        self.assertEqual(self.r.redact({"token": "abc"}).payload["token"], REDACTED)
        self.assertEqual(self.r.redact({"access_token": "abc"}).payload["access_token"], REDACTED)

    def test_aws_access_key_id_in_string(self) -> None:
        res = self.r.redact({"note": "key is AKIAIOSFODNN7EXAMPLE ok"})
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", res.payload["note"])
        self.assertTrue(res.redacted)

    def test_terragoat_style_user_data_with_embedded_creds(self) -> None:
        """TerraGoat's aws_instance user_data embeds plaintext AWS credentials."""
        user_data = (
            "#!/bin/bash\n"
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "echo done\n"
        )
        res = self.r.redact({"user_data": user_data})
        out = res.payload["user_data"]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertNotIn("wJalrXUtnFEMI", out)
        self.assertIn("echo done", out)  # non-secret context preserved

    def test_private_key_block(self) -> None:
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
        out = self.r.redact({"blob": f"x {pem} y"}).payload["blob"]
        self.assertNotIn("MIIabc", out)

    def test_bearer_and_github_tokens(self) -> None:
        out = self.r.redact({"h": "Authorization: Bearer abc.def-123"}).payload["h"]
        self.assertNotIn("abc.def-123", out)
        gh = "ghp_" + "a" * 36
        self.assertNotIn(gh, self.r.redact({"x": gh}).payload["x"])

    def test_non_secret_terraform_content_is_preserved(self) -> None:
        payload = {"ingress": [{"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}], "vpc_id": "vpc-1"}
        self.assertEqual(self.r.redact(payload).payload, payload)

    def test_original_is_not_mutated(self) -> None:
        original = {"password": "hunter2"}
        self.r.redact(original)
        self.assertEqual(original["password"], "hunter2")

    def test_redaction_is_idempotent(self) -> None:
        once = self.r.redact({"password": "x", "s": "AKIAIOSFODNN7EXAMPLE"})
        twice = self.r.redact(once.payload)
        self.assertEqual(twice.redaction_count, 0)
        self.assertEqual(twice.payload, once.payload)

    def test_none_secret_value_is_not_counted(self) -> None:
        self.assertEqual(self.r.redact({"password": None}).redaction_count, 0)

    def test_policy_version_is_recorded(self) -> None:
        self.assertEqual(self.r.redact({"password": "x"}).policy_version, REDACTION_POLICY_VERSION)

    def test_contains_secret(self) -> None:
        self.assertTrue(self.r.contains_secret({"api_key": "k"}))
        self.assertFalse(self.r.contains_secret({"engine": "postgres"}))


if __name__ == "__main__":
    unittest.main()
