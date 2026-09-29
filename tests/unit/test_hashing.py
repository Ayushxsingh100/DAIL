import unittest

from core.domain.hashing import canonical_json, content_hash, verify_content_hash


class TestCanonicalHashStability(unittest.TestCase):
    """P1 exit criterion: 'Canonical hashes are stable.'"""

    def test_dict_key_order_does_not_affect_hash(self) -> None:
        payload_a = {"address": "aws_vpc.web_vpc", "action": "CREATED", "before": None}
        payload_b = {"before": None, "action": "CREATED", "address": "aws_vpc.web_vpc"}
        self.assertEqual(content_hash(payload_a), content_hash(payload_b))

    def test_nested_dict_key_order_does_not_affect_hash(self) -> None:
        payload_a = {"outer": {"a": 1, "b": 2}, "list": [1, 2, 3]}
        payload_b = {"list": [1, 2, 3], "outer": {"b": 2, "a": 1}}
        self.assertEqual(content_hash(payload_a), content_hash(payload_b))

    def test_different_content_produces_different_hash(self) -> None:
        h1 = content_hash({"cidr_blocks": ["0.0.0.0/0"]})
        h2 = content_hash({"cidr_blocks": ["10.99.0.0/16"]})
        self.assertNotEqual(h1, h2)

    def test_hash_is_deterministic_across_calls(self) -> None:
        payload = {"a": [1, {"nested": True}], "b": "x"}
        hashes = {content_hash(payload) for _ in range(20)}
        self.assertEqual(len(hashes), 1, "same payload must hash identically every time")

    def test_hash_is_a_valid_sha256_hex_digest(self) -> None:
        h = content_hash({"anything": "here"})
        self.assertEqual(len(h), 64)
        int(h, 16)  # must not raise -- confirms it's valid hex

    def test_verify_content_hash_true_for_matching_payload(self) -> None:
        payload = {"foo": "bar"}
        h = content_hash(payload)
        self.assertTrue(verify_content_hash(payload, h))

    def test_verify_content_hash_false_for_tampered_payload(self) -> None:
        payload = {"foo": "bar"}
        h = content_hash(payload)
        tampered = {"foo": "baz"}
        self.assertFalse(verify_content_hash(tampered, h))

    def test_canonical_json_has_no_whitespace(self) -> None:
        s = canonical_json({"a": 1, "b": [1, 2]})
        self.assertNotIn(" ", s)


if __name__ == "__main__":
    unittest.main()
