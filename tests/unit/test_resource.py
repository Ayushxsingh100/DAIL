import unittest

from core.domain.enums import ChangeAction, IdentityOutcome
from core.domain.resource import Resource


class TestResourceValidation(unittest.TestCase):
    """Schema validation, per P1 exit criterion 'Domain schemas validate.'"""

    def test_valid_modified_resource(self) -> None:
        r = Resource(
            address="aws_security_group.web-node",
            action=ChangeAction.MODIFIED,
            before={"ingress": [{"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]},
            after={"ingress": []},
        )
        self.assertEqual(r.action, ChangeAction.MODIFIED)
        self.assertIsNone(r.identity)  # Identity Engine hasn't run yet

    def test_created_resource_must_have_no_before(self) -> None:
        with self.assertRaises(ValueError):
            Resource(
                address="aws_db_instance.default",
                action=ChangeAction.CREATED,
                before={"engine": "postgres"},  # illegal: created resources have no prior state
            )

    def test_deleted_resource_must_have_no_after(self) -> None:
        with self.assertRaises(ValueError):
            Resource(
                address="aws_instance.old",
                action=ChangeAction.DELETED,
                after={"instance_type": "t2.nano"},  # illegal: deleted resources have no resulting state
            )

    def test_unchanged_resource_before_after_must_match(self) -> None:
        with self.assertRaises(ValueError):
            Resource(
                address="aws_vpc.web_vpc",
                action=ChangeAction.UNCHANGED,
                before={"cidr_block": "172.16.0.0/16"},
                after={"cidr_block": "172.16.0.0/8"},  # contradicts UNCHANGED
            )

    def test_replace_paths_requires_replaced_action(self) -> None:
        with self.assertRaises(ValueError):
            Resource(
                address="aws_security_group_rule.ec2_to_rds",
                action=ChangeAction.MODIFIED,  # not REPLACED
                replace_paths=(("source_security_group_id",),),
            )

    def test_replaced_resource_with_replace_paths_is_valid(self) -> None:
        r = Resource(
            address="aws_security_group_rule.ec2_to_rds",
            action=ChangeAction.REPLACED,
            before={"source_security_group_id": "sg-0web-node", "cidr_blocks": None},
            after={"source_security_group_id": None, "cidr_blocks": ["10.99.0.0/16"]},
            replace_paths=(("cidr_blocks",),),
        )
        self.assertEqual(r.action, ChangeAction.REPLACED)

    def test_empty_address_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Resource(address="", action=ChangeAction.UNCHANGED)

    def test_resource_is_frozen(self) -> None:
        r = Resource(address="aws_vpc.web_vpc", action=ChangeAction.UNCHANGED)
        with self.assertRaises(Exception):
            r.address = "something-else"  # type: ignore[misc]


class TestResourceIdentity(unittest.TestCase):
    def test_with_identity_returns_new_copy(self) -> None:
        r = Resource(address="aws_security_group.web-node", action=ChangeAction.MODIFIED)
        r_with_identity = r.with_identity(IdentityOutcome.SAME)
        self.assertIsNone(r.identity)  # original untouched
        self.assertEqual(r_with_identity.identity, IdentityOutcome.SAME)
        self.assertEqual(r_with_identity.address, r.address)

    def test_uncertain_identity_is_representable(self) -> None:
        """Section IV-C: UNCERTAIN is the conservative default and must
        always be representable, never coerced to SAME or DIFFERENT."""
        r = Resource(address="aws_instance.web_host", action=ChangeAction.REPLACED)
        r2 = r.with_identity(IdentityOutcome.UNCERTAIN)
        self.assertEqual(r2.identity, IdentityOutcome.UNCERTAIN)


class TestResourceCanonicalDict(unittest.TestCase):
    def test_canonical_dict_is_json_serializable(self) -> None:
        import json

        r = Resource(
            address="aws_security_group.web-node",
            action=ChangeAction.REPLACED,
            replace_paths=(("name",), ("cidr_blocks", "0")),
        )
        d = r.canonical_dict()
        # Must not raise -- this is what core.domain.hashing will feed to json.dumps
        json.dumps(d)
        self.assertEqual(d["replace_paths"], [["name"], ["cidr_blocks", "0"]])


if __name__ == "__main__":
    unittest.main()
