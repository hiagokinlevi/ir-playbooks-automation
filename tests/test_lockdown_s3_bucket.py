"""
Tests for automations/cloud/lockdown_s3_bucket.py.

The offline safety contract is the priority here: predictable dry-run previews,
rollback-state capture, public ACL detection, and graceful boto3 handling.
"""
from __future__ import annotations

import builtins
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from automations.cloud.lockdown_s3_bucket import (
    S3BucketLockdownResult,
    _bucket_region_from_location,
    _incident_tags,
    _is_public_acl,
    _public_access_block_config,
    lockdown_s3_bucket,
    restore_s3_bucket,
)


class FakeClientError(Exception):
    def __init__(self, code: str):
        self.response = {"Error": {"Code": code}}
        super().__init__(code)


class FakeS3Client:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get_bucket_location(self, Bucket: str) -> dict[str, str]:
        self.calls.append(("get_bucket_location", {"Bucket": Bucket}))
        return {"LocationConstraint": "us-west-2"}

    def get_public_access_block(self, Bucket: str) -> dict[str, object]:
        self.calls.append(("get_public_access_block", {"Bucket": Bucket}))
        raise FakeClientError("NoSuchPublicAccessBlockConfiguration")

    def get_bucket_policy(self, Bucket: str) -> dict[str, str]:
        self.calls.append(("get_bucket_policy", {"Bucket": Bucket}))
        return {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*"}]}'
        }

    def get_bucket_policy_status(self, Bucket: str) -> dict[str, dict[str, bool]]:
        self.calls.append(("get_bucket_policy_status", {"Bucket": Bucket}))
        return {"PolicyStatus": {"IsPublic": True}}

    def get_bucket_acl(self, Bucket: str) -> dict[str, object]:
        self.calls.append(("get_bucket_acl", {"Bucket": Bucket}))
        return {
            "Owner": {"DisplayName": "owner", "ID": "owner-id"},
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }
            ],
        }

    def get_bucket_tagging(self, Bucket: str) -> dict[str, list[dict[str, str]]]:
        self.calls.append(("get_bucket_tagging", {"Bucket": Bucket}))
        return {"TagSet": [{"Key": "team", "Value": "ir"}]}

    def put_public_access_block(
        self,
        Bucket: str,
        PublicAccessBlockConfiguration: dict[str, bool],
    ) -> None:
        self.calls.append(
            (
                "put_public_access_block",
                {
                    "Bucket": Bucket,
                    "PublicAccessBlockConfiguration": PublicAccessBlockConfiguration,
                },
            )
        )

    def delete_bucket_policy(self, Bucket: str) -> None:
        self.calls.append(("delete_bucket_policy", {"Bucket": Bucket}))

    def put_bucket_acl(self, Bucket: str, **kwargs: object) -> None:
        payload = {"Bucket": Bucket}
        payload.update(kwargs)
        self.calls.append(("put_bucket_acl", payload))

    def put_bucket_tagging(
        self,
        Bucket: str,
        Tagging: dict[str, list[dict[str, str]]],
    ) -> None:
        self.calls.append(("put_bucket_tagging", {"Bucket": Bucket, "Tagging": Tagging}))


class FakeSession:
    def __init__(self, client: FakeS3Client) -> None:
        self.client_instance = client
        self.requested_regions: list[str | None] = []

    def client(self, service_name: str, region_name: str | None = None) -> FakeS3Client:
        assert service_name == "s3"
        self.requested_regions.append(region_name)
        return self.client_instance


class TestHelpers:
    def test_public_access_block_config_enables_all_controls(self):
        assert _public_access_block_config() == {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

    def test_incident_tags_include_bucket_and_incident(self):
        tags = _incident_tags("INC-2026-060", "prod-exposure")
        assert tags["k1n-ir-incident-id"] == "INC-2026-060"
        assert tags["k1n-ir-bucket"] == "prod-exposure"
        assert tags["k1n-ir-action"] == "lockdown"

    def test_is_public_acl_detects_all_users_group(self):
        grants = [
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                }
            }
        ]
        assert _is_public_acl(grants) is True

    def test_is_public_acl_ignores_owner_only_grants(self):
        grants = [{"Grantee": {"Type": "CanonicalUser", "ID": "owner-id"}}]
        assert _is_public_acl(grants) is False

    def test_bucket_region_handles_legacy_values(self):
        assert _bucket_region_from_location(None) == "us-east-1"
        assert _bucket_region_from_location("EU") == "eu-west-1"


class TestDryRun:
    def test_lockdown_preview_is_successful(self):
        result = lockdown_s3_bucket(
            bucket_name="prod-exposure",
            incident_id="INC-2026-060",
            dry_run=True,
        )
        assert result.success is True
        assert result.dry_run is True
        assert result.errors == []
        assert result.completed_at is not None
        assert all(action.startswith("[DRY RUN]") for action in result.actions_taken)
        assert "rollback_command" in result.lockdown_state

    def test_restore_preview_mentions_policy_and_tags(self):
        result = restore_s3_bucket(
            bucket_name="prod-exposure",
            lockdown_state={
                "bucket_region": "us-west-2",
                "original_public_access_block": {"BlockPublicAcls": False},
                "original_bucket_policy": '{"Statement":[]}',
                "original_acl": {"Owner": {"ID": "owner"}, "Grants": []},
                "original_tags": [{"Key": "env", "Value": "prod"}],
            },
            dry_run=True,
        )
        text = " ".join(result.actions_taken)
        assert result.success is True
        assert "bucket policy" in text.lower()
        assert "bucket tags" in text.lower()


class TestLiveMode:
    def test_live_mode_applies_lockdown_controls(self, monkeypatch):
        fake_client = FakeS3Client()
        fake_session = FakeSession(fake_client)
        fake_boto3 = types.SimpleNamespace(Session=lambda **kwargs: fake_session)
        monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

        result = lockdown_s3_bucket(
            bucket_name="prod-exposure",
            incident_id="INC-2026-060",
            region="us-east-1",
            dry_run=False,
        )

        assert result.success is True
        assert result.region == "us-west-2"
        assert fake_session.requested_regions == ["us-east-1", "us-west-2"]

        operations = [name for name, _ in fake_client.calls]
        assert "put_public_access_block" in operations
        assert "delete_bucket_policy" in operations
        assert "put_bucket_acl" in operations
        assert "put_bucket_tagging" in operations

        tag_call = next(payload for name, payload in fake_client.calls if name == "put_bucket_tagging")
        tag_set = tag_call["Tagging"]["TagSet"]  # type: ignore[index]
        assert {"Key": "k1n-ir-incident-id", "Value": "INC-2026-060"} in tag_set
        assert result.lockdown_state["original_policy_was_public"] is True


class TestMissingBoto3:
    def test_live_mode_reports_missing_boto3(self, monkeypatch):
        real_import = builtins.__import__
        monkeypatch.delitem(sys.modules, "boto3", raising=False)

        def fake_import(name, *args, **kwargs):
            if name == "boto3":
                raise ImportError("simulated missing boto3")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        result = lockdown_s3_bucket(
            bucket_name="prod-exposure",
            incident_id="INC-2026-060",
            dry_run=False,
        )

        assert result.success is False
        assert result.completed_at is not None
        assert "boto3 not installed" in result.errors[0]


class TestResultDefaults:
    def test_dataclass_collections_are_independent(self):
        first = S3BucketLockdownResult(True, True, "a", "us-east-1", "INC-1")
        second = S3BucketLockdownResult(True, True, "b", "us-east-1", "INC-2")
        first.actions_taken.append("changed")
        first.lockdown_state["key"] = "value"
        first.errors.append("changed")

        assert second.actions_taken == []
        assert second.lockdown_state == {}
        assert second.errors == []
