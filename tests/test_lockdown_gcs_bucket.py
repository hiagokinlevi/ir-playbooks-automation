"""
Tests for automations/cloud/lockdown_gcs_bucket.py.

The offline safety contract is the priority here: deterministic dry-run
previews, reversible state capture, public-member stripping, and graceful
google-cloud-storage handling.
"""
from __future__ import annotations

import builtins
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from automations.cloud.lockdown_gcs_bucket import (
    GcsBucketLockdownResult,
    _incident_labels,
    _policy_has_public_members,
    _remove_public_members,
    lockdown_gcs_bucket,
    restore_gcs_bucket,
)


class FakeIamConfiguration:
    def __init__(self) -> None:
        self.public_access_prevention = "inherited"
        self.uniform_bucket_level_access_enabled = False


class FakeBucket:
    def __init__(self) -> None:
        self.labels = {"team": "ir"}
        self.iam_configuration = FakeIamConfiguration()
        self.policy = {
            "version": 3,
            "bindings": [
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers", "group:blue@example.com"],
                },
                {
                    "role": "roles/storage.objectAdmin",
                    "members": ["user:owner@example.com", "allAuthenticatedUsers"],
                },
            ],
        }
        self.calls: list[tuple[str, object]] = []

    def reload(self) -> None:
        self.calls.append(("reload", None))

    def get_iam_policy(self, requested_policy_version: int = 3) -> dict[str, object]:
        self.calls.append(("get_iam_policy", requested_policy_version))
        return {
            "version": self.policy["version"],
            "bindings": [
                {
                    "role": binding["role"],
                    "members": list(binding["members"]),
                }
                for binding in self.policy["bindings"]
            ],
        }

    def set_iam_policy(self, policy: dict[str, object]) -> None:
        self.calls.append(("set_iam_policy", policy))
        self.policy = policy

    def patch(self) -> None:
        self.calls.append(("patch", None))


class FakeClient:
    def __init__(self, bucket: FakeBucket, project: str = "blue-project") -> None:
        self.bucket_instance = bucket
        self.project = project
        self.requested_buckets: list[str] = []

    def bucket(self, bucket_name: str) -> FakeBucket:
        self.requested_buckets.append(bucket_name)
        return self.bucket_instance


class TestHelpers:
    def test_incident_labels_are_traceable(self):
        labels = _incident_labels("INC-2026-061", "prod-exposure")
        assert labels["k1n-ir-incident-id"] == "inc-2026-061"
        assert labels["k1n-ir-action"] == "lockdown"
        assert labels["k1n-ir-bucket"] == "prod-exposure"

    def test_policy_has_public_members(self):
        assert _policy_has_public_members(
            {
                "bindings": [
                    {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                ]
            }
        ) is True

    def test_remove_public_members_preserves_private_bindings(self):
        policy, removed = _remove_public_members(
            {
                "version": 3,
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers", "group:blue@example.com"],
                    },
                    {
                        "role": "roles/storage.objectAdmin",
                        "members": ["allAuthenticatedUsers"],
                    },
                ],
            }
        )

        assert removed == ["allAuthenticatedUsers", "allUsers"]
        assert policy["bindings"] == [
            {
                "role": "roles/storage.objectViewer",
                "members": ["group:blue@example.com"],
            }
        ]


class TestDryRun:
    def test_lockdown_preview_is_successful(self):
        result = lockdown_gcs_bucket(
            bucket_name="prod-exposure",
            incident_id="INC-2026-061",
            project_id="blue-project",
            dry_run=True,
        )

        assert result.success is True
        assert result.dry_run is True
        assert result.errors == []
        assert result.completed_at is not None
        assert all(action.startswith("[DRY RUN]") for action in result.actions_taken)
        assert "rollback_command" in result.lockdown_state

    def test_restore_preview_mentions_policy_and_labels(self):
        result = restore_gcs_bucket(
            bucket_name="prod-exposure",
            lockdown_state={
                "project_id": "blue-project",
                "original_public_access_prevention": "inherited",
                "original_uniform_bucket_level_access_enabled": False,
                "original_labels": {"team": "ir"},
                "original_iam_policy": {"version": 3, "bindings": []},
            },
            dry_run=True,
        )

        text = " ".join(result.actions_taken)
        assert result.success is True
        assert "labels" in text.lower()
        assert "iam policy" in text.lower()


class TestLiveMode:
    def test_live_mode_enforces_bucket_hardening(self, monkeypatch):
        fake_bucket = FakeBucket()
        fake_client = FakeClient(fake_bucket)
        fake_storage = types.SimpleNamespace(Client=lambda project=None: fake_client)
        monkeypatch.setitem(sys.modules, "google.cloud.storage", fake_storage)

        google_module = types.ModuleType("google")
        cloud_module = types.ModuleType("google.cloud")
        cloud_module.storage = fake_storage
        google_module.cloud = cloud_module
        monkeypatch.setitem(sys.modules, "google", google_module)
        monkeypatch.setitem(sys.modules, "google.cloud", cloud_module)

        result = lockdown_gcs_bucket(
            bucket_name="prod-exposure",
            incident_id="INC-2026-061",
            project_id="blue-project",
            dry_run=False,
        )

        assert result.success is True
        assert result.project_id == "blue-project"
        assert fake_bucket.iam_configuration.public_access_prevention == "enforced"
        assert fake_bucket.iam_configuration.uniform_bucket_level_access_enabled is True
        assert fake_bucket.labels["k1n-ir-incident-id"] == "inc-2026-061"
        assert any(name == "set_iam_policy" for name, _ in fake_bucket.calls)
        assert any(name == "patch" for name, _ in fake_bucket.calls)
        assert _policy_has_public_members(fake_bucket.policy) is False
        assert result.lockdown_state["original_labels"] == {"team": "ir"}


class TestMissingSdk:
    def test_live_mode_reports_missing_google_storage_sdk(self, monkeypatch):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("google"):
                raise ImportError(f"simulated missing sdk: {name}")
            return real_import(name, *args, **kwargs)

        monkeypatch.delitem(sys.modules, "google", raising=False)
        monkeypatch.delitem(sys.modules, "google.cloud", raising=False)
        monkeypatch.delitem(sys.modules, "google.cloud.storage", raising=False)
        monkeypatch.setattr(builtins, "__import__", fake_import)

        result = lockdown_gcs_bucket(
            bucket_name="prod-exposure",
            incident_id="INC-2026-061",
            dry_run=False,
        )

        assert result.success is False
        assert result.completed_at is not None
        assert "google-cloud-storage not installed" in result.errors[0]


class TestResultDefaults:
    def test_dataclass_collections_are_independent(self):
        first = GcsBucketLockdownResult(True, True, "a", "blue", "INC-1")
        second = GcsBucketLockdownResult(True, True, "b", "blue", "INC-2")
        first.actions_taken.append("changed")
        first.lockdown_state["a"] = "changed"
        first.errors.append("changed")

        assert second.actions_taken == []
        assert second.lockdown_state == {}
        assert second.errors == []
