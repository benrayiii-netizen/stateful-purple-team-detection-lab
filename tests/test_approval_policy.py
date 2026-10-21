"""Security tests for protected reviewer policy."""

import pytest

from approval_policy import load_authorized_uids


def test_missing_policy_fails_closed(tmp_path):
    """Never authorize reviewers when policy is missing."""
    missing_policy = tmp_path / "reviewers.json"

    with pytest.raises(
        PermissionError, match="policy"
    ):
        load_authorized_uids(missing_policy)


def test_user_owned_policy_is_rejected(tmp_path):
    """Reject policy controlled by an untrusted user."""
    import json
    import os

    if os.geteuid() == 0:
        pytest.skip("Requires non-root test runner")

    policy = tmp_path / "reviewers.json"

    policy.write_text(
        json.dumps({
            "authorized_uids": [os.getuid()]
        }),
        encoding="utf-8",
    )

    policy.chmod(0o600)

    with pytest.raises(
        PermissionError, match="owner"
    ):
        load_authorized_uids(policy)
