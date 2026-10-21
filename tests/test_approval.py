"""Security tests for controlled analyst approval."""

from copy import deepcopy

import pytest

from response import create_triage_record
from approval import create_approval_record


def test_approval_requires_authenticated_reviewer():
    """Reject approval without trusted reviewer identity."""
    incident = {
        "source_ip": "192.168.139.128",
        "target_ip": "192.168.139.129",
        "trigger_sid": 1000001,
        "backdoor_sid": 1000002,
        "trigger_time": "2026-10-09T12:49:21-05:00",
        "backdoor_time": "2026-10-09T12:49:23-05:00",
    }

    triage_record = create_triage_record(
        incident,
        "Blue Team Analyst",
        "Recommend containment",
        "Correlated FTP trigger and backdoor alert",
    )

    original_record = deepcopy(triage_record)

    with pytest.raises(
        PermissionError,
        match="authenticated reviewer",
    ):
        create_approval_record(
            triage_record=triage_record,
            reviewer_context=None,
            decision="APPROVE",
            reason="Correlated evidence reviewed",
        )

    assert triage_record == original_record
    assert triage_record["approved"] is False
@pytest.mark.parametrize(
    "forged_context",
    [
        {"reviewer": "Blue Team Lead", "authenticated": True},
        {"reviewer_id": "lead-001", "permissions": ["approve"]},
        "Blue Team Lead",
    ],
)
def test_untrusted_reviewer_claims_are_rejected(forged_context):
    """Self-asserted identity must not grant approval."""
    triage_record = {
        "incident_id": "a" * 64,
        "status": "TRIAGED",
        "analyst": "Blue Team Analyst",
        "decision": "Recommend containment",
        "reason": "Evidence reviewed",
        "approved": False,
    }

    original_record = deepcopy(triage_record)

    with pytest.raises(PermissionError):
        create_approval_record(
            triage_record=triage_record,
            reviewer_context=forged_context,
            decision="APPROVE",
            reason="Evidence reviewed",
        )

    assert triage_record == original_record
    assert triage_record["approved"] is False
