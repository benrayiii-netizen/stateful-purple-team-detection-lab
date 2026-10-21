"""Controlled reviewer approval security boundary."""


def create_approval_record(
    *,
    triage_record,
    reviewer_context,
    decision,
    reason,
):
    """Reject approval until trusted authorization is implemented."""

    if reviewer_context is None:
        raise PermissionError(
            "Approval requires an authenticated reviewer"
        )

    raise PermissionError(
        "Approval unavailable: trusted reviewer authentication "
        "and authorization are not implemented"
    )
