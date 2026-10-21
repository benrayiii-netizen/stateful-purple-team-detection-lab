"""Protected reviewer authorization policy."""

from pathlib import Path


def load_authorized_uids(file_path):
    """Fail closed until protected policy loading is implemented."""
    path = Path(file_path)

    if not path.is_file():
        raise PermissionError(
            f"Reviewer policy missing or inaccessible: {path}"
        )

    if path.stat().st_uid != 0:
        raise PermissionError(
            f"Reviewer policy owner must be root: {path}"
        )

    raise PermissionError(
        "Reviewer policy validation is not implemented"
    )
