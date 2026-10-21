"""Tests for trusted approval-service identity."""

import os
import socket

from approval_service import get_peer_credentials


def test_peer_credentials_come_from_kernel():
    """Read OS-reported identity from a Unix socket."""
    client, server = socket.socketpair()

    try:
        credentials = get_peer_credentials(server)

        assert credentials == (
            os.getpid(),
            os.getuid(),
            os.getgid(),
        )
    finally:
        client.close()
        server.close()


def test_peer_credentials_identify_separate_process(tmp_path):
    """Verify kernel identity for a separate client process."""
    import subprocess
    import sys

    socket_path = tmp_path / "approval.sock"

    client_code = (
        "import socket, sys\n"
        "with socket.socket(socket.AF_UNIX) as s:\n"
        "    s.connect(sys.argv[1])\n"
        "    s.recv(1)\n"
    )

    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        listener.settimeout(5)

        client = subprocess.Popen(
            [sys.executable, "-c", client_code, str(socket_path)]
        )

        try:
            connection, _ = listener.accept()

            with connection:
                credentials = get_peer_credentials(connection)
                connection.sendall(b"x")

            assert client.wait(timeout=5) == 0

            assert credentials == (
                client.pid,
                os.getuid(),
                os.getgid(),
            )

            assert credentials[0] != os.getpid()

        finally:
            if client.poll() is None:
                client.terminate()
                client.wait(timeout=5)


def test_unauthorized_peer_is_denied():
    """Reject a peer whose UID is not authorized."""
    import pytest
    from approval_service import require_authorized_peer

    client, server = socket.socketpair()

    try:
        authorized_uids = frozenset({os.getuid() + 1})

        with pytest.raises(
            PermissionError, match="not authorized"
        ):
            require_authorized_peer(
                server,
                authorized_uids=authorized_uids,
            )
    finally:
        client.close()
        server.close()


def test_authorized_peer_is_accepted():
    """Accept a kernel UID explicitly allowed by server policy."""
    from approval_service import require_authorized_peer

    client, server = socket.socketpair()

    try:
        authorized_uids = frozenset({os.getuid()})

        credentials = require_authorized_peer(
            server,
            authorized_uids=authorized_uids,
        )

        assert credentials == (
            os.getpid(),
            os.getuid(),
            os.getgid(),
        )
    finally:
        client.close()
        server.close()
