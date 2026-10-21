"""Kernel-backed identity verification for approval service."""

import socket
import struct


def get_peer_credentials(connection):
    """Return PID, UID, and GID reported by the Linux kernel."""
    credentials = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize("3i"),
    )

    return struct.unpack("3i", credentials)


def require_authorized_peer(connection, *, authorized_uids):
    """Authorize a peer using its kernel-reported UID."""
    pid, uid, gid = get_peer_credentials(connection)

    if uid not in authorized_uids:
        raise PermissionError(
            f"Peer UID {uid} is not authorized"
        )

    return pid, uid, gid
