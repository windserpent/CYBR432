"""
connection.py - TCP Connection Module

Handles peer-to-peer TCP communication with length-prefixed payloads.
This module is crypto- and protocol-agnostic -- it transports raw bytes
only.  The main application is responsible for serializing/deserializing
keys and message frames before passing them through this layer.

Wire format:
    Every transmission is a 4-byte big-endian length header followed by
    exactly that many bytes of payload.

Handshake order:
    The connecting side (client) sends its handshake payload first.
    The listening side (server) receives, then sends its own payload back.

Author:  Kori Prins
"""

import socket
import struct
from typing import Optional


__all__ = [
    "DEFAULT_PORT",
    "Connection",
]

# Protocol constants
DEFAULT_PORT = 8180
_LENGTH_PREFIX_SIZE = 4            # 4-byte big-endian uint32
_LENGTH_PREFIX_FMT = ">I"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _send_prefixed(sock: socket.socket, data: bytes) -> None:
    """Send a length-prefixed payload over the socket."""
    header = struct.pack(_LENGTH_PREFIX_FMT, len(data))
    sock.sendall(header + data)


def _recv_prefixed(sock: socket.socket) -> bytes:
    """Receive a length-prefixed payload from the socket."""
    header = _recv_exact(sock, _LENGTH_PREFIX_SIZE)
    length = struct.unpack(_LENGTH_PREFIX_FMT, header)[0]
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly *num_bytes* from the socket."""
    chunks = []
    remaining = num_bytes
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError(
                f"Connection closed while expecting {remaining} more bytes"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Connection class
# ---------------------------------------------------------------------------

class Connection:
    """
    Single-use TCP connection with length-prefixed transport.

    Provides two entry points for establishing a connection:
        - start_listener() -- wait for an incoming peer (server role)
        - connect_to()     -- connect to a remote peer (client role)

    After the connection is established (with handshake exchange),
    use send() and recv() to exchange payloads, then close().
    """

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None
        self._server_sock: Optional[socket.socket] = None
        self._peer_address: Optional[tuple] = None

    # ----- connection establishment -----

    def start_listener(
        self,
        port: int,
        handshake_payload: bytes,
    ) -> bytes:
        """
        Listen for one incoming connection and perform the handshake.

        Binds to all interfaces on the specified port, accepts a single
        connection, receives the peer's handshake payload, then sends
        ours back.

        Parameters
        ----------
        port : int
            TCP port to listen on.
        handshake_payload : bytes
            Our payload to send to the peer (e.g. serialized public key).

        Returns
        -------
        bytes
            The peer's handshake payload.
        """
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("", port))
        self._server_sock.listen(1)

        self._sock, self._peer_address = self._server_sock.accept()

        # Handshake: client sends first, then we respond
        peer_payload = _recv_prefixed(self._sock)
        _send_prefixed(self._sock, handshake_payload)

        return peer_payload

    def connect_to(
        self,
        ip: str,
        port: int,
        handshake_payload: bytes,
    ) -> bytes:
        """
        Connect to a remote peer and perform the handshake.

        Establishes a TCP connection, sends our handshake payload,
        then receives the peer's payload back.

        Parameters
        ----------
        ip : str
            IP address of the remote peer.
        port : int
            TCP port of the remote peer.
        handshake_payload : bytes
            Our payload to send to the peer (e.g. serialized public key).

        Returns
        -------
        bytes
            The peer's handshake payload.
        """
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((ip, port))
        self._peer_address = (ip, port)

        # Handshake: client sends first, then receives
        _send_prefixed(self._sock, handshake_payload)
        peer_payload = _recv_prefixed(self._sock)

        return peer_payload

    # ----- data transport -----

    def send(self, data: bytes) -> None:
        """
        Send a length-prefixed payload to the connected peer.

        Parameters
        ----------
        data : bytes
            Raw bytes to send.
        """
        if self._sock is None:
            raise ConnectionError("No active connection")
        _send_prefixed(self._sock, data)

    def recv(self) -> bytes:
        """
        Receive a length-prefixed payload from the connected peer.

        Returns
        -------
        bytes
            The received payload.
        """
        if self._sock is None:
            raise ConnectionError("No active connection")
        return _recv_prefixed(self._sock)

    # ----- teardown -----

    def close(self) -> None:
        """Close the connection and release all sockets."""
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        if self._server_sock is not None:
            self._server_sock.close()
            self._server_sock = None
        self._peer_address = None

    @property
    def peer_address(self) -> Optional[tuple]:
        """IP address and port of the connected peer, or None."""
        return self._peer_address


# ---------------------------------------------------------------------------
# Self-test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import threading
    import time

    print("connection.py - Self Test")
    print("=" * 60)

    TEST_PORT = 18180          # high port to avoid conflicts

    # --- Handshake and round-trip ---
    print("\n[1] Handshake and data round-trip ...")

    server_payload = b"SERVER_HANDSHAKE_DATA_here_is_a_public_key"
    client_payload = b"CLIENT_HANDSHAKE_DATA_here_is_a_public_key"
    test_message = b"Hello from the client!"
    test_reply = b"Hello from the server!"

    server_received_handshake = None
    server_received_message = None

    def run_server():
        global server_received_handshake, server_received_message
        server = Connection()
        server_received_handshake = server.start_listener(
            TEST_PORT, server_payload,
        )
        server_received_message = server.recv()
        server.send(test_reply)
        server.close()

    server_thread = threading.Thread(target=run_server)
    server_thread.start()
    time.sleep(0.1)            # let the listener bind

    client = Connection()
    client_received_handshake = client.connect_to(
        "127.0.0.1", TEST_PORT, client_payload,
    )

    # Verify handshake exchange
    assert client_received_handshake == server_payload, (
        "Client did not receive server handshake"
    )
    print("    Client received server handshake: verified")

    # Send a message and get a reply
    client.send(test_message)
    client_received_reply = client.recv()
    client.close()

    server_thread.join()

    assert server_received_handshake == client_payload, (
        "Server did not receive client handshake"
    )
    print("    Server received client handshake: verified")

    assert server_received_message == test_message, (
        "Server did not receive client message"
    )
    print(f"    Server received message: {server_received_message}")

    assert client_received_reply == test_reply, (
        "Client did not receive server reply"
    )
    print(f"    Client received reply:   {client_received_reply}")

    # --- Large payload ---
    print("\n[2] Large payload test ...")

    large_data = bytes(range(256)) * 4000       # ~1 MB

    def run_server_large():
        server = Connection()
        payload = server.start_listener(TEST_PORT, b"server")
        received = server.recv()
        server.send(received)                   # echo back
        server.close()

    server_thread = threading.Thread(target=run_server_large)
    server_thread.start()
    time.sleep(0.1)

    client = Connection()
    client.connect_to("127.0.0.1", TEST_PORT, b"client")
    client.send(large_data)
    echoed = client.recv()
    client.close()
    server_thread.join()

    assert echoed == large_data, "Large payload echo mismatch"
    print(f"    Sent and echoed {len(large_data):,} bytes successfully")

    # --- Empty payload ---
    print("\n[3] Empty payload test ...")

    def run_server_empty():
        server = Connection()
        server.start_listener(TEST_PORT, b"server")
        received = server.recv()
        server.send(received)
        server.close()

    server_thread = threading.Thread(target=run_server_empty)
    server_thread.start()
    time.sleep(0.1)

    client = Connection()
    client.connect_to("127.0.0.1", TEST_PORT, b"client")
    client.send(b"")
    echoed_empty = client.recv()
    client.close()
    server_thread.join()

    assert echoed_empty == b"", "Empty payload echo mismatch"
    print("    Empty payload sent and echoed successfully")

    # --- Peer address ---
    print("\n[4] Peer address tracking ...")

    def run_server_addr():
        server = Connection()
        server.start_listener(TEST_PORT, b"s")
        assert server.peer_address is not None, "Server has no peer address"
        print(f"    Server sees peer: {server.peer_address}")
        server.close()
        assert server.peer_address is None, "Peer address not cleared"
        print("    After close: peer_address is None")

    server_thread = threading.Thread(target=run_server_addr)
    server_thread.start()
    time.sleep(0.1)

    client = Connection()
    client.connect_to("127.0.0.1", TEST_PORT, b"c")
    assert client.peer_address == ("127.0.0.1", TEST_PORT), (
        "Client peer address incorrect"
    )
    print(f"    Client sees peer: {client.peer_address}")
    client.close()
    server_thread.join()

    # --- Connection error on unconnected socket ---
    print("\n[5] Error on unconnected send/recv ...")

    orphan = Connection()
    try:
        orphan.send(b"should fail")
        assert False, "SHOULD HAVE RAISED ConnectionError"
    except ConnectionError:
        print("    send() on unconnected socket: correctly raised")

    try:
        orphan.recv()
        assert False, "SHOULD HAVE RAISED ConnectionError"
    except ConnectionError:
        print("    recv() on unconnected socket: correctly raised")

    print("\n" + "=" * 60)
    print("All tests passed.")