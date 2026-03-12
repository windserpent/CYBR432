"""
message_protocol.py - Message Framing Protocol

Defines the structured message format for encrypted P2P messaging.
This module is transport- and crypto-agnostic -- it handles only
the packing and unpacking of message frames.

Message format (446 bytes total):
    Header: 192 bytes
        - version           (1 byte)
        - message_type      (1 byte)
        - timestamp         (8 bytes, uint64 big-endian, Unix epoch)
        - sender_id         (32 bytes, key fingerprint)
        - recipient_id      (32 bytes, key fingerprint)
        - sender_first_name (24 bytes, ASCII null-padded)
        - sender_last_name  (24 bytes, ASCII null-padded)
        - recipient_first_name (24 bytes, ASCII null-padded)
        - recipient_last_name  (24 bytes, ASCII null-padded)
        - sequence_number   (4 bytes, uint32 big-endian)
        - body_length       (2 bytes, uint16 big-endian)
        - reserved          (16 bytes, zero-padded)
    Body:   254 bytes (ASCII text, null-padded)

Author:  Kori Prins
"""

import struct
import time as _time
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


__all__ = [
    "PROTOCOL_VERSION",
    "HEADER_SIZE",
    "MAX_BODY_SIZE",
    "MAX_MESSAGE_SIZE",
    "NAME_FIELD_SIZE",
    "RESERVED_SIZE",
    "MessageType",
    "MessageHeader",
    "Message",
]

# Protocol constants
PROTOCOL_VERSION = 1
HEADER_SIZE = 192
MAX_BODY_SIZE = 254
MAX_MESSAGE_SIZE = HEADER_SIZE + MAX_BODY_SIZE   # 446 bytes
NAME_FIELD_SIZE = 24
RESERVED_SIZE = 16


class MessageType(IntEnum):
    """Message type identifiers."""
    TEXT = 0x01
    KEY_EXCHANGE = 0x02
    ACK = 0x03
    DISCONNECT = 0x04


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pack_name(name: str) -> bytes:
    """Encode a name string into a fixed-width null-padded field."""
    encoded = name.encode("ascii")
    if len(encoded) > NAME_FIELD_SIZE:
        raise ValueError(
            f"Name '{name}' exceeds {NAME_FIELD_SIZE}-byte limit "
            f"({len(encoded)} bytes)"
        )
    return encoded.ljust(NAME_FIELD_SIZE, b"\x00")


def _unpack_name(data: bytes) -> str:
    """Decode a null-padded name field back to a string."""
    return data.split(b"\x00", 1)[0].decode("ascii")


# ---------------------------------------------------------------------------
# Message header
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MessageHeader:
    """
    Fixed-size 192-byte message header.

    Layout (all multi-byte integers are big-endian):
        Offset  Size  Field
        ------  ----  -----
        0       1     version
        1       1     message_type
        2       8     timestamp (uint64, Unix epoch)
        10      32    sender_id (SHA-256 fingerprint of sender public key)
        42      32    recipient_id (SHA-256 fingerprint of recipient public key)
        74      24    sender_first_name (ASCII, null-padded)
        98      24    sender_last_name (ASCII, null-padded)
        122     24    recipient_first_name (ASCII, null-padded)
        146     24    recipient_last_name (ASCII, null-padded)
        170     4     sequence_number (uint32)
        174     2     body_length (uint16)
        176     16    reserved (zero-padded)
        ------  ----
        Total:  192 bytes
    """

    version: int
    message_type: MessageType
    timestamp: int
    sender_id: bytes
    recipient_id: bytes
    sender_first_name: str
    sender_last_name: str
    recipient_first_name: str
    recipient_last_name: str
    sequence_number: int
    body_length: int

    def pack(self) -> bytes:
        """Serialize the header into exactly 192 bytes."""
        buf = bytearray(HEADER_SIZE)

        buf[0] = self.version
        buf[1] = self.message_type

        struct.pack_into(">Q", buf, 2, self.timestamp)

        buf[10:42] = self.sender_id[:32]
        buf[42:74] = self.recipient_id[:32]

        buf[74:98] = _pack_name(self.sender_first_name)
        buf[98:122] = _pack_name(self.sender_last_name)
        buf[122:146] = _pack_name(self.recipient_first_name)
        buf[146:170] = _pack_name(self.recipient_last_name)

        struct.pack_into(">I", buf, 170, self.sequence_number)
        struct.pack_into(">H", buf, 174, self.body_length)

        # bytes 176-191 remain zero (reserved)
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> "MessageHeader":
        """Deserialize a 192-byte buffer into a MessageHeader."""
        if len(data) < HEADER_SIZE:
            raise ValueError(
                f"Header must be at least {HEADER_SIZE} bytes, "
                f"got {len(data)}"
            )

        version = data[0]
        message_type = MessageType(data[1])
        timestamp = struct.unpack_from(">Q", data, 2)[0]
        sender_id = bytes(data[10:42])
        recipient_id = bytes(data[42:74])
        sender_first_name = _unpack_name(data[74:98])
        sender_last_name = _unpack_name(data[98:122])
        recipient_first_name = _unpack_name(data[122:146])
        recipient_last_name = _unpack_name(data[146:170])
        sequence_number = struct.unpack_from(">I", data, 170)[0]
        body_length = struct.unpack_from(">H", data, 174)[0]

        return cls(
            version=version,
            message_type=message_type,
            timestamp=timestamp,
            sender_id=sender_id,
            recipient_id=recipient_id,
            sender_first_name=sender_first_name,
            sender_last_name=sender_last_name,
            recipient_first_name=recipient_first_name,
            recipient_last_name=recipient_last_name,
            sequence_number=sequence_number,
            body_length=body_length,
        )


# ---------------------------------------------------------------------------
# Complete message
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Message:
    """Complete message with header and body."""

    header: MessageHeader
    body: str

    def pack(self) -> bytes:
        """Serialize the full message into exactly 446 bytes."""
        header_bytes = self.header.pack()
        body_bytes = self.body.encode("ascii")
        padded_body = body_bytes.ljust(MAX_BODY_SIZE, b"\x00")
        return header_bytes + padded_body

    @classmethod
    def unpack(cls, data: bytes) -> "Message":
        """Deserialize a 446-byte buffer into a Message."""
        if len(data) != MAX_MESSAGE_SIZE:
            raise ValueError(
                f"Message must be exactly {MAX_MESSAGE_SIZE} bytes, "
                f"got {len(data)}"
            )

        header = MessageHeader.unpack(data[:HEADER_SIZE])
        body_raw = data[HEADER_SIZE : HEADER_SIZE + header.body_length]
        body = body_raw.decode("ascii")

        return cls(header=header, body=body)

    @staticmethod
    def create(
        body: str,
        message_type: MessageType,
        sender_id: bytes,
        recipient_id: bytes,
        sender_first_name: str,
        sender_last_name: str,
        recipient_first_name: str,
        recipient_last_name: str,
        sequence_number: int,
        timestamp: Optional[int] = None,
    ) -> "Message":
        """
        Build a Message with a fully populated header.

        Parameters
        ----------
        body : str
            ASCII message text, max 254 characters.
        message_type : MessageType
            Type of message being sent.
        sender_id : bytes
            32-byte sender identity (e.g. key fingerprint).
        recipient_id : bytes
            32-byte recipient identity (e.g. key fingerprint).
        sender_first_name / sender_last_name : str
            Sender's name fields, max 24 ASCII characters each.
        recipient_first_name / recipient_last_name : str
            Recipient's name fields, max 24 ASCII characters each.
        sequence_number : int
            Monotonically increasing message counter.
        timestamp : int, optional
            Unix epoch timestamp.  Defaults to current time.

        Returns
        -------
        Message
            A fully constructed message ready for use.
        """
        body_bytes = body.encode("ascii")
        if len(body_bytes) > MAX_BODY_SIZE:
            raise ValueError(
                f"Message body exceeds {MAX_BODY_SIZE}-character limit "
                f"({len(body_bytes)} bytes)"
            )

        if len(sender_id) != 32:
            raise ValueError(
                f"sender_id must be exactly 32 bytes, got {len(sender_id)}"
            )
        if len(recipient_id) != 32:
            raise ValueError(
                f"recipient_id must be exactly 32 bytes, "
                f"got {len(recipient_id)}"
            )

        for label, name in (
            ("sender_first_name", sender_first_name),
            ("sender_last_name", sender_last_name),
            ("recipient_first_name", recipient_first_name),
            ("recipient_last_name", recipient_last_name),
        ):
            encoded_name = name.encode("ascii")
            if len(encoded_name) > NAME_FIELD_SIZE:
                raise ValueError(
                    f"{label} '{name}' exceeds {NAME_FIELD_SIZE}-byte "
                    f"limit ({len(encoded_name)} bytes)"
                )

        if timestamp is None:
            timestamp = int(_time.time())

        header = MessageHeader(
            version=PROTOCOL_VERSION,
            message_type=message_type,
            timestamp=timestamp,
            sender_id=sender_id,
            recipient_id=recipient_id,
            sender_first_name=sender_first_name,
            sender_last_name=sender_last_name,
            recipient_first_name=recipient_first_name,
            recipient_last_name=recipient_last_name,
            sequence_number=sequence_number,
            body_length=len(body_bytes),
        )

        return Message(header=header, body=body)


# ---------------------------------------------------------------------------
# Self-test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import hashlib

    print("message_protocol.py - Self Test")
    print("=" * 60)

    # Synthetic 32-byte IDs for testing (no crypto dependency)
    alice_id = hashlib.sha256(b"alice_test_key").digest()
    bob_id = hashlib.sha256(b"bob_test_key").digest()

    # --- Header pack/unpack ---
    print("\n[1] Header pack/unpack ...")
    msg = Message.create(
        body="Hello Bob, this is a test message from Alice!",
        message_type=MessageType.TEXT,
        sender_id=alice_id,
        recipient_id=bob_id,
        sender_first_name="Alice",
        sender_last_name="Smith",
        recipient_first_name="Bob",
        recipient_last_name="Jones",
        sequence_number=1,
        timestamp=1700000000,
    )

    packed = msg.pack()
    assert len(packed) == MAX_MESSAGE_SIZE, (
        f"Packed size {len(packed)} != {MAX_MESSAGE_SIZE}"
    )

    unpacked = Message.unpack(packed)
    assert unpacked.body == msg.body
    assert unpacked.header.sender_first_name == "Alice"
    assert unpacked.header.sender_last_name == "Smith"
    assert unpacked.header.recipient_first_name == "Bob"
    assert unpacked.header.recipient_last_name == "Jones"
    assert unpacked.header.sequence_number == 1
    assert unpacked.header.message_type == MessageType.TEXT
    assert unpacked.header.version == PROTOCOL_VERSION
    assert unpacked.header.timestamp == 1700000000
    assert unpacked.header.sender_id == alice_id
    assert unpacked.header.recipient_id == bob_id
    print(f"    Header size:  {HEADER_SIZE} bytes")
    print(f"    Body size:    {MAX_BODY_SIZE} bytes")
    print(f"    Total packed: {len(packed)} bytes")
    print(f"    Body text:    {unpacked.body}")
    print(f"    Sender:       {unpacked.header.sender_first_name} "
          f"{unpacked.header.sender_last_name}")
    print(f"    Recipient:    {unpacked.header.recipient_first_name} "
          f"{unpacked.header.recipient_last_name}")

    # --- Max-length body ---
    print("\n[2] Max-length body test (254 characters) ...")
    max_body = "X" * MAX_BODY_SIZE
    max_msg = Message.create(
        body=max_body,
        message_type=MessageType.TEXT,
        sender_id=alice_id,
        recipient_id=bob_id,
        sender_first_name="Alice",
        sender_last_name="Smith",
        recipient_first_name="Bob",
        recipient_last_name="Jones",
        sequence_number=2,
    )
    packed_max = max_msg.pack()
    unpacked_max = Message.unpack(packed_max)
    assert unpacked_max.body == max_body
    assert len(unpacked_max.body) == MAX_BODY_SIZE
    print(f"    {MAX_BODY_SIZE}-character body packed and recovered")

    # --- Oversized body rejection ---
    print("\n[3] Oversized body rejection ...")
    try:
        Message.create(
            body="X" * (MAX_BODY_SIZE + 1),
            message_type=MessageType.TEXT,
            sender_id=alice_id,
            recipient_id=bob_id,
            sender_first_name="Alice",
            sender_last_name="Smith",
            recipient_first_name="Bob",
            recipient_last_name="Jones",
            sequence_number=3,
        )
        assert False, "SHOULD HAVE RAISED ValueError"
    except ValueError:
        print("    Correctly rejected 255-character body")

    # --- Oversized name rejection ---
    print("\n[4] Oversized name rejection ...")
    try:
        Message.create(
            body="test",
            message_type=MessageType.TEXT,
            sender_id=alice_id,
            recipient_id=bob_id,
            sender_first_name="A" * (NAME_FIELD_SIZE + 1),
            sender_last_name="Smith",
            recipient_first_name="Bob",
            recipient_last_name="Jones",
            sequence_number=4,
        )
        assert False, "SHOULD HAVE RAISED ValueError"
    except ValueError:
        print(f"    Correctly rejected name exceeding {NAME_FIELD_SIZE} bytes")

    # --- Invalid sender_id length rejection ---
    print("\n[5] Invalid ID length rejection ...")
    try:
        Message.create(
            body="test",
            message_type=MessageType.TEXT,
            sender_id=b"too_short",
            recipient_id=bob_id,
            sender_first_name="Alice",
            sender_last_name="Smith",
            recipient_first_name="Bob",
            recipient_last_name="Jones",
            sequence_number=5,
        )
        assert False, "SHOULD HAVE RAISED ValueError"
    except ValueError:
        print("    Correctly rejected non-32-byte sender_id")

    # --- All message types ---
    print("\n[6] All message types ...")
    for msg_type in MessageType:
        mt = Message.create(
            body=f"Type {msg_type.name} test",
            message_type=msg_type,
            sender_id=alice_id,
            recipient_id=bob_id,
            sender_first_name="Alice",
            sender_last_name="Smith",
            recipient_first_name="Bob",
            recipient_last_name="Jones",
            sequence_number=10 + msg_type.value,
        )
        packed_mt = mt.pack()
        unpacked_mt = Message.unpack(packed_mt)
        assert unpacked_mt.header.message_type == msg_type
        print(f"    {msg_type.name} (0x{msg_type.value:02x}): verified")

    # --- Empty body ---
    print("\n[7] Empty body test ...")
    empty_msg = Message.create(
        body="",
        message_type=MessageType.ACK,
        sender_id=alice_id,
        recipient_id=bob_id,
        sender_first_name="Alice",
        sender_last_name="Smith",
        recipient_first_name="Bob",
        recipient_last_name="Jones",
        sequence_number=99,
    )
    packed_empty = empty_msg.pack()
    unpacked_empty = Message.unpack(packed_empty)
    assert unpacked_empty.body == ""
    assert unpacked_empty.header.body_length == 0
    print("    Empty body packed and recovered")

    print("\n" + "=" * 60)
    print("All tests passed.")