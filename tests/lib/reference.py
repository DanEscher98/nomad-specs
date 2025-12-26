"""
NOMAD Protocol Reference Codec

This module provides a Python reference implementation of the NOMAD protocol
encoding/decoding logic. It is used by conformance tests to validate
implementations against the canonical encoding.

The reference codec is the SOURCE OF TRUTH for wire format correctness.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from nacl.bindings import crypto_scalarmult_base
from nacl.hash import blake2b

# =============================================================================
# Protocol Constants (from PROTOCOL.md)
# =============================================================================

PROTOCOL_VERSION = 0x0001
NOMAD_VERSION = "1.0.0"

# Frame types
FRAME_HANDSHAKE_INIT = 0x01
FRAME_HANDSHAKE_RESP = 0x02
FRAME_DATA = 0x03
FRAME_REKEY = 0x04
FRAME_CLOSE = 0x05

# Flags
FLAG_ACK_ONLY = 0x01
FLAG_HAS_EXTENSION = 0x02

# Sizes
SESSION_ID_SIZE = 6
AEAD_TAG_SIZE = 16
AEAD_NONCE_SIZE = 24  # XChaCha20 nonce
PUBLIC_KEY_SIZE = 32
PRIVATE_KEY_SIZE = 32

# Frame header size (used as AAD)
DATA_FRAME_HEADER_SIZE = 16

# Sync message header size (before diff payload)
SYNC_MESSAGE_HEADER_SIZE = 28  # 3 * uint64 + uint32


# =============================================================================
# Data Classes for Parsed Messages
# =============================================================================


@dataclass
class DataFrameHeader:
    """Parsed data frame header (16 bytes, used as AAD)."""

    frame_type: int
    flags: int
    session_id: bytes
    nonce_counter: int

    def __post_init__(self) -> None:
        if len(self.session_id) != SESSION_ID_SIZE:
            raise ValueError(f"Session ID must be {SESSION_ID_SIZE} bytes")


@dataclass
class SyncMessage:
    """Parsed sync message."""

    sender_state_num: int
    acked_state_num: int
    base_state_num: int
    diff: bytes


@dataclass
class PayloadHeader:
    """Parsed encrypted payload header."""

    timestamp: int  # ms since session start
    timestamp_echo: int  # echo of peer's timestamp
    payload_length: int


@dataclass
class DataFrame:
    """Complete parsed data frame."""

    header: DataFrameHeader
    payload_header: PayloadHeader
    sync_message: SyncMessage


@dataclass
class NonceComponents:
    """Components of a 24-byte XChaCha20 nonce."""

    epoch: int
    direction: int  # 0 = initiator->responder, 1 = responder->initiator
    counter: int


# =============================================================================
# XChaCha20-Poly1305 Implementation
# =============================================================================


def hchacha20(key: bytes, nonce: bytes) -> bytes:
    """HChaCha20 - derives subkey from first 16 bytes of nonce.

    This is the key derivation step that makes XChaCha20 work.
    """
    assert len(key) == 32, f"Key must be 32 bytes, got {len(key)}"
    assert len(nonce) >= 16, f"Nonce must be at least 16 bytes, got {len(nonce)}"

    # HChaCha20 constants
    constants = b"expand 32-byte k"

    # Build initial state
    state = list(struct.unpack("<16I", constants + key + nonce[:16]))

    # 20 rounds (10 double-rounds)
    def quarter_round(a: int, b: int, c: int, d: int) -> None:
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF

        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF

    for _ in range(10):
        # Column rounds
        quarter_round(0, 4, 8, 12)
        quarter_round(1, 5, 9, 13)
        quarter_round(2, 6, 10, 14)
        quarter_round(3, 7, 11, 15)
        # Diagonal rounds
        quarter_round(0, 5, 10, 15)
        quarter_round(1, 6, 11, 12)
        quarter_round(2, 7, 8, 13)
        quarter_round(3, 4, 9, 14)

    # Extract subkey (first and last 4 words)
    return struct.pack(
        "<8I",
        state[0],
        state[1],
        state[2],
        state[3],
        state[12],
        state[13],
        state[14],
        state[15],
    )


def xchacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """XChaCha20-Poly1305 AEAD encryption.

    1. Use HChaCha20 to derive subkey from first 16 bytes of nonce
    2. Use ChaCha20-Poly1305 with subkey and last 8 bytes of nonce

    Args:
        key: 32-byte encryption key
        nonce: 24-byte nonce (XChaCha20 extended nonce)
        plaintext: Data to encrypt
        aad: Additional authenticated data (not encrypted, but authenticated)

    Returns:
        Ciphertext with 16-byte Poly1305 tag appended
    """
    assert len(key) == 32, f"Key must be 32 bytes, got {len(key)}"
    assert len(nonce) == AEAD_NONCE_SIZE, f"Nonce must be {AEAD_NONCE_SIZE} bytes, got {len(nonce)}"

    # Derive subkey using HChaCha20
    subkey = hchacha20(key, nonce)

    # Build 12-byte nonce for ChaCha20-Poly1305: 4 zero bytes + last 8 bytes of XChaCha nonce
    chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:24]

    # Encrypt with standard ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(subkey)
    return cipher.encrypt(chacha_nonce, plaintext, aad)


def xchacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """XChaCha20-Poly1305 AEAD decryption.

    Args:
        key: 32-byte encryption key
        nonce: 24-byte nonce (XChaCha20 extended nonce)
        ciphertext: Data to decrypt (includes 16-byte tag)
        aad: Additional authenticated data

    Returns:
        Decrypted plaintext

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    assert len(key) == 32, f"Key must be 32 bytes, got {len(key)}"
    assert len(nonce) == AEAD_NONCE_SIZE, f"Nonce must be {AEAD_NONCE_SIZE} bytes, got {len(nonce)}"

    subkey = hchacha20(key, nonce)
    chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:24]

    cipher = ChaCha20Poly1305(subkey)
    return cipher.decrypt(chacha_nonce, ciphertext, aad)


# =============================================================================
# Nonce Construction
# =============================================================================


def construct_nonce(epoch: int, direction: int, counter: int) -> bytes:
    """Construct 24-byte XChaCha20 nonce.

    Layout:
    - Bytes 0-3: Epoch (LE32)
    - Byte 4: Direction (0x00 = initiator->responder, 0x01 = responder->initiator)
    - Bytes 5-15: Zeros (padding)
    - Bytes 16-23: Counter (LE64)

    Args:
        epoch: Key epoch (increments on rekey)
        direction: 0 for initiator->responder, 1 for responder->initiator
        counter: Monotonically increasing frame counter

    Returns:
        24-byte nonce
    """
    nonce = bytearray(AEAD_NONCE_SIZE)
    struct.pack_into("<I", nonce, 0, epoch)  # Epoch at offset 0
    nonce[4] = direction  # Direction at offset 4
    # Bytes 5-15 are zeros (already initialized)
    struct.pack_into("<Q", nonce, 16, counter)  # Counter at offset 16
    return bytes(nonce)


def parse_nonce(nonce: bytes) -> NonceComponents:
    """Parse 24-byte nonce into components.

    Args:
        nonce: 24-byte XChaCha20 nonce

    Returns:
        NonceComponents with epoch, direction, counter
    """
    assert len(nonce) == AEAD_NONCE_SIZE, f"Nonce must be {AEAD_NONCE_SIZE} bytes"

    epoch = struct.unpack_from("<I", nonce, 0)[0]
    direction = nonce[4]
    counter = struct.unpack_from("<Q", nonce, 16)[0]

    return NonceComponents(epoch=epoch, direction=direction, counter=counter)


# =============================================================================
# Frame Encoding/Decoding
# =============================================================================


def encode_data_frame_header(flags: int, session_id: bytes, nonce_counter: int) -> bytes:
    """Encode data frame header (16 bytes, used as AAD).

    Args:
        flags: Frame flags byte
        session_id: 6-byte session identifier
        nonce_counter: Frame nonce counter (LE64)

    Returns:
        16-byte header
    """
    assert len(session_id) == SESSION_ID_SIZE, f"Session ID must be {SESSION_ID_SIZE} bytes"

    header = bytearray(DATA_FRAME_HEADER_SIZE)
    header[0] = FRAME_DATA
    header[1] = flags
    header[2:8] = session_id
    struct.pack_into("<Q", header, 8, nonce_counter)
    return bytes(header)


def parse_data_frame_header(data: bytes) -> DataFrameHeader:
    """Parse data frame header.

    Args:
        data: At least 16 bytes

    Returns:
        Parsed header
    """
    if len(data) < DATA_FRAME_HEADER_SIZE:
        raise ValueError(f"Header too short: {len(data)} < {DATA_FRAME_HEADER_SIZE}")

    frame_type = data[0]
    if frame_type != FRAME_DATA:
        raise ValueError(f"Not a data frame: type 0x{frame_type:02x}")

    flags = data[1]
    session_id = bytes(data[2:8])
    nonce_counter = struct.unpack_from("<Q", data, 8)[0]

    return DataFrameHeader(
        frame_type=frame_type,
        flags=flags,
        session_id=session_id,
        nonce_counter=nonce_counter,
    )


def encode_payload_header(timestamp: int, timestamp_echo: int, payload_length: int) -> bytes:
    """Encode encrypted payload header.

    Args:
        timestamp: Sender's current time in ms since session start
        timestamp_echo: Most recent timestamp received from peer
        payload_length: Length of sync message

    Returns:
        10-byte payload header
    """
    return struct.pack("<IIH", timestamp, timestamp_echo, payload_length)


def parse_payload_header(data: bytes) -> PayloadHeader:
    """Parse encrypted payload header.

    Args:
        data: At least 10 bytes

    Returns:
        Parsed payload header
    """
    if len(data) < 10:
        raise ValueError(f"Payload header too short: {len(data)} < 10")

    timestamp, timestamp_echo, payload_length = struct.unpack_from("<IIH", data, 0)
    return PayloadHeader(
        timestamp=timestamp,
        timestamp_echo=timestamp_echo,
        payload_length=payload_length,
    )


# =============================================================================
# Sync Message Encoding/Decoding
# =============================================================================


def encode_sync_message(
    sender_state_num: int, acked_state_num: int, base_state_num: int, diff: bytes
) -> bytes:
    """Encode sync message.

    Layout:
    - Sender State Num (8 bytes, LE64)
    - Acked State Num (8 bytes, LE64)
    - Base State Num (8 bytes, LE64)
    - Diff Length (4 bytes, LE32)
    - Diff Payload (variable)

    Args:
        sender_state_num: Version of sender's current state
        acked_state_num: Highest version received from peer
        base_state_num: Version this diff was computed from
        diff: Application-specific diff payload

    Returns:
        Encoded sync message
    """
    header = struct.pack("<QQQ", sender_state_num, acked_state_num, base_state_num)
    length = struct.pack("<I", len(diff))
    return header + length + diff


def parse_sync_message(data: bytes) -> SyncMessage:
    """Parse sync message.

    Args:
        data: Encoded sync message

    Returns:
        Parsed sync message
    """
    if len(data) < SYNC_MESSAGE_HEADER_SIZE:
        raise ValueError(f"Sync message too short: {len(data)} < {SYNC_MESSAGE_HEADER_SIZE}")

    sender_state_num, acked_state_num, base_state_num = struct.unpack_from("<QQQ", data, 0)
    diff_length = struct.unpack_from("<I", data, 24)[0]

    if len(data) < SYNC_MESSAGE_HEADER_SIZE + diff_length:
        raise ValueError(
            f"Sync message truncated: {len(data)} < {SYNC_MESSAGE_HEADER_SIZE + diff_length}"
        )

    diff = bytes(data[SYNC_MESSAGE_HEADER_SIZE : SYNC_MESSAGE_HEADER_SIZE + diff_length])

    return SyncMessage(
        sender_state_num=sender_state_num,
        acked_state_num=acked_state_num,
        base_state_num=base_state_num,
        diff=diff,
    )


# =============================================================================
# Key Derivation Utilities
# =============================================================================


def deterministic_keypair(seed: str) -> tuple[bytes, bytes]:
    """Generate X25519 keypair from seed string.

    Uses BLAKE2b to derive a 32-byte private key from the seed,
    then computes the public key via scalar multiplication.

    This is used for reproducible test vectors.

    Args:
        seed: Seed string

    Returns:
        Tuple of (private_key, public_key)
    """
    # Derive private key from seed
    private = blake2b(seed.encode(), digest_size=32)

    # Clamp private key for X25519
    private_bytes = bytearray(private)
    private_bytes[0] &= 248
    private_bytes[31] &= 127
    private_bytes[31] |= 64
    private = bytes(private_bytes)

    # Compute public key
    public = crypto_scalarmult_base(private)

    return private, public


def deterministic_bytes(seed: str, length: int) -> bytes:
    """Generate deterministic bytes from seed.

    Uses BLAKE2b with a counter to generate arbitrary-length output.

    Args:
        seed: Seed string
        length: Number of bytes to generate

    Returns:
        Deterministic bytes
    """
    result = b""
    counter = 0
    while len(result) < length:
        chunk = blake2b(f"{seed}:{counter}".encode(), digest_size=32)
        result += chunk
        counter += 1
    return result[:length]


# =============================================================================
# NomadCodec Class (Main Interface)
# =============================================================================


class NomadCodec:
    """Full protocol reference implementation.

    This class provides the canonical encoding/decoding for the NOMAD protocol.
    It is the reference implementation that all tests validate against.
    """

    # Expose constants
    FRAME_HANDSHAKE_INIT = FRAME_HANDSHAKE_INIT
    FRAME_HANDSHAKE_RESP = FRAME_HANDSHAKE_RESP
    FRAME_DATA = FRAME_DATA
    FRAME_REKEY = FRAME_REKEY
    FRAME_CLOSE = FRAME_CLOSE

    FLAG_ACK_ONLY = FLAG_ACK_ONLY
    FLAG_HAS_EXTENSION = FLAG_HAS_EXTENSION

    SESSION_ID_SIZE = SESSION_ID_SIZE
    AEAD_TAG_SIZE = AEAD_TAG_SIZE
    AEAD_NONCE_SIZE = AEAD_NONCE_SIZE

    # AEAD methods
    @staticmethod
    def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """XChaCha20-Poly1305 encryption."""
        return xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """XChaCha20-Poly1305 decryption."""
        return xchacha20_poly1305_decrypt(key, nonce, ciphertext, aad)

    # Nonce methods
    @staticmethod
    def construct_nonce(epoch: int, direction: int, counter: int) -> bytes:
        """Construct 24-byte XChaCha20 nonce."""
        return construct_nonce(epoch, direction, counter)

    @staticmethod
    def parse_nonce(nonce: bytes) -> NonceComponents:
        """Parse nonce into components."""
        return parse_nonce(nonce)

    # Frame methods
    @staticmethod
    def create_data_frame_header(flags: int, session_id: bytes, nonce_counter: int) -> bytes:
        """Create data frame header (16 bytes, used as AAD)."""
        return encode_data_frame_header(flags, session_id, nonce_counter)

    @staticmethod
    def parse_data_frame_header(data: bytes) -> DataFrameHeader:
        """Parse data frame header."""
        return parse_data_frame_header(data)

    @staticmethod
    def create_payload_header(timestamp: int, timestamp_echo: int, payload_length: int) -> bytes:
        """Create encrypted payload header."""
        return encode_payload_header(timestamp, timestamp_echo, payload_length)

    @staticmethod
    def parse_payload_header(data: bytes) -> PayloadHeader:
        """Parse encrypted payload header."""
        return parse_payload_header(data)

    # Sync message methods
    @staticmethod
    def create_sync_message(
        sender_state_num: int,
        acked_state_num: int,
        base_state_num: int,
        diff: bytes,
    ) -> bytes:
        """Create sync message."""
        return encode_sync_message(sender_state_num, acked_state_num, base_state_num, diff)

    @staticmethod
    def parse_sync_message(data: bytes) -> SyncMessage:
        """Parse sync message."""
        return parse_sync_message(data)

    # Complete frame creation/parsing
    def create_data_frame(
        self,
        session_id: bytes,
        nonce_counter: int,
        key: bytes,
        epoch: int,
        direction: int,
        timestamp: int,
        timestamp_echo: int,
        sync_message: bytes,
        *,
        flags: int = 0,
    ) -> bytes:
        """Create a complete encrypted data frame.

        Args:
            session_id: 6-byte session identifier
            nonce_counter: Frame nonce counter
            key: 32-byte encryption key
            epoch: Key epoch for nonce
            direction: 0 for initiator->responder, 1 for responder->initiator
            timestamp: Sender's current time (ms)
            timestamp_echo: Echo of peer's timestamp
            sync_message: Encoded sync message
            flags: Frame flags (default 0)

        Returns:
            Complete wire frame (header + encrypted payload + tag)
        """
        # Create header (used as AAD)
        header = self.create_data_frame_header(flags, session_id, nonce_counter)

        # Create payload (to be encrypted)
        payload_header = self.create_payload_header(timestamp, timestamp_echo, len(sync_message))
        plaintext = payload_header + sync_message

        # Encrypt
        nonce = self.construct_nonce(epoch, direction, nonce_counter)
        ciphertext = self.encrypt(key, nonce, plaintext, header)

        return header + ciphertext

    def parse_data_frame(
        self,
        data: bytes,
        key: bytes,
        epoch: int,
        direction: int,
    ) -> DataFrame:
        """Parse a complete encrypted data frame.

        Args:
            data: Wire frame bytes
            key: 32-byte decryption key
            epoch: Expected key epoch
            direction: Expected direction (for nonce reconstruction)

        Returns:
            Parsed DataFrame with header, payload header, and sync message

        Raises:
            ValueError: If frame is malformed
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        if len(data) < DATA_FRAME_HEADER_SIZE + AEAD_TAG_SIZE:
            raise ValueError(f"Frame too short: {len(data)}")

        # Parse header
        header = self.parse_data_frame_header(data[:DATA_FRAME_HEADER_SIZE])

        # Decrypt payload
        ciphertext = data[DATA_FRAME_HEADER_SIZE:]
        aad = data[:DATA_FRAME_HEADER_SIZE]
        nonce = self.construct_nonce(epoch, direction, header.nonce_counter)
        plaintext = self.decrypt(key, nonce, ciphertext, aad)

        # Parse payload header
        payload_header = self.parse_payload_header(plaintext)

        # Parse sync message
        sync_data = plaintext[10 : 10 + payload_header.payload_length]
        sync_message = self.parse_sync_message(sync_data)

        return DataFrame(
            header=header,
            payload_header=payload_header,
            sync_message=sync_message,
        )

    # Key derivation (for testing)
    @staticmethod
    def deterministic_keypair(seed: str) -> tuple[bytes, bytes]:
        """Generate deterministic X25519 keypair for testing."""
        return deterministic_keypair(seed)

    @staticmethod
    def deterministic_bytes(seed: str, length: int) -> bytes:
        """Generate deterministic bytes for testing."""
        return deterministic_bytes(seed, length)
