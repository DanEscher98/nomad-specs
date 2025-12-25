"""
Tamper Detection Tests for NOMAD Protocol.

These tests verify that implementations correctly detect and reject
tampered frames using AEAD (Authenticated Encryption with Associated Data).

Per spec (1-SECURITY.md):
- XChaCha20-Poly1305 AEAD provides integrity and authenticity
- Header is included in AAD (authenticated but not encrypted)
- Any modification MUST cause AEAD verification to fail

Security property: Integrity ensures attackers cannot modify frame contents
without detection.
"""

from __future__ import annotations

import os
import struct
from typing import TYPE_CHECKING

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from lib.reference import (
    AEAD_TAG_SIZE,
    DATA_FRAME_HEADER_SIZE,
    NomadCodec,
)

if TYPE_CHECKING:
    from lib.attacker import MITMAttacker


# Mark all tests in this module as adversarial
pytestmark = pytest.mark.adversarial


class TestCiphertextTampering:
    """Tests for tampering with encrypted payload (ciphertext)."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    @pytest.fixture
    def valid_frame(self, codec: NomadCodec) -> tuple[bytes, dict]:
        """Create a valid frame for tampering tests."""
        key = codec.deterministic_bytes("tamper-test-key", 32)
        session_id = codec.deterministic_bytes("tamper-session-id", 6)

        sync_message = codec.create_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"original content that should not be modified",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=42,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        return frame, {
            "key": key,
            "session_id": session_id,
            "epoch": 0,
            "direction": 0,
        }

    def test_flip_bit_in_ciphertext_aead_fails(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Flipping any bit in ciphertext causes AEAD failure.

        Spec: 1-SECURITY.md §AEAD Encryption
        "Poly1305 authentication tag" provides integrity.

        Attack scenario:
        1. Attacker captures valid frame
        2. Attacker flips a bit in the ciphertext portion
        3. AEAD verification MUST fail
        """
        frame, session = valid_frame

        # Ciphertext starts after header (16 bytes)
        # Flip a bit in the middle of ciphertext (not the tag)
        ciphertext_offset = DATA_FRAME_HEADER_SIZE + 10  # Somewhere in encrypted payload

        # XOR with 0x01 to flip lowest bit
        tampered = bytearray(frame)
        tampered[ciphertext_offset] ^= 0x01
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    @given(bit_position=st.integers(min_value=0, max_value=7))
    @settings(max_examples=8, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_any_bit_flip_in_ciphertext_detected(
        self,
        codec: NomadCodec,
        valid_frame: tuple[bytes, dict],
        bit_position: int,
    ) -> None:
        """Any single bit flip in ciphertext is detected.

        Test that flipping any of the 8 bits in a byte causes detection.
        """
        frame, session = valid_frame

        # Target a byte in the ciphertext
        offset = DATA_FRAME_HEADER_SIZE + 5
        assume(offset < len(frame) - AEAD_TAG_SIZE)

        # Flip the specific bit
        tampered = bytearray(frame)
        tampered[offset] ^= (1 << bit_position)
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    @given(offset=st.integers(min_value=0, max_value=50))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_flip_bit_at_any_ciphertext_offset(
        self,
        codec: NomadCodec,
        valid_frame: tuple[bytes, dict],
        offset: int,
    ) -> None:
        """Bit flip at any offset in ciphertext is detected."""
        frame, session = valid_frame

        # Ensure offset is within ciphertext (after header, before end)
        actual_offset = DATA_FRAME_HEADER_SIZE + offset
        assume(actual_offset < len(frame))

        tampered = bytearray(frame)
        tampered[actual_offset] ^= 0x01
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )


class TestHeaderTampering:
    """Tests for tampering with frame header (AAD)."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    @pytest.fixture
    def valid_frame(self, codec: NomadCodec) -> tuple[bytes, dict]:
        """Create a valid frame for tampering tests."""
        key = codec.deterministic_bytes("header-tamper-key", 32)
        session_id = codec.deterministic_bytes("header-session-id", 6)

        sync_message = codec.create_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"payload content",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        return frame, {
            "key": key,
            "session_id": session_id,
            "epoch": 0,
            "direction": 0,
        }

    def test_flip_bit_in_header_aead_fails(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Flipping any bit in header (AAD) causes AEAD failure.

        Spec: 1-SECURITY.md §Additional Authenticated Data (AAD)
        "The frame header is authenticated but not encrypted.
         This prevents bit-flipping attacks on header fields."

        Attack scenario:
        1. Attacker captures valid frame
        2. Attacker modifies a header field (type, flags, session_id, nonce)
        3. AEAD verification MUST fail because header is in AAD
        """
        frame, session = valid_frame

        # Flip a bit in the flags byte (offset 1)
        tampered = bytearray(frame)
        tampered[1] ^= 0x01
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    def test_modify_frame_type_aead_fails(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Modifying frame type causes AEAD failure or frame type rejection.

        Attacker cannot change a Data frame to a Close frame.
        Implementation may reject at frame type check or AEAD verification.
        """
        frame, session = valid_frame

        # Change frame type from 0x03 (Data) to 0x05 (Close)
        tampered = bytearray(frame)
        tampered[0] = 0x05
        tampered = bytes(tampered)

        # May fail at frame type check (ValueError) or AEAD verification (InvalidTag)
        with pytest.raises((InvalidTag, ValueError)):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    def test_modify_flags_aead_fails(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Modifying flags causes AEAD failure.

        Attacker cannot add or remove flags (e.g., ACK_ONLY).
        """
        frame, session = valid_frame

        # Set ACK_ONLY flag
        tampered = bytearray(frame)
        tampered[1] = 0x01  # ACK_ONLY
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    def test_modify_session_id_aead_fails(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Modifying session ID causes AEAD failure.

        Attacker cannot redirect frame to different session.
        """
        frame, session = valid_frame

        # Modify session ID (bytes 2-7)
        tampered = bytearray(frame)
        tampered[2:8] = os.urandom(6)  # Random session ID
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    def test_modify_nonce_counter_aead_fails(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Modifying nonce counter causes AEAD failure.

        Attacker cannot replay with modified counter to bypass window.
        """
        frame, session = valid_frame

        # Modify nonce counter (bytes 8-15)
        tampered = bytearray(frame)
        original_nonce = struct.unpack_from("<Q", frame, 8)[0]
        struct.pack_into("<Q", tampered, 8, original_nonce + 1000)
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    @given(header_offset=st.integers(min_value=1, max_value=15))  # Skip byte 0 (frame type)
    @settings(max_examples=15, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_any_header_byte_modification_detected(
        self,
        codec: NomadCodec,
        valid_frame: tuple[bytes, dict],
        header_offset: int,
    ) -> None:
        """Modification of any non-type header byte is detected via AEAD.

        Note: Byte 0 (frame type) is checked separately and may raise ValueError.
        This test focuses on bytes 1-15 which are all authenticated via AAD.
        """
        frame, session = valid_frame

        tampered = bytearray(frame)
        tampered[header_offset] ^= 0xFF  # Flip all bits in byte
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )


class TestFrameTruncation:
    """Tests for frame truncation attacks."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    @pytest.fixture
    def valid_frame(self, codec: NomadCodec) -> tuple[bytes, dict]:
        """Create a valid frame for truncation tests."""
        key = codec.deterministic_bytes("truncate-key", 32)
        session_id = codec.deterministic_bytes("truncate-session", 6)

        sync_message = codec.create_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"payload with some length to truncate",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=50,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        return frame, {
            "key": key,
            "session_id": session_id,
            "epoch": 0,
            "direction": 0,
        }

    def test_truncate_frame_rejected(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Truncated frame MUST be rejected.

        Spec: 2-TRANSPORT.md §Error Handling
        "Frame too small: Silently drop"

        Attack scenario:
        1. Attacker captures valid frame
        2. Attacker truncates frame (removes bytes from end)
        3. Implementation MUST reject (tag is corrupted/missing)
        """
        frame, session = valid_frame

        # Truncate by removing last 10 bytes (part of tag)
        truncated = frame[:-10]

        # Frame is now too short for valid AEAD
        assert len(truncated) < len(frame)

        with pytest.raises((InvalidTag, ValueError)):
            codec.parse_data_frame(
                truncated,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    def test_truncate_to_header_only_rejected(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Frame truncated to header only MUST be rejected."""
        frame, session = valid_frame

        # Keep only header
        truncated = frame[:DATA_FRAME_HEADER_SIZE]

        with pytest.raises((InvalidTag, ValueError)):
            codec.parse_data_frame(
                truncated,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    @given(truncate_by=st.integers(min_value=1, max_value=50))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_any_truncation_rejected(
        self,
        codec: NomadCodec,
        valid_frame: tuple[bytes, dict],
        truncate_by: int,
    ) -> None:
        """Any amount of truncation is rejected."""
        frame, session = valid_frame

        assume(truncate_by < len(frame))
        truncated = frame[:-truncate_by]

        with pytest.raises((InvalidTag, ValueError)):
            codec.parse_data_frame(
                truncated,
                session["key"],
                session["epoch"],
                session["direction"],
            )


class TestFrameExtension:
    """Tests for frame extension attacks (appending garbage)."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    @pytest.fixture
    def valid_frame(self, codec: NomadCodec) -> tuple[bytes, dict]:
        """Create a valid frame for extension tests."""
        key = codec.deterministic_bytes("extend-key", 32)
        session_id = codec.deterministic_bytes("extend-session", 6)

        sync_message = codec.create_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"original payload",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=75,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        return frame, {
            "key": key,
            "session_id": session_id,
            "epoch": 0,
            "direction": 0,
        }

    def test_extend_frame_with_garbage_aead_fails(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Extending frame with garbage causes AEAD failure.

        Spec: 1-SECURITY.md §AEAD Encryption
        AEAD authenticates the entire ciphertext including length.

        Attack scenario:
        1. Attacker captures valid frame
        2. Attacker appends garbage bytes
        3. AEAD verification MUST fail (ciphertext length changed)
        """
        frame, session = valid_frame

        # Append garbage
        garbage = os.urandom(16)
        extended = frame + garbage

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                extended,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    @given(garbage_size=st.integers(min_value=1, max_value=100))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_any_extension_rejected(
        self,
        codec: NomadCodec,
        valid_frame: tuple[bytes, dict],
        garbage_size: int,
    ) -> None:
        """Any amount of extension is rejected."""
        frame, session = valid_frame

        garbage = os.urandom(garbage_size)
        extended = frame + garbage

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                extended,
                session["key"],
                session["epoch"],
                session["direction"],
            )


class TestTagTampering:
    """Tests for tampering with the AEAD tag directly."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    @pytest.fixture
    def valid_frame(self, codec: NomadCodec) -> tuple[bytes, dict]:
        """Create a valid frame for tag tampering tests."""
        key = codec.deterministic_bytes("tag-tamper-key", 32)
        session_id = codec.deterministic_bytes("tag-session", 6)

        sync_message = codec.create_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"test payload",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=99,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        return frame, {
            "key": key,
            "session_id": session_id,
            "epoch": 0,
            "direction": 0,
        }

    def test_modify_tag_aead_fails(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Modifying any byte in the AEAD tag causes failure.

        The tag is the last 16 bytes of the frame.
        """
        frame, session = valid_frame

        # Flip a bit in the tag (last 16 bytes)
        tampered = bytearray(frame)
        tampered[-8] ^= 0x01  # Middle of tag
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    def test_replace_tag_with_random_aead_fails(
        self, codec: NomadCodec, valid_frame: tuple[bytes, dict]
    ) -> None:
        """Replacing tag with random bytes causes failure."""
        frame, session = valid_frame

        # Replace tag with random bytes
        tampered = frame[:-AEAD_TAG_SIZE] + os.urandom(AEAD_TAG_SIZE)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                tampered,
                session["key"],
                session["epoch"],
                session["direction"],
            )

    def test_swap_tags_between_frames_fails(self, codec: NomadCodec) -> None:
        """Swapping tags between frames causes failure.

        Tags are bound to specific (key, nonce, aad, ciphertext) tuples.
        """
        key = codec.deterministic_bytes("swap-tag-key", 32)
        session_id = codec.deterministic_bytes("swap-session", 6)

        # Create two different frames
        sync1 = codec.create_sync_message(1, 0, 0, b"first payload")
        frame1 = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=1,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync1,
        )

        sync2 = codec.create_sync_message(2, 1, 1, b"second payload")
        frame2 = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=2,
            key=key,
            epoch=0,
            direction=0,
            timestamp=2000,
            timestamp_echo=1000,
            sync_message=sync2,
        )

        # Swap tags
        tag1 = frame1[-AEAD_TAG_SIZE:]
        tag2 = frame2[-AEAD_TAG_SIZE:]

        franken1 = frame1[:-AEAD_TAG_SIZE] + tag2
        franken2 = frame2[:-AEAD_TAG_SIZE] + tag1

        # Both should fail
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(franken1, key, 0, 0)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(franken2, key, 0, 0)


class TestTamperWithAttacker:
    """Tests using the MITMAttacker tamper functionality."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_attacker_tamper_frame_produces_invalid_frame(
        self, codec: NomadCodec, attacker: MITMAttacker
    ) -> None:
        """Verify attacker.tamper_frame produces frames that fail AEAD."""
        key = codec.deterministic_bytes("attacker-tamper-key", 32)
        session_id = codec.deterministic_bytes("attacker-session", 6)

        sync = codec.create_sync_message(1, 0, 0, b"test")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=1,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Use attacker's tamper function
        tampered = attacker.tamper_frame(frame, offset=20, xor_mask=0xFF)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(tampered, key, 0, 0)
