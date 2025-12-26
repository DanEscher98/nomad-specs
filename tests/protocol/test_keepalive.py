"""
Keepalive Mechanism Tests

Tests keepalive frame creation, parsing, and timing behavior.
Keepalives are Data frames with ACK_ONLY flag and empty diff.

Spec reference: specs/2-TRANSPORT.md (Keepalive section)
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    AEAD_TAG_SIZE,
    DATA_FRAME_HEADER_SIZE,
    FLAG_ACK_ONLY,
    FRAME_DATA,
    NomadCodec,
    encode_sync_message,
)

# =============================================================================
# Protocol Constants from Spec
# =============================================================================

# Keepalive timing constants from spec
KEEPALIVE_INTERVAL_MS = 25_000  # 25 seconds
DEAD_INTERVAL_MS = 60_000  # 60 seconds


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """Reference codec instance."""
    return NomadCodec()


# =============================================================================
# Keepalive Frame Format Tests
# =============================================================================


class TestKeepaliveFrameFormat:
    """Test keepalive frame format per spec."""

    def test_keepalive_is_data_frame(self, codec: NomadCodec) -> None:
        """Keepalive is a Data frame (type 0x03)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive", 32)

        sync_message = encode_sync_message(
            sender_state_num=10,
            acked_state_num=10,
            base_state_num=0,
            diff=b"",  # Empty diff for keepalive
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=25000,  # 25 seconds
            timestamp_echo=24000,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        # Type byte is Data (0x03)
        assert frame[0] == FRAME_DATA

    def test_keepalive_has_ack_only_flag(self, codec: NomadCodec) -> None:
        """Keepalive has ACK_ONLY flag set."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_flag", 32)

        sync_message = encode_sync_message(
            sender_state_num=5,
            acked_state_num=5,
            base_state_num=0,
            diff=b"",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        # Flags byte (offset 1) has ACK_ONLY set
        assert frame[1] == FLAG_ACK_ONLY
        assert frame[1] & FLAG_ACK_ONLY == FLAG_ACK_ONLY

    def test_keepalive_has_empty_diff(self, codec: NomadCodec) -> None:
        """Keepalive has zero-length diff payload."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_empty", 32)

        sync_message = encode_sync_message(
            sender_state_num=42,
            acked_state_num=42,
            base_state_num=0,
            diff=b"",  # Empty diff
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=1,
            timestamp=30000,
            timestamp_echo=29000,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        # Parse and verify empty diff
        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=1,
        )

        assert parsed.sync_message.diff == b""
        assert len(parsed.sync_message.diff) == 0

    def test_keepalive_minimal_size(self, codec: NomadCodec) -> None:
        """Keepalive has minimal frame size."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_size", 32)

        sync_message = encode_sync_message(
            sender_state_num=0,
            acked_state_num=0,
            base_state_num=0,
            diff=b"",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        # Header (16) + PayloadHeader (10) + SyncHeader (28) + Tag (16) = 70
        expected_size = DATA_FRAME_HEADER_SIZE + 10 + 28 + AEAD_TAG_SIZE
        assert len(frame) == expected_size
        assert len(frame) == 70


# =============================================================================
# Keepalive Roundtrip Tests
# =============================================================================


class TestKeepaliveRoundtrip:
    """Test keepalive encoding/decoding roundtrip."""

    def test_keepalive_roundtrip_basic(self, codec: NomadCodec) -> None:
        """Keepalive can be created and parsed."""
        session_id = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        key = codec.deterministic_bytes("keepalive_rt", 32)

        sync_message = encode_sync_message(
            sender_state_num=100,
            acked_state_num=99,
            base_state_num=0,
            diff=b"",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=50,
            key=key,
            epoch=0,
            direction=0,
            timestamp=25000,
            timestamp_echo=24500,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        assert parsed.header.session_id == session_id
        assert parsed.header.nonce_counter == 50
        assert parsed.header.flags == FLAG_ACK_ONLY
        assert parsed.payload_header.timestamp == 25000
        assert parsed.payload_header.timestamp_echo == 24500
        assert parsed.sync_message.sender_state_num == 100
        assert parsed.sync_message.acked_state_num == 99
        assert parsed.sync_message.diff == b""

    def test_keepalive_responder_to_initiator(self, codec: NomadCodec) -> None:
        """Keepalive from responder (direction=1) works."""
        session_id = b"\x11\x22\x33\x44\x55\x66"
        key = codec.deterministic_bytes("keepalive_resp", 32)

        sync_message = encode_sync_message(
            sender_state_num=50,
            acked_state_num=49,
            base_state_num=0,
            diff=b"",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=25,
            key=key,
            epoch=0,
            direction=1,  # responder -> initiator
            timestamp=50000,
            timestamp_echo=49000,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=1,
        )

        assert parsed.sync_message.diff == b""

    @given(
        nonce_counter=st.integers(min_value=0, max_value=2**32),
        sender_state=st.integers(min_value=0, max_value=2**32),
        acked_state=st.integers(min_value=0, max_value=2**32),
        timestamp=st.integers(min_value=0, max_value=2**32 - 1),
    )
    @settings(max_examples=50)
    def test_keepalive_roundtrip_property(
        self,
        nonce_counter: int,
        sender_state: int,
        acked_state: int,
        timestamp: int,
        codec: NomadCodec,
    ) -> None:
        """Any valid keepalive can be round-tripped."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_prop", 32)

        sync_message = encode_sync_message(
            sender_state_num=sender_state,
            acked_state_num=acked_state,
            base_state_num=0,
            diff=b"",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=nonce_counter,
            key=key,
            epoch=0,
            direction=0,
            timestamp=timestamp,
            timestamp_echo=0,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        assert parsed.sync_message.sender_state_num == sender_state
        assert parsed.sync_message.acked_state_num == acked_state
        assert parsed.sync_message.diff == b""


# =============================================================================
# Keepalive Timing Constants Tests
# =============================================================================


class TestKeepaliveTimingConstants:
    """Test keepalive timing constants from spec."""

    def test_keepalive_interval(self) -> None:
        """KEEPALIVE_INTERVAL is 25 seconds (25000 ms)."""
        assert KEEPALIVE_INTERVAL_MS == 25_000

    def test_dead_interval(self) -> None:
        """DEAD_INTERVAL is 60 seconds (60000 ms)."""
        assert DEAD_INTERVAL_MS == 60_000

    def test_dead_interval_greater_than_keepalive(self) -> None:
        """DEAD_INTERVAL > KEEPALIVE_INTERVAL (to allow multiple retries)."""
        assert DEAD_INTERVAL_MS > KEEPALIVE_INTERVAL_MS

    def test_keepalive_fits_in_timestamp(self) -> None:
        """Keepalive interval fits in uint32 timestamp field."""
        max_timestamp = 0xFFFFFFFF  # ~49 days in ms
        assert max_timestamp > KEEPALIVE_INTERVAL_MS
        assert max_timestamp > DEAD_INTERVAL_MS


# =============================================================================
# Keepalive vs Data Frame Tests
# =============================================================================


class TestKeepaliveVsDataFrame:
    """Test differences between keepalive and regular data frames."""

    def test_keepalive_vs_data_flags(self, codec: NomadCodec) -> None:
        """Keepalive has ACK_ONLY flag, data frame doesn't."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_vs_data", 32)

        # Keepalive
        keepalive_sync = encode_sync_message(10, 10, 0, b"")
        keepalive = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=keepalive_sync,
            flags=FLAG_ACK_ONLY,
        )

        # Data frame
        data_sync = encode_sync_message(11, 10, 10, b"data")
        data_frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=1,
            key=key,
            epoch=0,
            direction=0,
            timestamp=100,
            timestamp_echo=0,
            sync_message=data_sync,
            flags=0,  # No ACK_ONLY
        )

        # Verify flags
        assert keepalive[1] == FLAG_ACK_ONLY
        assert data_frame[1] == 0

    def test_keepalive_vs_data_size(self, codec: NomadCodec) -> None:
        """Keepalive is smaller than data frame with payload."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("size_compare", 32)

        # Keepalive (empty diff)
        keepalive_sync = encode_sync_message(10, 10, 0, b"")
        keepalive = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=keepalive_sync,
            flags=FLAG_ACK_ONLY,
        )

        # Data frame (with payload)
        data_sync = encode_sync_message(11, 10, 10, b"some data payload here")
        data_frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=1,
            key=key,
            epoch=0,
            direction=0,
            timestamp=100,
            timestamp_echo=0,
            sync_message=data_sync,
            flags=0,
        )

        # Keepalive is smaller
        assert len(keepalive) < len(data_frame)

    def test_data_frame_without_ack_only_not_keepalive(self, codec: NomadCodec) -> None:
        """Data frame without ACK_ONLY is not a keepalive even if diff is empty."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("not_keepalive", 32)

        # Empty diff but no ACK_ONLY flag
        sync_message = encode_sync_message(10, 9, 9, b"")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
            flags=0,  # No ACK_ONLY - this is NOT a keepalive
        )

        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        # Not a keepalive (no ACK_ONLY flag)
        assert parsed.header.flags & FLAG_ACK_ONLY == 0
        # But diff is still empty
        assert parsed.sync_message.diff == b""


# =============================================================================
# Keepalive Acknowledgment Tests
# =============================================================================


class TestKeepaliveAcknowledgment:
    """Test that keepalives carry acknowledgment information."""

    def test_keepalive_carries_acked_state(self, codec: NomadCodec) -> None:
        """Keepalive carries acked_state_num even with empty diff."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_ack", 32)

        sync_message = encode_sync_message(
            sender_state_num=100,
            acked_state_num=99,  # Acknowledging peer's state 99
            base_state_num=0,
            diff=b"",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        # Acknowledgment is preserved
        assert parsed.sync_message.acked_state_num == 99

    def test_keepalive_carries_timestamp_echo(self, codec: NomadCodec) -> None:
        """Keepalive carries timestamp echo for RTT measurement."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_rtt", 32)

        sync_message = encode_sync_message(50, 50, 0, b"")

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=25000,
            timestamp_echo=24500,  # Echoing peer's timestamp
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        # Timestamp echo is preserved
        assert parsed.payload_header.timestamp_echo == 24500


# =============================================================================
# Keepalive Security Tests
# =============================================================================


class TestKeepaliveSecurity:
    """Test keepalive security properties."""

    def test_keepalive_authenticated(self, codec: NomadCodec) -> None:
        """Keepalive is authenticated (AEAD)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_auth", 32)
        wrong_key = codec.deterministic_bytes("wrong_key", 32)

        sync_message = encode_sync_message(10, 10, 0, b"")

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        # Decryption with wrong key fails
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=frame,
                key=wrong_key,
                epoch=0,
                direction=0,
            )

    def test_keepalive_header_in_aad(self, codec: NomadCodec) -> None:
        """Keepalive header is included in AAD."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_aad", 32)

        sync_message = encode_sync_message(10, 10, 0, b"")

        frame = bytearray(codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        ))

        # Modify header (AAD)
        frame[1] = 0x00  # Clear ACK_ONLY flag

        # Decryption fails
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=bytes(frame),
                key=key,
                epoch=0,
                direction=0,
            )
