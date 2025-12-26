"""
Network utilities for Nomad protocol conformance tests.

This module provides:
- Scapy-based packet injection and capture
- UDP frame sending/receiving utilities
- Malformed packet generation
- IP spoofing support for amplification tests

Uses scapy for low-level packet manipulation.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from scapy.all import UDP, IP, Ether, Raw, rdpcap, sendp, sniff, sr1
from scapy.layers.inet import ICMP

if TYPE_CHECKING:
    from scapy.packet import Packet

log = structlog.get_logger()

# Default Nomad port
NOMAD_PORT = 19999


@dataclass
class CapturedFrame:
    """A captured Nomad frame with metadata."""

    raw_bytes: bytes
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    timestamp: float

    @property
    def is_nomad_port(self) -> bool:
        """Check if frame is on Nomad port."""
        return self.src_port == NOMAD_PORT or self.dst_port == NOMAD_PORT

    @property
    def frame_type(self) -> int | None:
        """Get frame type byte if available."""
        if len(self.raw_bytes) >= 1:
            return self.raw_bytes[0]
        return None

    @property
    def session_id(self) -> bytes | None:
        """Get session ID if this looks like a data frame."""
        if len(self.raw_bytes) >= 8 and self.frame_type == 0x03:
            return self.raw_bytes[2:8]
        return None


@dataclass
class PacketSender:
    """Utility for sending packets to containers."""

    target_ip: str
    target_port: int = NOMAD_PORT
    source_ip: str | None = None
    source_port: int = 0
    interface: str = "eth0"

    def send_udp(self, payload: bytes, wait_response: bool = False, timeout: float = 1.0) -> Packet | None:
        """Send a UDP packet.

        Args:
            payload: Raw bytes to send as UDP payload.
            wait_response: If True, wait for a response packet.
            timeout: Response timeout in seconds.

        Returns:
            Response packet if wait_response=True and response received, else None.
        """
        # Build IP layer
        if self.source_ip:
            ip = IP(src=self.source_ip, dst=self.target_ip)
        else:
            ip = IP(dst=self.target_ip)

        # Build UDP layer
        if self.source_port:
            udp = UDP(sport=self.source_port, dport=self.target_port)
        else:
            udp = UDP(dport=self.target_port)

        # Build packet
        pkt = ip / udp / Raw(load=payload)

        log.debug(
            "sending_packet",
            src=self.source_ip or "auto",
            dst=self.target_ip,
            port=self.target_port,
            size=len(payload),
        )

        if wait_response:
            # Send and wait for response
            response = sr1(pkt, timeout=timeout, verbose=False)
            return response
        else:
            # Just send, don't wait
            sendp(Ether() / pkt, iface=self.interface, verbose=False)
            return None

    def send_spoofed(
        self,
        payload: bytes,
        spoofed_src_ip: str,
        spoofed_src_port: int = 0,
    ) -> None:
        """Send a packet with spoofed source address.

        Used for anti-amplification testing.

        Args:
            payload: Raw bytes to send.
            spoofed_src_ip: IP address to spoof as source.
            spoofed_src_port: Source port to spoof (0 = random).
        """
        ip = IP(src=spoofed_src_ip, dst=self.target_ip)
        udp = UDP(sport=spoofed_src_port or 12345, dport=self.target_port)
        pkt = ip / udp / Raw(load=payload)

        log.debug(
            "sending_spoofed_packet",
            spoofed_src=spoofed_src_ip,
            dst=self.target_ip,
            size=len(payload),
        )

        sendp(Ether() / pkt, iface=self.interface, verbose=False)


@dataclass
class PacketCapture:
    """Captures packets from the network."""

    interface: str = "eth0"
    filter_expr: str = f"udp port {NOMAD_PORT}"
    captured: list[CapturedFrame] = field(default_factory=list)
    _stop_sniff: bool = False

    def start_async(self, count: int = 0, timeout: float = 10.0) -> None:
        """Start capturing packets asynchronously.

        Args:
            count: Number of packets to capture (0 = unlimited).
            timeout: Capture timeout in seconds.
        """
        import threading

        self._stop_sniff = False

        def do_capture():
            packets = sniff(
                iface=self.interface,
                filter=self.filter_expr,
                count=count,
                timeout=timeout,
                stop_filter=lambda _: self._stop_sniff,
            )
            self._process_packets(packets)

        thread = threading.Thread(target=do_capture)
        thread.daemon = True
        thread.start()

    def stop(self) -> list[CapturedFrame]:
        """Stop capturing and return captured frames."""
        self._stop_sniff = True
        return self.captured

    def capture_sync(self, count: int = 10, timeout: float = 5.0) -> list[CapturedFrame]:
        """Capture packets synchronously.

        Args:
            count: Number of packets to capture.
            timeout: Capture timeout.

        Returns:
            List of captured frames.
        """
        packets = sniff(
            iface=self.interface,
            filter=self.filter_expr,
            count=count,
            timeout=timeout,
        )
        self._process_packets(packets)
        return self.captured

    def _process_packets(self, packets) -> None:
        """Process captured packets into CapturedFrames."""
        for pkt in packets:
            if UDP in pkt and Raw in pkt:
                frame = CapturedFrame(
                    raw_bytes=bytes(pkt[Raw].load),
                    src_ip=pkt[IP].src,
                    dst_ip=pkt[IP].dst,
                    src_port=pkt[UDP].sport,
                    dst_port=pkt[UDP].dport,
                    timestamp=float(pkt.time),
                )
                self.captured.append(frame)


def parse_pcap(pcap_file: Path) -> list[CapturedFrame]:
    """Parse a pcap file into CapturedFrames.

    Args:
        pcap_file: Path to the pcap file.

    Returns:
        List of CapturedFrames from the file.
    """
    if not pcap_file.exists():
        log.warning("pcap_file_not_found", path=str(pcap_file))
        return []

    packets = rdpcap(str(pcap_file))
    frames = []

    for pkt in packets:
        if UDP in pkt and Raw in pkt:
            frame = CapturedFrame(
                raw_bytes=bytes(pkt[Raw].load),
                src_ip=pkt[IP].src,
                dst_ip=pkt[IP].dst,
                src_port=pkt[UDP].sport,
                dst_port=pkt[UDP].dport,
                timestamp=float(pkt.time),
            )
            frames.append(frame)

    log.info("parsed_pcap", path=str(pcap_file), frame_count=len(frames))
    return frames


# =============================================================================
# Malformed Packet Generators
# =============================================================================


def generate_truncated_frame(valid_frame: bytes, truncate_bytes: int) -> bytes:
    """Generate a truncated frame.

    Args:
        valid_frame: A valid frame to truncate.
        truncate_bytes: Number of bytes to remove from the end.

    Returns:
        Truncated frame bytes.
    """
    return valid_frame[:-truncate_bytes] if truncate_bytes > 0 else valid_frame


def generate_corrupted_tag(valid_frame: bytes, corruption_byte: int = 0xFF) -> bytes:
    """Generate a frame with corrupted AEAD tag.

    Args:
        valid_frame: A valid frame with AEAD tag.
        corruption_byte: Byte to XOR with last byte of tag.

    Returns:
        Frame with corrupted tag.
    """
    frame = bytearray(valid_frame)
    if len(frame) >= 16:
        frame[-1] ^= corruption_byte
    return bytes(frame)


def generate_invalid_type_frame(valid_frame: bytes, new_type: int) -> bytes:
    """Generate a frame with invalid type byte.

    Args:
        valid_frame: A valid frame.
        new_type: New type byte value (e.g., 0x00, 0xFF).

    Returns:
        Frame with modified type byte.
    """
    frame = bytearray(valid_frame)
    if len(frame) >= 1:
        frame[0] = new_type
    return bytes(frame)


def generate_random_frame(size: int) -> bytes:
    """Generate a frame with random bytes.

    Args:
        size: Size of the random frame.

    Returns:
        Random bytes.
    """
    import os
    return os.urandom(size)


def generate_session_id_variants(base_frame: bytes) -> list[bytes]:
    """Generate frames with various session ID modifications.

    Args:
        base_frame: A valid frame.

    Returns:
        List of frames with different session IDs.
    """
    if len(base_frame) < 8:
        return []

    variants = []
    frame = bytearray(base_frame)

    # All zeros
    zeros = bytearray(frame)
    zeros[2:8] = b"\x00" * 6
    variants.append(bytes(zeros))

    # All ones
    ones = bytearray(frame)
    ones[2:8] = b"\xFF" * 6
    variants.append(bytes(ones))

    # Incrementing
    for i in range(6):
        modified = bytearray(frame)
        modified[2 + i] ^= 0x01
        variants.append(bytes(modified))

    return variants


# =============================================================================
# Wire Format Validation Utilities
# =============================================================================


def validate_data_frame_header(raw_bytes: bytes) -> dict[str, bool]:
    """Validate a data frame header structure.

    Args:
        raw_bytes: Raw frame bytes.

    Returns:
        Dict with validation results.
    """
    results = {
        "has_minimum_size": len(raw_bytes) >= 32,
        "has_header": len(raw_bytes) >= 16,
        "type_is_data": False,
        "flags_valid": False,
        "session_id_present": False,
        "nonce_counter_present": False,
    }

    if len(raw_bytes) >= 16:
        results["type_is_data"] = raw_bytes[0] == 0x03
        results["flags_valid"] = (raw_bytes[1] & 0xFC) == 0  # Reserved bits are 0
        results["session_id_present"] = True
        results["nonce_counter_present"] = True

    return results


def extract_header_fields(raw_bytes: bytes) -> dict:
    """Extract header fields from a data frame.

    Args:
        raw_bytes: Raw frame bytes (at least 16 bytes).

    Returns:
        Dict with extracted fields.
    """
    if len(raw_bytes) < 16:
        raise ValueError(f"Frame too short: {len(raw_bytes)} < 16")

    return {
        "type": raw_bytes[0],
        "flags": raw_bytes[1],
        "session_id": raw_bytes[2:8],
        "nonce_counter": struct.unpack("<Q", raw_bytes[8:16])[0],
    }


def measure_frame_timing(
    sender: PacketSender,
    frames: list[bytes],
    interval_ms: float = 100,
) -> list[float]:
    """Measure timing of frame transmission.

    Args:
        sender: PacketSender instance.
        frames: List of frames to send.
        interval_ms: Interval between frames in ms.

    Returns:
        List of actual inter-frame intervals in ms.
    """
    if len(frames) < 2:
        return []

    intervals = []
    last_time = time.monotonic()

    for frame in frames:
        sender.send_udp(frame)
        now = time.monotonic()
        intervals.append((now - last_time) * 1000)
        last_time = now
        time.sleep(interval_ms / 1000)

    return intervals[1:]  # Skip first (no previous frame)
