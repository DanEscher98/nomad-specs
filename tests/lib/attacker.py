"""
MITM Attack Toolkit for NOMAD Protocol Security Tests.

This module provides tools for simulating adversarial network conditions
and performing security testing on NOMAD protocol implementations.

**IMPORTANT**: This code is for AUTHORIZED SECURITY TESTING ONLY.
It is designed to validate the security properties of the NOMAD protocol
in controlled test environments (Docker containers, pytest).

The tools in this module can:
- Capture UDP traffic on port 19999 (NOMAD protocol)
- Replay captured frames
- Inject forged frames
- Tamper with frame contents (bit-flip attacks)
- Spoof source IP addresses

All operations require appropriate capabilities (NET_RAW, NET_ADMIN).
"""

from __future__ import annotations

import os
import random
import struct
import time
from dataclasses import dataclass

import structlog

# scapy imports - lazy loaded for faster test startup
_scapy_loaded = False
_sniff = None
_sendp = None
_send = None
_IP = None
_UDP = None
_Raw = None
_Ether = None
_conf = None


def _ensure_scapy():
    """Lazy load scapy modules."""
    global _scapy_loaded, _sniff, _sendp, _send, _IP, _UDP, _Raw, _Ether, _conf
    if not _scapy_loaded:
        from scapy.all import IP, UDP, Ether, Raw, conf, send, sendp, sniff
        _sniff = sniff
        _sendp = sendp
        _send = send
        _IP = IP
        _UDP = UDP
        _Raw = Raw
        _Ether = Ether
        _conf = conf
        _scapy_loaded = True



log = structlog.get_logger()

# Default NOMAD port
NOMAD_PORT = 19999


@dataclass
class CapturedFrame:
    """A captured NOMAD protocol frame with metadata."""

    # Raw frame bytes (UDP payload only)
    data: bytes

    # Source address
    src_ip: str
    src_port: int

    # Destination address
    dst_ip: str
    dst_port: int

    # Capture timestamp
    timestamp: float

    # Parsed header fields (if valid NOMAD data frame)
    frame_type: int | None = None
    flags: int | None = None
    session_id: bytes | None = None
    nonce_counter: int | None = None

    def __post_init__(self) -> None:
        """Parse header fields if this looks like a data frame."""
        if len(self.data) >= 16:
            self.frame_type = self.data[0]
            self.flags = self.data[1]
            self.session_id = self.data[2:8]
            self.nonce_counter = struct.unpack_from("<Q", self.data, 8)[0]


@dataclass
class AttackStats:
    """Statistics for attack operations."""

    frames_captured: int = 0
    frames_replayed: int = 0
    frames_injected: int = 0
    frames_tampered: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


class MITMAttacker:
    """Man-in-the-middle attack toolkit for NOMAD protocol testing.

    This class provides methods to capture, replay, inject, and tamper
    with NOMAD protocol frames for security testing purposes.

    Example usage:
        attacker = MITMAttacker(interface="eth0")

        # Capture traffic
        frames = attacker.capture_traffic(count=10, timeout=5.0)

        # Replay a captured frame
        attacker.replay_frame(frames[0].data)

        # Inject a forged frame
        attacker.inject_frame(forged_frame, dst_ip="172.31.0.10")

        # Tamper with a frame (bit-flip attack)
        tampered = attacker.tamper_frame(frames[0].data, offset=20, byte=0xFF)
    """

    def __init__(
        self,
        interface: str = "eth0",
        target_ip: str | None = None,
        target_port: int = NOMAD_PORT,
    ) -> None:
        """Initialize the MITM attacker.

        Args:
            interface: Network interface to capture on.
            target_ip: Target IP address for injection.
            target_port: Target port (default: 19999).
        """
        self.interface = interface
        self.target_ip = target_ip
        self.target_port = target_port
        self.stats = AttackStats()
        self._captured_frames: list[CapturedFrame] = []

        log.info(
            "mitm_attacker_initialized",
            interface=interface,
            target_ip=target_ip,
            target_port=target_port,
        )

    def capture_traffic(
        self,
        count: int = 10,
        timeout: float = 10.0,
        filter_expr: str | None = None,
    ) -> list[CapturedFrame]:
        """Capture NOMAD protocol frames from the network.

        Args:
            count: Maximum number of frames to capture.
            timeout: Capture timeout in seconds.
            filter_expr: BPF filter expression (default: "udp port 19999").

        Returns:
            List of captured frames.
        """
        _ensure_scapy()

        if filter_expr is None:
            filter_expr = f"udp port {self.target_port}"

        log.info(
            "starting_capture",
            interface=self.interface,
            count=count,
            timeout=timeout,
            filter=filter_expr,
        )

        captured: list[CapturedFrame] = []

        def packet_callback(pkt):
            if _UDP in pkt and _Raw in pkt:
                frame = CapturedFrame(
                    data=bytes(pkt[_Raw].load),
                    src_ip=pkt[_IP].src,
                    src_port=pkt[_UDP].sport,
                    dst_ip=pkt[_IP].dst,
                    dst_port=pkt[_UDP].dport,
                    timestamp=time.time(),
                )
                captured.append(frame)
                self.stats.frames_captured += 1
                self.stats.bytes_received += len(frame.data)
                log.debug(
                    "frame_captured",
                    src=f"{frame.src_ip}:{frame.src_port}",
                    dst=f"{frame.dst_ip}:{frame.dst_port}",
                    size=len(frame.data),
                    type=frame.frame_type,
                    nonce=frame.nonce_counter,
                )

        try:
            _sniff(
                iface=self.interface,
                filter=filter_expr,
                prn=packet_callback,
                count=count,
                timeout=timeout,
                store=False,
            )
        except PermissionError as err:
            log.error("capture_permission_denied", interface=self.interface)
            raise PermissionError(
                f"Cannot capture on {self.interface}. "
                "Need NET_RAW/NET_ADMIN capabilities."
            ) from err

        self._captured_frames.extend(captured)
        log.info("capture_complete", frames=len(captured))
        return captured

    def replay_frame(
        self,
        frame: bytes,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        count: int = 1,
        delay: float = 0.0,
    ) -> int:
        """Replay a captured frame.

        Args:
            frame: Frame data to replay.
            dst_ip: Destination IP (default: use target_ip).
            dst_port: Destination port (default: use target_port).
            count: Number of times to replay.
            delay: Delay between replays in seconds.

        Returns:
            Number of frames sent.
        """
        _ensure_scapy()

        dst_ip = dst_ip or self.target_ip
        dst_port = dst_port or self.target_port

        if dst_ip is None:
            raise ValueError("No destination IP specified")

        log.info(
            "replaying_frame",
            dst=f"{dst_ip}:{dst_port}",
            size=len(frame),
            count=count,
        )

        sent = 0
        for _ in range(count):
            pkt = _IP(dst=dst_ip) / _UDP(dport=dst_port) / _Raw(load=frame)
            _send(pkt, verbose=False)
            sent += 1
            self.stats.frames_replayed += 1
            self.stats.bytes_sent += len(frame)
            if delay > 0 and sent < count:
                time.sleep(delay)

        return sent

    def inject_frame(
        self,
        frame: bytes,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        src_ip: str | None = None,
        src_port: int | None = None,
    ) -> None:
        """Inject a forged frame into the network.

        Args:
            frame: Frame data to inject.
            dst_ip: Destination IP address.
            dst_port: Destination port.
            src_ip: Source IP to spoof (optional).
            src_port: Source port to use (optional, random if not set).
        """
        _ensure_scapy()

        dst_ip = dst_ip or self.target_ip
        dst_port = dst_port or self.target_port
        src_port = src_port or random.randint(10000, 60000)

        if dst_ip is None:
            raise ValueError("No destination IP specified")

        log.info(
            "injecting_frame",
            dst=f"{dst_ip}:{dst_port}",
            src_ip=src_ip,
            src_port=src_port,
            size=len(frame),
        )

        if src_ip:
            pkt = (
                _IP(src=src_ip, dst=dst_ip)
                / _UDP(sport=src_port, dport=dst_port)
                / _Raw(load=frame)
            )
        else:
            pkt = (
                _IP(dst=dst_ip)
                / _UDP(sport=src_port, dport=dst_port)
                / _Raw(load=frame)
            )

        _send(pkt, verbose=False)
        self.stats.frames_injected += 1
        self.stats.bytes_sent += len(frame)

    def tamper_frame(
        self,
        frame: bytes,
        offset: int,
        byte: int | None = None,
        xor_mask: int | None = None,
    ) -> bytes:
        """Create a tampered version of a frame.

        Args:
            frame: Original frame data.
            offset: Byte offset to tamper.
            byte: New byte value to set (mutually exclusive with xor_mask).
            xor_mask: XOR mask to apply (bit-flip attack).

        Returns:
            Tampered frame data.
        """
        if offset < 0 or offset >= len(frame):
            raise ValueError(f"Offset {offset} out of range [0, {len(frame)})")

        if byte is None and xor_mask is None:
            raise ValueError("Must specify either byte or xor_mask")

        if byte is not None and xor_mask is not None:
            raise ValueError("Cannot specify both byte and xor_mask")

        tampered = bytearray(frame)

        if byte is not None:
            tampered[offset] = byte & 0xFF
        else:
            tampered[offset] ^= xor_mask & 0xFF

        self.stats.frames_tampered += 1
        log.debug(
            "frame_tampered",
            offset=offset,
            original=frame[offset],
            new=tampered[offset],
        )

        return bytes(tampered)

    def spoof_source(
        self,
        frame: bytes,
        spoof_ip: str,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        src_port: int | None = None,
    ) -> None:
        """Send a frame with spoofed source IP.

        Args:
            frame: Frame data to send.
            spoof_ip: Source IP address to spoof.
            dst_ip: Destination IP address.
            dst_port: Destination port.
            src_port: Source port (random if not set).
        """
        self.inject_frame(
            frame=frame,
            dst_ip=dst_ip,
            dst_port=dst_port,
            src_ip=spoof_ip,
            src_port=src_port,
        )

    def truncate_frame(self, frame: bytes, new_length: int) -> bytes:
        """Truncate a frame to a shorter length.

        Args:
            frame: Original frame data.
            new_length: New length for the frame.

        Returns:
            Truncated frame data.
        """
        if new_length < 0:
            raise ValueError("Length cannot be negative")
        if new_length >= len(frame):
            return frame
        return frame[:new_length]

    def extend_frame(self, frame: bytes, garbage: bytes | None = None) -> bytes:
        """Extend a frame with garbage data.

        Args:
            frame: Original frame data.
            garbage: Garbage bytes to append (random if not set).

        Returns:
            Extended frame data.
        """
        if garbage is None:
            garbage = os.urandom(16)
        return frame + garbage

    def forge_frame(
        self,
        session_id: bytes,
        nonce_counter: int,
        payload: bytes | None = None,
        frame_type: int = 0x03,
        flags: int = 0x00,
    ) -> bytes:
        """Forge a NOMAD data frame header with random payload.

        This creates a frame that has the correct header structure but
        will fail AEAD verification (since we don't have the keys).

        Args:
            session_id: 6-byte session ID.
            nonce_counter: Nonce counter value.
            payload: Encrypted payload (random if not set).
            frame_type: Frame type byte (default: 0x03 Data).
            flags: Flags byte.

        Returns:
            Forged frame bytes.
        """
        if len(session_id) != 6:
            raise ValueError("Session ID must be 6 bytes")

        # Build header (16 bytes)
        header = bytearray(16)
        header[0] = frame_type
        header[1] = flags
        header[2:8] = session_id
        struct.pack_into("<Q", header, 8, nonce_counter)

        # Random payload with fake AEAD tag
        if payload is None:
            # Minimum: 10 bytes payload header + 16 bytes tag
            payload = os.urandom(26)

        return bytes(header) + payload

    def get_stats(self) -> AttackStats:
        """Get attack operation statistics.

        Returns:
            Current statistics.
        """
        return self.stats

    def reset_stats(self) -> None:
        """Reset all statistics."""
        self.stats = AttackStats()
        self._captured_frames.clear()


class TimingAnalyzer:
    """Analyze timing patterns in captured frames.

    Used to test whether implementations leak keystroke timing
    through inter-frame arrival times.
    """

    def __init__(self) -> None:
        """Initialize the timing analyzer."""
        self.samples: list[float] = []

    def record_frame(self, timestamp: float) -> None:
        """Record a frame arrival timestamp.

        Args:
            timestamp: Frame arrival time in seconds.
        """
        self.samples.append(timestamp)

    def get_inter_arrival_times(self) -> list[float]:
        """Calculate inter-arrival times between frames.

        Returns:
            List of inter-arrival times in seconds.
        """
        if len(self.samples) < 2:
            return []
        return [
            self.samples[i] - self.samples[i - 1] for i in range(1, len(self.samples))
        ]

    def correlate_with_pattern(self, pattern: list[float]) -> float:
        """Calculate Pearson correlation with a known timing pattern.

        This tests whether inter-arrival times correlate with a known
        keystroke pattern, which would indicate timing leakage.

        Args:
            pattern: Known inter-keystroke times in seconds.

        Returns:
            Pearson correlation coefficient (-1 to 1).
        """
        arrivals = self.get_inter_arrival_times()

        if len(arrivals) < 2 or len(pattern) < 2:
            return 0.0

        # Truncate to shorter length
        n = min(len(arrivals), len(pattern))
        arrivals = arrivals[:n]
        pattern = pattern[:n]

        # Calculate means
        mean_a = sum(arrivals) / n
        mean_p = sum(pattern) / n

        # Calculate Pearson correlation
        num = sum(
            (a - mean_a) * (p - mean_p)
            for a, p in zip(arrivals, pattern, strict=True)
        )
        denom_a = sum((a - mean_a) ** 2 for a in arrivals) ** 0.5
        denom_p = sum((p - mean_p) ** 2 for p in pattern) ** 0.5

        if denom_a * denom_p == 0:
            return 0.0

        return num / (denom_a * denom_p)

    def clear(self) -> None:
        """Clear all recorded samples."""
        self.samples.clear()


class SessionProbe:
    """Probe for session ID enumeration attacks.

    Tests whether session IDs are predictable or can be enumerated.
    """

    def __init__(self, attacker: MITMAttacker) -> None:
        """Initialize the session probe.

        Args:
            attacker: MITM attacker instance for sending probes.
        """
        self.attacker = attacker
        self.probed_ids: set[bytes] = set()
        self.valid_ids: set[bytes] = set()

    def probe_session_id(
        self,
        session_id: bytes,
        dst_ip: str,
        dst_port: int = NOMAD_PORT,
    ) -> None:
        """Send a probe frame with a guessed session ID.

        The frame will have an invalid AEAD tag and should be silently
        dropped. If the implementation responds differently to valid vs
        invalid session IDs, that's a vulnerability.

        Args:
            session_id: Session ID to probe.
            dst_ip: Target IP address.
            dst_port: Target port.
        """
        frame = self.attacker.forge_frame(
            session_id=session_id,
            nonce_counter=0,
        )
        self.attacker.inject_frame(frame, dst_ip=dst_ip, dst_port=dst_port)
        self.probed_ids.add(session_id)

    def probe_sequential(
        self,
        base_id: bytes,
        count: int,
        dst_ip: str,
        dst_port: int = NOMAD_PORT,
    ) -> None:
        """Probe sequential session IDs from a base.

        Tests whether session IDs are sequential/predictable.

        Args:
            base_id: Starting session ID.
            count: Number of IDs to probe.
            dst_ip: Target IP address.
            dst_port: Target port.
        """
        base_int = int.from_bytes(base_id, "little")
        for i in range(count):
            probe_id = (base_int + i).to_bytes(6, "little")
            self.probe_session_id(probe_id, dst_ip, dst_port)

    def entropy_estimate(self, sample_ids: list[bytes]) -> float:
        """Estimate entropy of observed session IDs.

        Low entropy indicates predictable session IDs.

        Args:
            sample_ids: List of observed session IDs.

        Returns:
            Estimated bits of entropy.
        """
        if len(sample_ids) < 2:
            return 48.0  # Maximum for 6-byte ID

        # Simple heuristic: check for sequential patterns
        ints = [int.from_bytes(sid, "little") for sid in sample_ids]
        ints.sort()

        # Calculate gaps between consecutive IDs
        gaps = [ints[i] - ints[i - 1] for i in range(1, len(ints))]

        # If gaps are all 1 (sequential), entropy is very low
        if all(g == 1 for g in gaps):
            return 0.0

        # If gaps are uniform, estimate entropy from gap distribution
        mean_gap = sum(gaps) / len(gaps)
        if mean_gap < 10:
            return 8.0  # Low entropy

        # Otherwise assume reasonable entropy
        return 48.0


# Convenience function for pytest fixtures
def create_attacker(
    interface: str = "eth0",
    target_ip: str | None = None,
    target_port: int = NOMAD_PORT,
) -> MITMAttacker:
    """Create a configured MITM attacker instance.

    Args:
        interface: Network interface.
        target_ip: Target IP address.
        target_port: Target port.

    Returns:
        Configured MITMAttacker instance.
    """
    return MITMAttacker(
        interface=interface,
        target_ip=target_ip,
        target_port=target_port,
    )
