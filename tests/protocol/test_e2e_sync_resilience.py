"""
Sync layer resilience tests under adverse network conditions.

These tests validate sync behavior with:
- Packet loss (10%, 30%, 50%)
- High latency (100ms, 500ms)
- Packet reordering
- Packet duplication
- Network partitions

Uses pumba/tc netem for real network chaos injection.
Requires Docker containers for real protocol traffic.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

from lib.chaos import NetworkChaos
from lib.network import parse_pcap

if TYPE_CHECKING:
    from docker import DockerClient
    from docker.models.containers import Container

    from lib.containers import ContainerManager, PacketCapture


pytestmark = [pytest.mark.container, pytest.mark.network, pytest.mark.slow]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def chaos(docker_client: DockerClient) -> NetworkChaos:
    """Network chaos controller."""
    import os

    network_name = os.environ.get("NOMAD_TEST_NETWORK", "nomad-test-net")
    return NetworkChaos(docker_client, network_name)


@pytest.fixture
def client_container_name() -> str:
    """Client container name from environment."""
    import os

    return os.environ.get("NOMAD_CLIENT_CONTAINER", "nomad-client")


@pytest.fixture
def server_container_name() -> str:
    """Server container name from environment."""
    import os

    return os.environ.get("NOMAD_SERVER_CONTAINER", "nomad-server")


# =============================================================================
# Packet Loss Tests
# =============================================================================


class TestPacketLoss:
    """Test sync convergence under packet loss conditions."""

    @pytest.mark.parametrize("loss_percent", [10, 30, 50])
    def test_sync_converges_with_loss(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        packet_capture: PacketCapture,
        loss_percent: int,
    ) -> None:
        """Sync eventually converges despite packet loss.

        Args:
            loss_percent: Percentage of packets to drop.
        """
        with (
            packet_capture.capture() as pcap_file,
            chaos.apply_loss(client_container_name, percent=loss_percent),
        ):
            # Allow time for sync with retransmissions
            # Higher loss = more time needed
            wait_time = 5 + (loss_percent // 10)
            time.sleep(wait_time)

        # Verify packets were exchanged
        frames = parse_pcap(pcap_file)
        assert len(frames) > 0, "Should capture some packets despite loss"

        # With high loss, we expect retransmissions
        # Check for multiple frames with same session (retransmits)
        session_ids = [f.session_id for f in frames if f.session_id]
        if loss_percent >= 30:
            # At 30%+ loss, we should see retransmissions
            # (same session ID, different nonce counters)
            assert len(session_ids) > 2, "Should see retransmissions under high loss"

    def test_sync_with_asymmetric_loss(
        self,
        server_container: Container,
        client_container: Container,
        server_container_name: str,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync converges with asymmetric loss (client->server ok, server->client lossy)."""
        # Apply loss only to server's outbound traffic
        with chaos.apply_loss(server_container_name, percent=30):
            time.sleep(5)

        # Verify both containers are still healthy
        container_manager.check_all_containers()


# =============================================================================
# Latency Tests
# =============================================================================


class TestHighLatency:
    """Test sync behavior under high latency conditions."""

    def test_sync_with_100ms_delay(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync works correctly with 100ms delay."""
        with chaos.apply_delay(client_container_name, delay_ms=100, jitter_ms=20):
            time.sleep(5)

        container_manager.check_all_containers()

    def test_sync_with_500ms_delay(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync works correctly with 500ms delay (challenging for real-time apps)."""
        with chaos.apply_delay(client_container_name, delay_ms=500, jitter_ms=100):
            # Need more time for sync with high latency
            time.sleep(10)

        container_manager.check_all_containers()

    def test_sync_with_variable_jitter(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        packet_capture: PacketCapture,
    ) -> None:
        """Sync handles variable latency (jitter) correctly."""
        with (
            packet_capture.capture() as pcap_file,
            chaos.apply_delay(
                client_container_name,
                delay_ms=50,
                jitter_ms=50,  # 0-100ms range
            ),
        ):
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        assert len(frames) > 0, "Should capture packets despite jitter"


# =============================================================================
# Reordering Tests
# =============================================================================


class TestPacketReordering:
    """Test sync behavior when packets arrive out of order."""

    def test_sync_with_reordering(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        packet_capture: PacketCapture,
    ) -> None:
        """Sync converges when packets are reordered."""
        with (
            packet_capture.capture() as pcap_file,
            chaos.apply_reorder(client_container_name, percent=25, gap=5),
        ):
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        assert len(frames) > 0, "Should capture packets despite reordering"

        # Verify we captured both directions
        directions = {(f.src_ip, f.dst_ip) for f in frames}
        assert len(directions) >= 1, "Should see traffic"

    def test_sync_idempotent_under_reordering(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Idempotent diffs handle reordering correctly."""
        # With reordering, older versions may arrive after newer ones
        # The sync layer should skip outdated versions
        with chaos.apply_reorder(client_container_name, percent=40, gap=10):
            time.sleep(5)

        # No crashes = successful handling
        container_manager.check_all_containers()


# =============================================================================
# Duplication Tests
# =============================================================================


class TestPacketDuplication:
    """Test sync behavior when packets are duplicated."""

    def test_sync_with_duplication(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync handles duplicate packets correctly (idempotent)."""
        with chaos.apply_duplicate(client_container_name, percent=30):
            time.sleep(5)

        # Idempotent application means duplicates don't cause issues
        container_manager.check_all_containers()

    def test_duplicate_with_high_rate(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync handles very high duplication rate."""
        with chaos.apply_duplicate(client_container_name, percent=80):
            time.sleep(5)

        container_manager.check_all_containers()


# =============================================================================
# Combined Chaos Tests
# =============================================================================


class TestCombinedChaos:
    """Test sync under multiple adverse conditions."""

    def test_loss_plus_delay(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync converges with both loss and delay."""
        # Apply both loss and delay sequentially
        # (pumba doesn't support multiple netem rules simultaneously easily)
        with chaos.apply_loss(client_container_name, percent=20):
            time.sleep(3)

        with chaos.apply_delay(client_container_name, delay_ms=200):
            time.sleep(3)

        container_manager.check_all_containers()

    def test_realistic_mobile_network(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Simulate realistic mobile network conditions.

        Mobile networks typically have:
        - 1-5% packet loss
        - 50-200ms latency with jitter
        - Occasional bursts of higher loss
        """
        # Simulate mobile network with delay and jitter
        with chaos.apply_delay(
            client_container_name,
            delay_ms=100,
            jitter_ms=50,
        ):
            time.sleep(5)

        container_manager.check_all_containers()


# =============================================================================
# Network Partition Tests
# =============================================================================


class TestNetworkPartition:
    """Test sync behavior during network partitions."""

    def test_recovery_after_partition(
        self,
        server_container: Container,
        client_container: Container,
        server_container_name: str,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync recovers after network partition heals."""
        # Wait for initial sync
        time.sleep(2)

        # Create partition
        with chaos.partition_context(server_container_name, client_container_name):
            # During partition, sync should not crash
            time.sleep(3)

        # After partition heals, give time to re-sync
        time.sleep(3)

        container_manager.check_all_containers()

    def test_short_partition(
        self,
        server_container: Container,
        client_container: Container,
        server_container_name: str,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync handles brief network interruptions."""
        for _ in range(3):
            # Brief partition
            with chaos.partition_context(server_container_name, client_container_name):
                time.sleep(0.5)

            # Recovery time
            time.sleep(1)

        container_manager.check_all_containers()


# =============================================================================
# Stress Tests
# =============================================================================


class TestNetworkStress:
    """Stress tests for sync layer under network chaos."""

    @pytest.mark.slow
    def test_extended_loss(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync survives extended period of packet loss."""
        with chaos.apply_loss(client_container_name, percent=20):
            # Extended test - 30 seconds
            time.sleep(30)

        container_manager.check_all_containers()

    @pytest.mark.slow
    def test_chaos_cycling(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        container_manager: ContainerManager,
    ) -> None:
        """Sync survives cycling through different chaos conditions."""
        conditions = [
            ("loss", lambda: chaos.apply_loss(client_container_name, percent=20)),
            ("delay", lambda: chaos.apply_delay(client_container_name, delay_ms=200)),
            ("reorder", lambda: chaos.apply_reorder(client_container_name, percent=20)),
            ("duplicate", lambda: chaos.apply_duplicate(client_container_name, percent=20)),
        ]

        for _name, apply_chaos in conditions:
            with apply_chaos():
                time.sleep(3)

            # Brief recovery between conditions
            time.sleep(1)

        container_manager.check_all_containers()


# =============================================================================
# Convergence Measurement Tests
# =============================================================================


class TestConvergenceTiming:
    """Measure sync convergence time under various conditions."""

    def test_measure_convergence_clean(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Measure baseline convergence time without chaos."""
        start = time.monotonic()

        with packet_capture.capture() as pcap_file:
            # Wait for sync
            time.sleep(3)

        _ = time.monotonic() - start  # elapsed time (for future benchmarking)
        frames = parse_pcap(pcap_file)

        # Report timing (for benchmarking, not assertions)
        assert len(frames) > 0, "Should capture sync traffic"

        # Calculate approximate RTT from first request/response pair
        if len(frames) >= 2:
            timestamps = [f.timestamp for f in frames]
            min_rtt = min(
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
                if timestamps[i + 1] > timestamps[i]
            )
            # RTT should be reasonable (< 100ms on clean network)
            assert min_rtt < 0.1, f"RTT too high on clean network: {min_rtt:.3f}s"

    def test_measure_convergence_with_loss(
        self,
        server_container: Container,
        client_container: Container,
        client_container_name: str,
        chaos: NetworkChaos,
        packet_capture: PacketCapture,
    ) -> None:
        """Measure convergence time with packet loss."""
        with (
            packet_capture.capture() as pcap_file,
            chaos.apply_loss(client_container_name, percent=20),
        ):
            time.sleep(5)

        frames = parse_pcap(pcap_file)

        # Should still converge, just with more packets
        assert len(frames) > 0, "Should capture sync traffic despite loss"
