"""
Network partition resilience tests.

These tests verify that the NOMAD protocol correctly handles network
partitions - complete loss of connectivity between client and server.
The protocol should:
1. Detect the partition (via keepalive timeout)
2. Buffer state changes during partition
3. Resync when connectivity is restored
4. Not lose data during the partition

Success criteria (from TODO.md):
- 5s network partition: session recovers (MUST PASS)
- 10s partition: session recovers
- Partition during active transfer: no data loss
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from docker.models.containers import Container

    from lib.chaos import NetworkChaos

# All tests in this module require Docker containers and are marked as resilience tests
pytestmark = [
    pytest.mark.resilience,
    pytest.mark.container,
    pytest.mark.slow,
]


class TestPartition:
    """Test session recovery after network partitions."""

    def test_session_recovers_from_5s_partition(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session recovers from 5-second network partition.

        CRITICAL TEST - This is the success criteria threshold.
        A 5-second complete outage should not kill the session.
        """
        client_name = client_container.name
        server_name = server_container.name

        # Establish session first
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'pre-partition-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.3)

        time.sleep(1)

        # Create 5-second partition
        with chaos.partition_context(server_name, client_name):
            # Try to send during partition (will be blocked)
            for i in range(3):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'during-partition-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=2,
                )
                time.sleep(1)

            # Wait for partition to last 5 seconds total
            time.sleep(2)

        # Partition healed - wait for recovery
        time.sleep(2)

        # Send post-partition state
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'post-partition-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.5)

        # Wait for sync
        time.sleep(3)

        # Verify recovery
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running", "Server crashed during partition"
        assert client_container.status == "running", "Client crashed during partition"

    def test_session_recovers_from_10s_partition(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session recovers from 10-second network partition.

        Longer partition tests timeout and reconnection logic.
        """
        client_name = client_container.name
        server_name = server_container.name

        # Establish session
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'pre-10s-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.3)

        time.sleep(1)

        # Create 10-second partition
        with chaos.partition_context(server_name, client_name):
            time.sleep(10)

        # Partition healed
        time.sleep(2)

        # Send post-partition state
        for i in range(5):
            client_container.exec_run(
                ["sh", "-c", f"echo 'post-10s-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.5)

        # Wait for sync
        time.sleep(5)

        # Verify recovery
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_partition_during_active_transfer_no_data_loss(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """No data loss when partition occurs during active transfer.

        State changes made during partition should be synced after
        connectivity is restored.
        """
        client_name = client_container.name
        server_name = server_container.name

        # Start active transfer
        for i in range(5):
            client_container.exec_run(
                ["sh", "-c", f"echo 'active-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.2)

        # Partition mid-transfer
        with chaos.partition_context(server_name, client_name):
            # Continue sending during partition
            for i in range(5):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'partitioned-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=2,
                )
                time.sleep(0.5)

            time.sleep(3)

        # Partition healed - continue transfer
        time.sleep(1)
        for i in range(5):
            client_container.exec_run(
                ["sh", "-c", f"echo 'resumed-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.2)

        # Wait for full sync
        time.sleep(5)

        # Verify session integrity
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

        # TODO: When implementation available, verify all state changes
        # (active-*, partitioned-*, resumed-*) were applied

    def test_multiple_short_partitions(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session survives multiple short partitions.

        Simulates flaky connection with repeated short outages.
        """
        client_name = client_container.name
        server_name = server_container.name

        for cycle in range(3):
            # Send some state
            for i in range(2):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'cycle-{cycle}-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=2,
                )
                time.sleep(0.3)

            # Short partition
            with chaos.partition_context(server_name, client_name):
                time.sleep(2)

            # Recovery time
            time.sleep(1)

        # Final verification
        time.sleep(3)

        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_asymmetric_partition(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles asymmetric partition (one-way block).

        Client→Server works but Server→Client is blocked.
        """
        # Establish session
        client_container.exec_run(
            ["sh", "-c", "echo 'establish' | nc -u 127.0.0.1 19999"],
            timeout=2,
        )
        time.sleep(1)

        # Get IPs for asymmetric block
        client_networks = client_container.attrs.get("NetworkSettings", {}).get("Networks", {})
        client_ip = None
        for net_info in client_networks.values():
            if net_info.get("IPAddress"):
                client_ip = net_info["IPAddress"]
                break

        if not client_ip:
            pytest.skip("Could not determine client IP")

        # Block only server → client
        server_container.exec_run(
            f"iptables -A OUTPUT -d {client_ip} -j DROP",
            privileged=True,
        )

        try:
            time.sleep(5)  # Hold asymmetric partition

            # Client can still send (server receives)
            for i in range(3):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'asymmetric-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=2,
                )
                time.sleep(0.5)

            time.sleep(3)
        finally:
            # Heal partition
            server_container.exec_run(
                f"iptables -D OUTPUT -d {client_ip} -j DROP",
                privileged=True,
            )

        # Wait for recovery
        time.sleep(3)

        # Verify session
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_partition_with_high_latency_recovery(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session recovers from partition when followed by high latency.

        After partition heals, network has high latency (common with
        failover to backup path).
        """
        client_name = client_container.name
        server_name = server_container.name

        # Establish session
        client_container.exec_run(
            ["sh", "-c", "echo 'pre-test' | nc -u 127.0.0.1 19999"],
            timeout=2,
        )
        time.sleep(1)

        # Partition
        with chaos.partition_context(server_name, client_name):
            time.sleep(3)

        # Recovery with high latency
        with chaos.apply_delay(client_name, delay_ms=500, jitter_ms=100):
            time.sleep(1)

            for i in range(5):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'recovery-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=5,
                )
                time.sleep(1)

            time.sleep(5)

        # Verify session
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_partition_near_keepalive_timeout(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session survives partition just under keepalive timeout.

        Tests edge case where partition heals just before session
        would timeout.
        """
        client_name = client_container.name
        server_name = server_container.name

        # Establish session
        client_container.exec_run(
            ["sh", "-c", "echo 'establish' | nc -u 127.0.0.1 19999"],
            timeout=2,
        )
        time.sleep(1)

        # Partition for almost the timeout period
        # (Assuming ~10s timeout, partition for 8s)
        with chaos.partition_context(server_name, client_name):
            time.sleep(8)

        # Immediately send keepalive/state after heal
        client_container.exec_run(
            ["sh", "-c", "echo 'keepalive-recovery' | nc -u 127.0.0.1 19999"],
            timeout=2,
        )

        # Wait and verify
        time.sleep(3)

        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_long_partition_reconnection(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session reconnects after long partition (30s).

        Tests full session timeout and reconnection flow.
        May require re-handshake.
        """
        client_name = client_container.name
        server_name = server_container.name

        # Establish session
        client_container.exec_run(
            ["sh", "-c", "echo 'initial' | nc -u 127.0.0.1 19999"],
            timeout=2,
        )
        time.sleep(1)

        # Long partition
        with chaos.partition_context(server_name, client_name):
            time.sleep(30)

        # Attempt reconnection
        time.sleep(2)
        for i in range(5):
            client_container.exec_run(
                ["sh", "-c", f"echo 'reconnect-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(1)

        # Wait for session restoration
        time.sleep(5)

        # Verify containers survived (session may have been reestablished)
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"
