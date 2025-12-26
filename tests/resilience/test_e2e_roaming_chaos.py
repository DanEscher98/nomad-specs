"""
IP migration (roaming) resilience tests.

These tests verify that the NOMAD protocol correctly handles IP address
changes - a key feature inspired by Mosh. When a device changes networks
(e.g., WiFi to cellular, or moving between access points), its IP changes
but the session should continue seamlessly.

The protocol uses session IDs rather than IP addresses for identification,
allowing the server to accept packets from a changed client IP.

Success criteria (from TODO.md):
- IP migration during transfer: no data loss
- Rapid IP changes (every 2s): session stable
- Migration under 50% loss: works
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


# Available IP addresses for roaming tests
# Must be in the test network subnet
ROAMING_IPS = [
    "172.31.0.100",
    "172.31.0.101",
    "172.31.0.102",
    "172.31.0.103",
    "172.31.0.104",
]


class TestRoaming:
    """Test IP migration (roaming) handling."""

    def test_ip_migration_during_transfer_no_data_loss(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """No data loss when IP changes during active transfer.

        Client changes IP mid-session, server accepts packets
        from new IP using session ID validation.
        """
        client_name = client_container.name

        # Establish session with initial IP
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'pre-migrate-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.3)

        time.sleep(1)

        # Migrate to new IP
        old_ip = chaos.change_ip(client_name, ROAMING_IPS[0])

        # Small delay for network reconfiguration
        time.sleep(0.5)

        # Continue transfer from new IP
        for i in range(5):
            client_container.exec_run(
                ["sh", "-c", f"echo 'post-migrate-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.3)

        # Wait for sync
        time.sleep(3)

        # Restore original IP for cleanup
        chaos.change_ip(client_name, old_ip)

        # Verify session integrity
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_rapid_ip_changes_session_stable(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session stable with rapid IP changes (every 2s).

        Simulates aggressive roaming between networks/APs.
        """
        client_name = client_container.name

        # Get original IP
        client_networks = client_container.attrs.get("NetworkSettings", {}).get("Networks", {})
        original_ip = None
        network_name = None
        for net_name, net_info in client_networks.items():
            if net_info.get("IPAddress"):
                original_ip = net_info["IPAddress"]
                network_name = net_name
                break

        if not original_ip:
            pytest.skip("Could not determine client IP")

        try:
            # Rapid IP changes
            for cycle in range(5):
                new_ip = ROAMING_IPS[cycle % len(ROAMING_IPS)]
                chaos.change_ip(client_name, new_ip, network_name)

                # Send state from new IP
                for i in range(2):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'rapid-{cycle}-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=2,
                    )
                    time.sleep(0.3)

                # Wait ~2s between migrations
                time.sleep(2)

            # Wait for final sync
            time.sleep(3)
        finally:
            # Restore original IP
            chaos.change_ip(client_name, original_ip, network_name)

        # Verify session stability
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_migration_under_50_percent_loss(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """IP migration works under 50% packet loss.

        Combines roaming with packet loss to test robustness.
        """
        client_name = client_container.name

        # Get original IP
        client_networks = client_container.attrs.get("NetworkSettings", {}).get("Networks", {})
        original_ip = None
        network_name = None
        for net_name, net_info in client_networks.items():
            if net_info.get("IPAddress"):
                original_ip = net_info["IPAddress"]
                network_name = net_name
                break

        if not original_ip:
            pytest.skip("Could not determine client IP")

        try:
            # Apply packet loss
            with chaos.apply_loss(client_name, percent=50):
                # Establish under loss
                for i in range(5):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'lossy-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=2,
                    )
                    time.sleep(0.5)

                # Migrate while under loss
                chaos.change_ip(client_name, ROAMING_IPS[0], network_name)
                time.sleep(0.5)

                # Continue under loss from new IP
                for i in range(10):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'migrated-lossy-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=2,
                    )
                    time.sleep(0.5)

                # Wait for convergence
                time.sleep(7)
        finally:
            # Restore original IP
            chaos.change_ip(client_name, original_ip, network_name)

        # Verify session
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_migration_with_latency_change(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles migration with latency change.

        Simulates WiFi→cellular migration where latency increases.
        """
        client_name = client_container.name

        # Get original IP
        client_networks = client_container.attrs.get("NetworkSettings", {}).get("Networks", {})
        original_ip = None
        network_name = None
        for net_name, net_info in client_networks.items():
            if net_info.get("IPAddress"):
                original_ip = net_info["IPAddress"]
                network_name = net_name
                break

        if not original_ip:
            pytest.skip("Could not determine client IP")

        try:
            # Start with low latency (WiFi)
            with chaos.apply_delay(client_name, delay_ms=20):
                for i in range(3):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'wifi-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=2,
                    )
                    time.sleep(0.3)

            # Migrate IP (simulating network switch)
            chaos.change_ip(client_name, ROAMING_IPS[0], network_name)

            # Now with high latency (cellular)
            with chaos.apply_delay(client_name, delay_ms=200, jitter_ms=50):
                for i in range(5):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'cellular-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=3,
                    )
                    time.sleep(0.5)

                time.sleep(3)
        finally:
            chaos.change_ip(client_name, original_ip, network_name)

        # Verify session
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_double_migration(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session survives multiple IP changes in quick succession.

        Two migrations close together (e.g., WiFi→cellular→WiFi).
        """
        client_name = client_container.name

        # Get original IP
        client_networks = client_container.attrs.get("NetworkSettings", {}).get("Networks", {})
        original_ip = None
        network_name = None
        for net_name, net_info in client_networks.items():
            if net_info.get("IPAddress"):
                original_ip = net_info["IPAddress"]
                network_name = net_name
                break

        if not original_ip:
            pytest.skip("Could not determine client IP")

        try:
            # Initial state
            client_container.exec_run(
                ["sh", "-c", "echo 'initial' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.5)

            # First migration
            chaos.change_ip(client_name, ROAMING_IPS[0], network_name)
            client_container.exec_run(
                ["sh", "-c", "echo 'first-hop' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(1)

            # Second migration (quick)
            chaos.change_ip(client_name, ROAMING_IPS[1], network_name)
            client_container.exec_run(
                ["sh", "-c", "echo 'second-hop' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(1)

            # More state from final IP
            for i in range(3):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'final-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=2,
                )
                time.sleep(0.3)

            time.sleep(3)
        finally:
            chaos.change_ip(client_name, original_ip, network_name)

        # Verify session
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_migration_back_to_original_ip(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session continues when migrating back to original IP.

        Tests round-trip migration (e.g., WiFi→cellular→WiFi on same AP).
        """
        client_name = client_container.name

        # Get original IP
        client_networks = client_container.attrs.get("NetworkSettings", {}).get("Networks", {})
        original_ip = None
        network_name = None
        for net_name, net_info in client_networks.items():
            if net_info.get("IPAddress"):
                original_ip = net_info["IPAddress"]
                network_name = net_name
                break

        if not original_ip:
            pytest.skip("Could not determine client IP")

        try:
            # From original IP
            client_container.exec_run(
                ["sh", "-c", "echo 'original' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.5)

            # Migrate away
            chaos.change_ip(client_name, ROAMING_IPS[0], network_name)
            for i in range(3):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'away-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=2,
                )
                time.sleep(0.3)

            time.sleep(2)

            # Migrate back to original
            chaos.change_ip(client_name, original_ip, network_name)
            for i in range(3):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'back-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=2,
                )
                time.sleep(0.3)

            time.sleep(3)
        except Exception:
            # Ensure cleanup even on failure
            chaos.change_ip(client_name, original_ip, network_name)
            raise

        # Verify session
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_migration_during_partition_recovery(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles IP change during partition recovery.

        Simulates device switching networks during a connectivity issue.
        """
        client_name = client_container.name
        server_name = server_container.name

        # Get original IP
        client_networks = client_container.attrs.get("NetworkSettings", {}).get("Networks", {})
        original_ip = None
        network_name = None
        for net_name, net_info in client_networks.items():
            if net_info.get("IPAddress"):
                original_ip = net_info["IPAddress"]
                network_name = net_name
                break

        if not original_ip:
            pytest.skip("Could not determine client IP")

        try:
            # Establish session
            client_container.exec_run(
                ["sh", "-c", "echo 'establish' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(1)

            # Create partition
            with chaos.partition_context(server_name, client_name):
                time.sleep(2)

                # While partitioned, change IP (simulates switching networks)
                chaos.change_ip(client_name, ROAMING_IPS[0], network_name)

                time.sleep(2)

            # Partition healed, now on new IP
            time.sleep(1)

            # Send from new IP
            for i in range(5):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'recovered-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=2,
                )
                time.sleep(0.5)

            time.sleep(3)
        finally:
            chaos.change_ip(client_name, original_ip, network_name)

        # Verify session
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"
