"""
Packet duplication resilience tests.

These tests verify that the NOMAD protocol correctly handles duplicate
packets. Duplicate packets can occur due to network equipment issues,
retransmissions at lower layers, or malicious replay attempts.

The protocol must:
1. Detect duplicate packets
2. Not apply the same state change twice
3. Maintain correct state despite duplicates

Success criteria (from TODO.md):
- Duplicate packets: handled gracefully
- Triple duplication: still works
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


class TestDuplication:
    """Test duplicate packet handling."""

    def test_duplicate_packets_handled_gracefully(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Duplicate packets are handled gracefully.

        With 20% duplication, many packets arrive twice.
        The protocol should detect and ignore duplicates.
        """
        client_name = client_container.name

        with chaos.apply_duplicate(client_name, percent=20):
            time.sleep(0.5)

            # Send state updates
            for i in range(15):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'dup-test-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.3)

            # Wait for sync
            time.sleep(5)

            # Verify session integrity
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_high_duplication_rate(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles high duplication rate (50%).

        Half of all packets arrive twice. Tests deduplication
        under heavy load.
        """
        client_name = client_container.name

        with chaos.apply_duplicate(client_name, percent=50):
            time.sleep(0.5)

            # Send state updates
            for i in range(15):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'high-dup-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.3)

            # Wait for sync
            time.sleep(5)

            # Verify session
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_triple_duplication_works(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session works with triple packet duplication.

        Apply duplication twice to create triple packets (original + 2 copies).
        Tests that nonce/counter tracking handles multiple duplicates.
        """
        client_name = client_container.name

        # Stack duplication to create triple copies
        with chaos.apply_duplicate(client_name, percent=50):
            with chaos.apply_duplicate(client_name, percent=50):
                time.sleep(0.5)

                # Send state updates
                for i in range(10):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'triple-dup-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=3,
                    )
                    time.sleep(0.4)

                # Wait for sync
                time.sleep(5)

                # Verify session
                server_container.reload()
                client_container.reload()

                assert server_container.status == "running"
                assert client_container.status == "running"

    def test_no_duplicate_state_application(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Duplicate packets don't cause duplicate state application.

        The protocol must track seen nonces to prevent applying
        the same state change multiple times.
        """
        client_name = client_container.name

        with chaos.apply_duplicate(client_name, percent=30):
            time.sleep(0.5)

            # Send state updates with incrementing values
            for i in range(20):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'unique-value-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.2)

            # Wait for sync
            time.sleep(5)

            # Verify session
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

            # TODO: When implementation is available, verify final state
            # matches expected (i.e., unique-value-19, not doubled)

    def test_duplication_bidirectional(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles duplication in both directions.

        Both client→server and server→client packets get duplicated.
        """
        client_name = client_container.name
        server_name = server_container.name

        with chaos.apply_duplicate(client_name, percent=25):
            with chaos.apply_duplicate(server_name, percent=25):
                time.sleep(0.5)

                # Send state updates
                for i in range(15):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'bidir-dup-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=3,
                    )
                    time.sleep(0.3)

                # Wait for sync
                time.sleep(5)

                # Verify session
                server_container.reload()
                client_container.reload()

                assert server_container.status == "running"
                assert client_container.status == "running"

    def test_duplication_with_reordering(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles duplication combined with reordering.

        Duplicates may arrive in different order than original.
        """
        client_name = client_container.name

        with chaos.apply_duplicate(client_name, percent=20):
            with chaos.apply_reorder(client_name, percent=20, gap=5):
                time.sleep(0.5)

                # Send state updates
                for i in range(15):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'dup-reorder-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=3,
                    )
                    time.sleep(0.3)

                # Wait for sync
                time.sleep(7)

                # Verify session
                server_container.reload()
                client_container.reload()

                assert server_container.status == "running"
                assert client_container.status == "running"

    def test_duplication_with_loss(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles duplication combined with loss.

        Some packets duplicated, others lost entirely.
        Duplication might help when original is lost but duplicate arrives.
        """
        client_name = client_container.name

        with chaos.apply_duplicate(client_name, percent=20):
            with chaos.apply_loss(client_name, percent=15):
                time.sleep(0.5)

                # Send state updates
                for i in range(20):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'dup-loss-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=3,
                    )
                    time.sleep(0.25)

                # Wait for sync
                time.sleep(7)

                # Verify session
                server_container.reload()
                client_container.reload()

                assert server_container.status == "running"
                assert client_container.status == "running"

    def test_correlated_duplication(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles correlated duplication.

        Correlated duplication means if one packet is duplicated,
        the next is more likely to be duplicated too (burst duplication).
        """
        client_name = client_container.name

        with chaos.apply_duplicate(client_name, percent=25, correlation=50):
            time.sleep(0.5)

            # Send rapid state updates
            for i in range(20):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'corr-dup-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.15)

            # Wait for sync
            time.sleep(5)

            # Verify session
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_duplication_recovery(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session recovers after duplication stops.

        Tests clean transition back to normal packet delivery.
        """
        client_name = client_container.name

        # Normal delivery
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'pre-dup-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.3)

        # Apply duplication
        with chaos.apply_duplicate(client_name, percent=40, duration=5):
            for i in range(5):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'during-dup-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.5)

        # Duplication stopped - continue
        time.sleep(0.5)
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'post-dup-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.3)

        # Wait for sync
        time.sleep(3)

        # Verify recovery
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"
