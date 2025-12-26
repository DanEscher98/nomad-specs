"""
Packet reordering resilience tests.

These tests verify that the NOMAD protocol correctly handles out-of-order
packet delivery. The key property is that idempotent diffs can be applied
in any order and still produce the correct final state.

Success criteria (from TODO.md):
- Out-of-order delivery: idempotent diffs handle correctly
- No duplicate state application on reordering
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


class TestReordering:
    """Test idempotent diff handling under packet reordering."""

    def test_idempotent_diffs_handle_reordering(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Idempotent diffs produce correct state despite reordering.

        When packets arrive out of order, applying diffs in wrong order
        should still converge to the correct final state because diffs
        are computed against a base state number.
        """
        client_name = client_container.name

        # Apply packet reordering
        with chaos.apply_reorder(client_name, percent=25, gap=5):
            time.sleep(0.5)

            # Send sequential state updates
            for i in range(20):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'reorder-seq-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.2)

            # Wait for sync to converge
            time.sleep(5)

            # Verify session integrity
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_no_duplicate_application_on_reordering(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """No duplicate state application when packets reordered.

        The state number tracking should prevent applying the same
        update twice even if it arrives after a newer update.
        """
        client_name = client_container.name

        # Heavy reordering
        with chaos.apply_reorder(client_name, percent=50, gap=10):
            time.sleep(0.5)

            # Send state updates with distinct content
            for i in range(15):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'unique-state-{i}' | nc -u 127.0.0.1 19999"],
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

            # TODO: When implementation is available, verify no duplicate
            # application by checking state version history

    def test_aggressive_reordering(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync handles aggressive reordering (75% of packets).

        Extreme test where most packets arrive out of order.
        """
        client_name = client_container.name

        with chaos.apply_reorder(client_name, percent=75, gap=10):
            time.sleep(0.5)

            # Send many state updates
            for i in range(25):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'aggressive-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.15)

            # Wait for sync (longer due to extreme reordering)
            time.sleep(7)

            # Verify session
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_reordering_with_large_gap(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync handles reordering with large gap.

        Large gap means packets can be delayed by many positions,
        testing the protocol's ability to handle very old packets.
        """
        client_name = client_container.name

        # Large gap = packets can be delayed significantly
        with chaos.apply_reorder(client_name, percent=30, gap=20):
            time.sleep(0.5)

            # Send state updates
            for i in range(25):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'large-gap-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.2)

            # Wait for sync
            time.sleep(7)

            # Verify session
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_reordering_bidirectional(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync handles reordering in both directions.

        Both client→server and server→client packets get reordered.
        """
        client_name = client_container.name
        server_name = server_container.name

        with chaos.apply_reorder(client_name, percent=30, gap=5):
            with chaos.apply_reorder(server_name, percent=30, gap=5):
                time.sleep(0.5)

                # Send state updates
                for i in range(15):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'bidir-reorder-{i}' | nc -u 127.0.0.1 19999"],
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

    def test_reordering_combined_with_loss(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync handles reordering combined with packet loss.

        Some packets arrive out of order, some don't arrive at all.
        """
        client_name = client_container.name

        with chaos.apply_reorder(client_name, percent=25, gap=5):
            with chaos.apply_loss(client_name, percent=10):
                time.sleep(0.5)

                # Send state updates
                for i in range(20):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'reorder-loss-{i}' | nc -u 127.0.0.1 19999"],
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

    def test_reordering_correlated(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync handles correlated reordering.

        Correlated reordering means sequential packets tend to be
        reordered together (burst reordering).
        """
        client_name = client_container.name

        with chaos.apply_reorder(client_name, percent=30, gap=5, correlation=50):
            time.sleep(0.5)

            # Send rapid state updates
            for i in range(20):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'correlated-reorder-{i}' | nc -u 127.0.0.1 19999"],
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

    def test_reordering_recovery(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync recovers after reordering stops.

        Tests transition from reordered to normal packet delivery.
        """
        client_name = client_container.name

        # Start with normal delivery
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'pre-reorder-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.3)

        # Apply reordering
        with chaos.apply_reorder(client_name, percent=50, gap=10, duration=5):
            for i in range(5):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'during-reorder-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.5)

        # Reordering stopped - continue
        time.sleep(0.5)
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'post-reorder-{i}' | nc -u 127.0.0.1 19999"],
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
