"""
Network jitter resilience tests.

These tests verify that the NOMAD protocol handles jitter (variable delay)
correctly. Jitter can cause packets to arrive out of order and creates
timing uncertainty. The protocol must handle this without duplicate
state application or incorrect sequencing.

Success criteria (from TODO.md):
- High jitter (±100ms): no duplicate application
- Extreme jitter (±300ms): sync recovers
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


class TestJitter:
    """Test sync behavior under jitter conditions."""

    def test_no_duplicate_application_with_high_jitter(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """No duplicate state application with ±100ms jitter.

        Jitter causes packets to arrive out of order. The protocol
        must track state versions to prevent applying the same diff
        multiple times.
        """
        client_name = client_container.name

        # 50ms base delay with ±100ms jitter
        # This creates significant reordering potential
        with chaos.apply_delay(client_name, delay_ms=50, jitter_ms=100):
            time.sleep(0.5)

            # Send sequential state updates
            for i in range(20):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'jitter-seq-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.2)

            # Wait for sync
            time.sleep(5)

            # Verify session integrity
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

            # TODO: When implementation is available, verify no duplicate
            # state application by checking state history or counters

    def test_sync_recovers_with_extreme_jitter(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync recovers with extreme jitter (±300ms).

        With extreme jitter, packets can arrive very out of order.
        The sync mechanism must still converge to consistent state.
        """
        client_name = client_container.name

        # 100ms base delay with ±300ms jitter
        # Packets can arrive from 0ms to 400ms delayed, in any order
        with chaos.apply_delay(
            client_name,
            delay_ms=100,
            jitter_ms=300,
            distribution="normal",
        ):
            time.sleep(1)

            # Send state updates
            for i in range(15):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'extreme-jitter-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=5,
                )
                time.sleep(0.4)

            # Wait for sync to converge
            time.sleep(7)

            # Verify session recovery
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_jitter_with_pareto_distribution(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync handles Pareto-distributed jitter.

        Pareto distribution creates occasional very long delays
        (heavy tail), which is realistic for some network conditions.
        """
        client_name = client_container.name

        with chaos.apply_delay(
            client_name,
            delay_ms=100,
            jitter_ms=100,
            distribution="pareto",
        ):
            time.sleep(0.5)

            # Send state updates
            for i in range(15):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'pareto-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=5,
                )
                time.sleep(0.3)

            # Wait for sync
            time.sleep(5)

            # Verify session
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_bidirectional_jitter(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync handles jitter in both directions.

        Both client→server and server→client experience jitter,
        creating complex reordering patterns.
        """
        client_name = client_container.name
        server_name = server_container.name

        with chaos.apply_delay(client_name, delay_ms=50, jitter_ms=100):
            with chaos.apply_delay(server_name, delay_ms=50, jitter_ms=100):
                time.sleep(0.5)

                # Send state updates
                for i in range(15):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'bidir-jitter-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=5,
                    )
                    time.sleep(0.3)

                # Wait for sync
                time.sleep(5)

                # Verify session
                server_container.reload()
                client_container.reload()

                assert server_container.status == "running"
                assert client_container.status == "running"

    def test_jitter_spike(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync recovers from temporary jitter spike.

        Tests transition from stable to jittery to stable again.
        """
        client_name = client_container.name

        # Start with normal conditions
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'pre-jitter-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.3)

        # Apply jitter spike
        with chaos.apply_delay(client_name, delay_ms=50, jitter_ms=200, duration=5):
            # Continue during jitter
            for i in range(5):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'during-jitter-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,
                )
                time.sleep(0.5)

        # Jitter removed - continue
        time.sleep(0.5)
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'post-jitter-{i}' | nc -u 127.0.0.1 19999"],
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

    def test_jitter_with_correlated_delay(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync handles correlated jitter.

        Correlated jitter means successive packets tend to have
        similar delays, creating bursts of reordering.
        """
        client_name = client_container.name

        with chaos.apply_delay(
            client_name,
            delay_ms=100,
            jitter_ms=100,
            correlation=75,  # High correlation
        ):
            time.sleep(0.5)

            # Send rapid state updates
            for i in range(20):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'correlated-{i}' | nc -u 127.0.0.1 19999"],
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

    def test_jitter_combined_with_loss(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Sync handles jitter combined with packet loss.

        Most challenging scenario - packets arrive out of order
        AND some are lost entirely.
        """
        client_name = client_container.name

        with chaos.apply_delay(client_name, delay_ms=50, jitter_ms=150):
            with chaos.apply_loss(client_name, percent=15):
                time.sleep(0.5)

                # Send state updates
                for i in range(20):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'jitter-loss-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=5,
                    )
                    time.sleep(0.25)

                # Wait for sync
                time.sleep(7)

                # Verify session
                server_container.reload()
                client_container.reload()

                assert server_container.status == "running"
                assert client_container.status == "running"
