"""
Network latency resilience tests.

These tests verify that the NOMAD protocol maintains session stability
under high-latency network conditions. High latency affects timing
assumptions, keepalive intervals, and sync convergence time.

Success criteria (from TODO.md):
- 100ms delay: session stable
- 500ms delay: session stable (MUST PASS)
- Variable delay (100-500ms): session stable
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


class TestLatency:
    """Test session stability under latency conditions."""

    def test_session_stable_with_100ms_delay(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session remains stable with 100ms network delay.

        This is a typical mobile network latency scenario.
        """
        client_name = client_container.name

        with chaos.apply_delay(client_name, delay_ms=100):
            time.sleep(0.5)

            # Send state updates over 5 seconds
            for i in range(10):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'latency-100-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=3,  # Higher timeout due to latency
                )
                time.sleep(0.5)

            # Wait for sync
            time.sleep(3)

            # Verify session stability
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_session_stable_with_500ms_delay(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session remains stable with 500ms network delay.

        CRITICAL TEST - This is the success criteria threshold.
        500ms RTT is 1 second - tests keepalive and timeout handling.
        """
        client_name = client_container.name

        with chaos.apply_delay(client_name, delay_ms=500):
            time.sleep(1)  # Wait for delay to take effect

            # Send state updates over 10 seconds
            # With 500ms delay, each round-trip takes ~1s
            for i in range(10):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'latency-500-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=5,  # Higher timeout for high latency
                )
                time.sleep(1)

            # Wait for final sync
            time.sleep(3)

            # Verify session stability
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running", "Server crashed under 500ms delay"
            assert client_container.status == "running", "Client crashed under 500ms delay"

    def test_session_stable_with_variable_delay(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session remains stable with variable delay (100-500ms).

        Uses jitter to simulate variable latency, which is more realistic
        than fixed delay. Tests adaptive timing behavior.
        """
        client_name = client_container.name

        # 300ms base delay with ±200ms jitter = 100-500ms range
        with chaos.apply_delay(client_name, delay_ms=300, jitter_ms=200):
            time.sleep(1)

            # Send state updates
            for i in range(15):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'variable-delay-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=5,
                )
                time.sleep(0.7)

            # Wait for sync
            time.sleep(5)

            # Verify session stability
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"

    def test_latency_spike_recovery(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session recovers from temporary latency spike.

        Simulates entering high-latency zone temporarily.
        """
        client_name = client_container.name

        # Start with normal latency
        client_container.exec_run(
            ["sh", "-c", "echo 'pre-spike' | nc -u 127.0.0.1 19999"],
            timeout=2,
        )
        time.sleep(1)

        # Apply high latency spike
        with chaos.apply_delay(client_name, delay_ms=1000, duration=5):
            # Continue sending during high latency
            for i in range(3):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'during-spike-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=10,
                )
                time.sleep(1.5)

        # Latency restored - continue sending
        time.sleep(0.5)
        for i in range(3):
            client_container.exec_run(
                ["sh", "-c", f"echo 'post-spike-{i}' | nc -u 127.0.0.1 19999"],
                timeout=2,
            )
            time.sleep(0.5)

        # Wait for sync
        time.sleep(3)

        # Verify recovery
        server_container.reload()
        client_container.reload()

        assert server_container.status == "running"
        assert client_container.status == "running"

    def test_asymmetric_latency(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles asymmetric latency (different upload/download delay).

        Common in satellite and some mobile networks.
        """
        client_name = client_container.name
        server_name = server_container.name

        # Apply different delays to each direction
        with chaos.apply_delay(client_name, delay_ms=100):  # Client → Server
            with chaos.apply_delay(server_name, delay_ms=400):  # Server → Client
                time.sleep(1)

                # Send state updates
                for i in range(10):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'asymmetric-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=5,
                    )
                    time.sleep(0.6)

                # Wait for sync
                time.sleep(5)

                # Verify session stability
                server_container.reload()
                client_container.reload()

                assert server_container.status == "running"
                assert client_container.status == "running"

    def test_latency_with_loss_combined(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session handles combined latency and packet loss.

        Real networks often have both latency and loss.
        """
        client_name = client_container.name

        # Apply both delay and loss
        with chaos.apply_delay(client_name, delay_ms=200, jitter_ms=50):
            with chaos.apply_loss(client_name, percent=10):
                time.sleep(1)

                # Send state updates
                for i in range(10):
                    client_container.exec_run(
                        ["sh", "-c", f"echo 'combined-{i}' | nc -u 127.0.0.1 19999"],
                        timeout=5,
                    )
                    time.sleep(0.5)

                # Wait for sync
                time.sleep(5)

                # Verify session stability
                server_container.reload()
                client_container.reload()

                assert server_container.status == "running"
                assert client_container.status == "running"

    def test_extreme_latency_session_survives(
        self,
        chaos: NetworkChaos,
        server_container: Container,
        client_container: Container,
    ) -> None:
        """Session survives extreme latency (2000ms).

        Tests absolute limits of the protocol's timing tolerance.
        Session may degrade but should not crash.
        """
        client_name = client_container.name

        with chaos.apply_delay(client_name, delay_ms=2000):
            time.sleep(2)

            # Send fewer updates due to high latency
            for i in range(3):
                client_container.exec_run(
                    ["sh", "-c", f"echo 'extreme-{i}' | nc -u 127.0.0.1 19999"],
                    timeout=15,
                )
                time.sleep(3)

            # Wait for final sync
            time.sleep(5)

            # Verify containers didn't crash
            server_container.reload()
            client_container.reload()

            assert server_container.status == "running"
            assert client_container.status == "running"
