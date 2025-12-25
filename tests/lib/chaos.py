"""
Network chaos injection utilities for resilience testing.

This module provides NetworkChaos class for applying network conditions
using pumba (gaiaadm/pumba) and tc/netem. Pumba manipulates Docker
container networking to simulate adverse conditions.

Usage:
    chaos = NetworkChaos(docker_client)
    async with chaos.apply_loss("nomad-client", percent=30):
        # Test with 30% packet loss
        await sync_and_verify()

All chaos operations are container-scoped and automatically cleaned up.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

    from docker import DockerClient
    from docker.models.containers import Container

log = structlog.get_logger()

# Pumba image for chaos injection
PUMBA_IMAGE = "gaiaadm/pumba:latest"
TC_IMAGE = "gaiadocker/iproute2:latest"

# Default chaos durations
DEFAULT_CHAOS_DURATION = 300  # seconds


@dataclass
class ChaosConfig:
    """Configuration for a chaos operation."""

    # Target container name
    target: str

    # Duration in seconds (0 = until explicitly stopped)
    duration: int = DEFAULT_CHAOS_DURATION

    # Network interface to affect (inside container)
    interface: str = "eth0"


@dataclass
class LossConfig(ChaosConfig):
    """Packet loss configuration."""

    percent: int = 10  # Percentage of packets to drop
    correlation: int = 0  # Correlation with previous loss decision


@dataclass
class DelayConfig(ChaosConfig):
    """Network delay configuration."""

    delay_ms: int = 100  # Base delay in milliseconds
    jitter_ms: int = 0  # Jitter (±) in milliseconds
    correlation: int = 0  # Correlation with previous delay
    distribution: str = "normal"  # normal, pareto, paretonormal


@dataclass
class ReorderConfig(ChaosConfig):
    """Packet reordering configuration."""

    percent: int = 10  # Percentage of packets to reorder
    gap: int = 5  # Gap for reordering
    correlation: int = 0  # Correlation with previous reorder


@dataclass
class DuplicateConfig(ChaosConfig):
    """Packet duplication configuration."""

    percent: int = 10  # Percentage of packets to duplicate
    correlation: int = 0  # Correlation with previous duplicate


@dataclass
class CorruptConfig(ChaosConfig):
    """Packet corruption configuration."""

    percent: int = 1  # Percentage of packets to corrupt
    correlation: int = 0  # Correlation with previous corruption


@dataclass
class ChaosHandle:
    """Handle to a running chaos operation for cleanup."""

    container: Container
    chaos_type: str
    target: str
    started_at: float = field(default_factory=time.monotonic)

    def elapsed(self) -> float:
        """Return seconds elapsed since chaos started."""
        return time.monotonic() - self.started_at


class NetworkChaos:
    """Network chaos injection using pumba and tc/netem.

    This class provides methods to apply various network conditions to
    Docker containers for resilience testing. It uses pumba to invoke
    tc/netem commands inside target containers.

    All chaos operations can be used as context managers for automatic cleanup.
    """

    def __init__(
        self,
        client: DockerClient,
        network_name: str = "nomad-test-net",
    ) -> None:
        """Initialize chaos controller.

        Args:
            client: Docker client instance.
            network_name: Network where chaos will be applied.
        """
        self.client = client
        self.network_name = network_name
        self._active_chaos: list[ChaosHandle] = []

    def _ensure_images(self) -> None:
        """Ensure pumba and tc images are available."""
        for image in [PUMBA_IMAGE, TC_IMAGE]:
            try:
                self.client.images.get(image)
            except Exception:
                log.info("pulling_image", image=image)
                self.client.images.pull(image)

    def _run_pumba(
        self,
        chaos_type: str,
        target: str,
        args: list[str],
        duration: int = DEFAULT_CHAOS_DURATION,
        name_suffix: str = "",
    ) -> Container:
        """Run a pumba container with given arguments.

        Args:
            chaos_type: Type of chaos (for logging).
            target: Target container name.
            args: Pumba command arguments.
            duration: Chaos duration in seconds.
            name_suffix: Optional suffix for container name.

        Returns:
            Running pumba container.
        """
        self._ensure_images()

        container_name = f"chaos-{chaos_type}-{target}{name_suffix}"

        # Build pumba command
        # Format: pumba netem --duration <dur>s --tc-image <img> <netem_cmd> <args> <target>
        command = [
            "netem",
            "--duration",
            f"{duration}s",
            "--tc-image",
            TC_IMAGE,
            *args,
            target,
        ]

        log.info(
            "starting_chaos",
            chaos_type=chaos_type,
            target=target,
            duration=duration,
            command=command,
        )

        # Remove existing chaos container if present
        try:
            existing = self.client.containers.get(container_name)
            existing.remove(force=True)
        except Exception:
            pass

        container = self.client.containers.run(
            PUMBA_IMAGE,
            command=command,
            name=container_name,
            detach=True,
            volumes={"/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"}},
            # Run with host network to access Docker socket
            network_mode="host",
            auto_remove=True,
        )

        handle = ChaosHandle(
            container=container,
            chaos_type=chaos_type,
            target=target,
        )
        self._active_chaos.append(handle)

        log.info(
            "chaos_started",
            chaos_type=chaos_type,
            target=target,
            container_id=container.short_id,
        )

        return container

    def _stop_chaos(self, handle: ChaosHandle) -> None:
        """Stop a chaos operation.

        Args:
            handle: Handle to the chaos operation.
        """
        try:
            handle.container.stop(timeout=5)
        except Exception as e:
            log.debug("chaos_stop_error", error=str(e))

        with contextlib.suppress(Exception):
            # auto_remove should handle this
            handle.container.remove(force=True)

        if handle in self._active_chaos:
            self._active_chaos.remove(handle)

        log.info(
            "chaos_stopped",
            chaos_type=handle.chaos_type,
            target=handle.target,
            elapsed=handle.elapsed(),
        )

    # =========================================================================
    # Synchronous Context Managers
    # =========================================================================

    @contextmanager
    def apply_loss(
        self,
        target: str,
        percent: int = 10,
        *,
        duration: int = DEFAULT_CHAOS_DURATION,
        correlation: int = 0,
    ) -> Iterator[ChaosHandle]:
        """Apply packet loss to a container.

        Args:
            target: Target container name.
            percent: Percentage of packets to drop (0-100).
            duration: Duration in seconds.
            correlation: Correlation with previous loss decision.

        Yields:
            ChaosHandle for the running chaos operation.

        Example:
            with chaos.apply_loss("nomad-client", percent=30):
                # Test with 30% packet loss
                pass
        """
        args = ["loss", "--percent", str(percent)]
        if correlation:
            args.extend(["--correlation", str(correlation)])

        self._run_pumba("loss", target, args, duration)
        handle = self._active_chaos[-1]

        try:
            # Give netem time to apply rules
            time.sleep(0.5)
            yield handle
        finally:
            self._stop_chaos(handle)

    @contextmanager
    def apply_delay(
        self,
        target: str,
        delay_ms: int = 100,
        jitter_ms: int = 0,
        *,
        duration: int = DEFAULT_CHAOS_DURATION,
        correlation: int = 0,
        distribution: str = "normal",
    ) -> Iterator[ChaosHandle]:
        """Apply network delay to a container.

        Args:
            target: Target container name.
            delay_ms: Base delay in milliseconds.
            jitter_ms: Jitter (±) in milliseconds.
            duration: Duration in seconds.
            correlation: Correlation with previous delay.
            distribution: Delay distribution (normal, pareto, paretonormal).

        Yields:
            ChaosHandle for the running chaos operation.

        Example:
            with chaos.apply_delay("nomad-client", delay_ms=100, jitter_ms=50):
                # Test with 100ms ± 50ms delay
                pass
        """
        args = ["delay", "--time", str(delay_ms)]
        if jitter_ms:
            args.extend(["--jitter", str(jitter_ms)])
        if correlation:
            args.extend(["--correlation", str(correlation)])
        if distribution != "normal":
            args.extend(["--distribution", distribution])

        self._run_pumba("delay", target, args, duration)
        handle = self._active_chaos[-1]

        try:
            time.sleep(0.5)
            yield handle
        finally:
            self._stop_chaos(handle)

    @contextmanager
    def apply_reorder(
        self,
        target: str,
        percent: int = 10,
        gap: int = 5,
        *,
        duration: int = DEFAULT_CHAOS_DURATION,
        correlation: int = 0,
    ) -> Iterator[ChaosHandle]:
        """Apply packet reordering to a container.

        Args:
            target: Target container name.
            percent: Percentage of packets to reorder.
            gap: Gap for reordering (packets held before release).
            duration: Duration in seconds.
            correlation: Correlation with previous reorder.

        Yields:
            ChaosHandle for the running chaos operation.

        Example:
            with chaos.apply_reorder("nomad-client", percent=25, gap=5):
                # Test with 25% packet reordering
                pass
        """
        # Note: reorder requires a base delay
        args = [
            "delay",
            "--time",
            "10",  # Small base delay required for reorder
            "--reorder-percent",
            str(percent),
            "--reorder-gap",
            str(gap),
        ]
        if correlation:
            args.extend(["--reorder-correlation", str(correlation)])

        self._run_pumba("reorder", target, args, duration)
        handle = self._active_chaos[-1]

        try:
            time.sleep(0.5)
            yield handle
        finally:
            self._stop_chaos(handle)

    @contextmanager
    def apply_duplicate(
        self,
        target: str,
        percent: int = 10,
        *,
        duration: int = DEFAULT_CHAOS_DURATION,
        correlation: int = 0,
    ) -> Iterator[ChaosHandle]:
        """Apply packet duplication to a container.

        Args:
            target: Target container name.
            percent: Percentage of packets to duplicate.
            duration: Duration in seconds.
            correlation: Correlation with previous duplicate.

        Yields:
            ChaosHandle for the running chaos operation.

        Example:
            with chaos.apply_duplicate("nomad-client", percent=20):
                # Test with 20% packet duplication
                pass
        """
        args = ["duplicate", "--percent", str(percent)]
        if correlation:
            args.extend(["--correlation", str(correlation)])

        self._run_pumba("duplicate", target, args, duration)
        handle = self._active_chaos[-1]

        try:
            time.sleep(0.5)
            yield handle
        finally:
            self._stop_chaos(handle)

    @contextmanager
    def apply_corrupt(
        self,
        target: str,
        percent: int = 1,
        *,
        duration: int = DEFAULT_CHAOS_DURATION,
        correlation: int = 0,
    ) -> Iterator[ChaosHandle]:
        """Apply packet corruption to a container.

        Args:
            target: Target container name.
            percent: Percentage of packets to corrupt.
            duration: Duration in seconds.
            correlation: Correlation with previous corruption.

        Yields:
            ChaosHandle for the running chaos operation.

        Example:
            with chaos.apply_corrupt("nomad-client", percent=5):
                # Test with 5% packet corruption
                pass
        """
        args = ["corrupt", "--percent", str(percent)]
        if correlation:
            args.extend(["--correlation", str(correlation)])

        self._run_pumba("corrupt", target, args, duration)
        handle = self._active_chaos[-1]

        try:
            time.sleep(0.5)
            yield handle
        finally:
            self._stop_chaos(handle)

    def partition(
        self,
        target_a: str,
        target_b: str,
        duration_sec: float,
    ) -> None:
        """Create a network partition between two containers.

        This uses iptables to DROP all packets between the two containers.
        The partition is automatically healed after duration_sec.

        Args:
            target_a: First container name.
            target_b: Second container name.
            duration_sec: Duration of partition in seconds.
        """
        log.info(
            "creating_partition",
            target_a=target_a,
            target_b=target_b,
            duration=duration_sec,
        )

        # Get container IPs
        container_a = self.client.containers.get(target_a)
        container_b = self.client.containers.get(target_b)

        networks_a = container_a.attrs.get("NetworkSettings", {}).get("Networks", {})
        networks_b = container_b.attrs.get("NetworkSettings", {}).get("Networks", {})

        ip_a = None
        ip_b = None
        for _net_name, net_info in networks_a.items():
            if net_info.get("IPAddress"):
                ip_a = net_info["IPAddress"]
                break
        for _net_name, net_info in networks_b.items():
            if net_info.get("IPAddress"):
                ip_b = net_info["IPAddress"]
                break

        if not ip_a or not ip_b:
            raise ValueError(f"Could not find IPs: {target_a}={ip_a}, {target_b}={ip_b}")

        # Add iptables rules to drop traffic
        # Using netshoot container for iptables manipulation
        drop_cmd_a = f"iptables -A OUTPUT -d {ip_b} -j DROP"
        drop_cmd_b = f"iptables -A OUTPUT -d {ip_a} -j DROP"

        # Execute in both containers (need NET_ADMIN capability)
        container_a.exec_run(drop_cmd_a, privileged=True)
        container_b.exec_run(drop_cmd_b, privileged=True)

        log.info("partition_active", ip_a=ip_a, ip_b=ip_b)

        # Wait for partition duration
        time.sleep(duration_sec)

        # Remove iptables rules (heal partition)
        heal_cmd_a = f"iptables -D OUTPUT -d {ip_b} -j DROP"
        heal_cmd_b = f"iptables -D OUTPUT -d {ip_a} -j DROP"

        container_a.exec_run(heal_cmd_a, privileged=True)
        container_b.exec_run(heal_cmd_b, privileged=True)

        log.info("partition_healed", duration=duration_sec)

    @contextmanager
    def partition_context(
        self,
        target_a: str,
        target_b: str,
    ) -> Iterator[None]:
        """Context manager for network partition.

        The partition is healed when the context exits.

        Args:
            target_a: First container name.
            target_b: Second container name.

        Example:
            with chaos.partition_context("nomad-server", "nomad-client"):
                # Network is partitioned
                time.sleep(5)
            # Network is healed
        """
        log.info("creating_partition_context", target_a=target_a, target_b=target_b)

        container_a = self.client.containers.get(target_a)
        container_b = self.client.containers.get(target_b)

        networks_a = container_a.attrs.get("NetworkSettings", {}).get("Networks", {})
        networks_b = container_b.attrs.get("NetworkSettings", {}).get("Networks", {})

        ip_a = None
        ip_b = None
        for net_info in networks_a.values():
            if net_info.get("IPAddress"):
                ip_a = net_info["IPAddress"]
                break
        for net_info in networks_b.values():
            if net_info.get("IPAddress"):
                ip_b = net_info["IPAddress"]
                break

        if not ip_a or not ip_b:
            raise ValueError(f"Could not find IPs: {target_a}={ip_a}, {target_b}={ip_b}")

        drop_cmd_a = f"iptables -A OUTPUT -d {ip_b} -j DROP"
        drop_cmd_b = f"iptables -A OUTPUT -d {ip_a} -j DROP"
        heal_cmd_a = f"iptables -D OUTPUT -d {ip_b} -j DROP"
        heal_cmd_b = f"iptables -D OUTPUT -d {ip_a} -j DROP"

        try:
            container_a.exec_run(drop_cmd_a, privileged=True)
            container_b.exec_run(drop_cmd_b, privileged=True)
            log.info("partition_active", ip_a=ip_a, ip_b=ip_b)
            yield
        finally:
            container_a.exec_run(heal_cmd_a, privileged=True)
            container_b.exec_run(heal_cmd_b, privileged=True)
            log.info("partition_healed")

    def change_ip(
        self,
        target: str,
        new_ip: str,
        network: str | None = None,
    ) -> str:
        """Change a container's IP address to simulate roaming.

        Args:
            target: Target container name.
            new_ip: New IP address to assign.
            network: Network name (defaults to self.network_name).

        Returns:
            The previous IP address.
        """
        network = network or self.network_name

        container = self.client.containers.get(target)
        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})

        old_ip: str | None = None
        for net_name, net_info in networks.items():
            if net_name == network:
                old_ip = str(net_info.get("IPAddress", ""))
                if old_ip:
                    break

        if not old_ip:
            raise ValueError(f"Container {target} not on network {network}")

        log.info("changing_ip", target=target, old_ip=old_ip, new_ip=new_ip)

        # Disconnect and reconnect with new IP
        docker_network = self.client.networks.get(network)
        docker_network.disconnect(container)
        docker_network.connect(container, ipv4_address=new_ip)

        log.info("ip_changed", target=target, new_ip=new_ip)

        return old_ip

    def cleanup_all(self) -> None:
        """Stop all active chaos operations."""
        log.info("cleanup_all_chaos", active=len(self._active_chaos))

        for handle in list(self._active_chaos):
            self._stop_chaos(handle)

        self._active_chaos.clear()

    # =========================================================================
    # Async Context Managers
    # =========================================================================

    @asynccontextmanager
    async def async_apply_loss(
        self,
        target: str,
        percent: int = 10,
        *,
        duration: int = DEFAULT_CHAOS_DURATION,
        correlation: int = 0,
    ) -> AsyncIterator[ChaosHandle]:
        """Async version of apply_loss."""
        args = ["loss", "--percent", str(percent)]
        if correlation:
            args.extend(["--correlation", str(correlation)])

        self._run_pumba("loss", target, args, duration)
        handle = self._active_chaos[-1]

        try:
            await asyncio.sleep(0.5)
            yield handle
        finally:
            self._stop_chaos(handle)

    @asynccontextmanager
    async def async_apply_delay(
        self,
        target: str,
        delay_ms: int = 100,
        jitter_ms: int = 0,
        *,
        duration: int = DEFAULT_CHAOS_DURATION,
    ) -> AsyncIterator[ChaosHandle]:
        """Async version of apply_delay."""
        args = ["delay", "--time", str(delay_ms)]
        if jitter_ms:
            args.extend(["--jitter", str(jitter_ms)])

        self._run_pumba("delay", target, args, duration)
        handle = self._active_chaos[-1]

        try:
            await asyncio.sleep(0.5)
            yield handle
        finally:
            self._stop_chaos(handle)

    @asynccontextmanager
    async def async_partition(
        self,
        target_a: str,
        target_b: str,
        duration_sec: float,
    ) -> AsyncIterator[None]:
        """Async version of partition that yields during partition.

        Args:
            target_a: First container name.
            target_b: Second container name.
            duration_sec: Duration of partition in seconds.
        """
        container_a = self.client.containers.get(target_a)
        container_b = self.client.containers.get(target_b)

        networks_a = container_a.attrs.get("NetworkSettings", {}).get("Networks", {})
        networks_b = container_b.attrs.get("NetworkSettings", {}).get("Networks", {})

        ip_a = None
        ip_b = None
        for net_info in networks_a.values():
            if net_info.get("IPAddress"):
                ip_a = net_info["IPAddress"]
                break
        for net_info in networks_b.values():
            if net_info.get("IPAddress"):
                ip_b = net_info["IPAddress"]
                break

        if not ip_a or not ip_b:
            raise ValueError(f"Could not find IPs: {target_a}={ip_a}, {target_b}={ip_b}")

        drop_cmd_a = f"iptables -A OUTPUT -d {ip_b} -j DROP"
        drop_cmd_b = f"iptables -A OUTPUT -d {ip_a} -j DROP"
        heal_cmd_a = f"iptables -D OUTPUT -d {ip_b} -j DROP"
        heal_cmd_b = f"iptables -D OUTPUT -d {ip_a} -j DROP"

        try:
            container_a.exec_run(drop_cmd_a, privileged=True)
            container_b.exec_run(drop_cmd_b, privileged=True)
            log.info("async_partition_active", ip_a=ip_a, ip_b=ip_b)

            # Yield control during partition, then auto-heal after duration
            yield

            await asyncio.sleep(duration_sec)
        finally:
            container_a.exec_run(heal_cmd_a, privileged=True)
            container_b.exec_run(heal_cmd_b, privileged=True)
            log.info("async_partition_healed")
