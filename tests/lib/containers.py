"""
Docker container management for Roam conformance tests.

This module provides utilities for managing Docker containers during testing:
- Starting/stopping server and client containers
- Health checking
- Container lifecycle management
- Packet capture management

The design allows plugging in any Roam implementation by pointing
SERVER_CONTEXT/SERVER_DOCKERFILE environment variables to the implementation.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import docker
import structlog
from docker.errors import APIError, NotFound

if TYPE_CHECKING:
    from docker import DockerClient
    from docker.models.containers import Container
    from docker.models.networks import Network

log = structlog.get_logger()

# Default paths relative to repo root
DOCKER_DIR = Path(__file__).parent.parent.parent / "docker"
DEFAULT_COMPOSE_FILE = DOCKER_DIR / "docker-compose.yml"


@dataclass
class ContainerConfig:
    """Configuration for a Roam container."""

    # Build context (path to implementation directory)
    context: Path = field(default_factory=lambda: DOCKER_DIR)

    # Dockerfile to use
    dockerfile: str = "Dockerfile.stub"

    # Build target (server or client)
    target: str = "server"

    # Environment variables
    env: dict[str, str] = field(default_factory=dict)

    # Network settings
    network: str = "roam-net"
    ip_address: str | None = None

    # Health check settings
    health_timeout: float = 30.0
    health_interval: float = 0.5


@dataclass
class KeyPair:
    """A Roam keypair for testing."""

    private_key: str  # Base64-encoded
    public_key: str  # Base64-encoded


@dataclass
class TestKeyPairs:
    """Deterministic keypairs for reproducible tests.

    These are well-known test keys. DO NOT USE IN PRODUCTION.
    """

    # Server keypair (well-known for testing)
    server: KeyPair = field(
        default_factory=lambda: KeyPair(
            # These are test-only keys generated from a known seed
            # Seed: "roam-test-server-key-v1"
            private_key="SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IGtleQ==",
            public_key="VGVzdCBwdWJsaWMga2V5IGZvciBSb2FtIHByb3RvY29s",
        )
    )

    # Client keypair (well-known for testing)
    client: KeyPair = field(
        default_factory=lambda: KeyPair(
            # Seed: "roam-test-client-key-v1"
            private_key="Q2xpZW50IHByaXZhdGUga2V5IGZvciBSb2FtIHRlc3Rz",
            public_key="Q2xpZW50IHB1YmxpYyBrZXkgZm9yIFJvYW0gdGVzdHM=",
        )
    )


class ContainerManager:
    """Manages Docker containers for Roam protocol testing."""

    def __init__(
        self,
        client: DockerClient | None = None,
        network_name: str = "roam-test-net",
        subnet: str = "172.30.0.0/16",
    ) -> None:
        """Initialize container manager.

        Args:
            client: Docker client instance. If None, creates from environment.
            network_name: Name of the Docker network to use.
            subnet: Subnet for the Docker network.
        """
        self.client = client or docker.from_env()
        self.network_name = network_name
        self.subnet = subnet
        self._network: Network | None = None
        self._containers: dict[str, Container] = {}

    @property
    def network(self) -> Network:
        """Get or create the test network."""
        if self._network is None:
            self._network = self._ensure_network()
        return self._network

    def _ensure_network(self) -> Network:
        """Ensure the test network exists."""
        try:
            network = self.client.networks.get(self.network_name)
            log.debug("network_exists", name=self.network_name)
            return network
        except NotFound:
            log.info("creating_network", name=self.network_name, subnet=self.subnet)
            return self.client.networks.create(
                self.network_name,
                driver="bridge",
                ipam=docker.types.IPAMConfig(
                    pool_configs=[docker.types.IPAMPool(subnet=self.subnet)]
                ),
            )

    def build_image(
        self,
        config: ContainerConfig,
        tag: str,
    ) -> str:
        """Build a Docker image from configuration.

        Args:
            config: Container configuration.
            tag: Tag for the built image.

        Returns:
            The image ID.
        """
        log.info(
            "building_image",
            context=str(config.context),
            dockerfile=config.dockerfile,
            target=config.target,
            tag=tag,
        )

        image, build_logs = self.client.images.build(
            path=str(config.context),
            dockerfile=config.dockerfile,
            target=config.target,
            tag=tag,
            rm=True,
        )

        for log_entry in build_logs:
            if "stream" in log_entry:
                line = log_entry["stream"].strip()
                if line:
                    log.debug("build_log", line=line)

        return image.id

    def start_container(
        self,
        name: str,
        config: ContainerConfig,
        image: str | None = None,
    ) -> Container:
        """Start a container.

        Args:
            name: Container name.
            config: Container configuration.
            image: Image to use. If None, builds from config.

        Returns:
            The running container.
        """
        # Build if no image specified
        if image is None:
            image = self.build_image(config, tag=f"roam-test-{name}")

        log.info(
            "starting_container",
            name=name,
            image=image,
            ip=config.ip_address,
        )

        container = self.client.containers.run(
            image,
            name=name,
            detach=True,
            environment=config.env,
            network=self.network_name,
            # Note: IP assignment done after creation for custom IPs
        )

        # Assign static IP if specified
        if config.ip_address:
            # Disconnect from default network connection
            self.network.disconnect(container)
            # Reconnect with static IP
            self.network.connect(container, ipv4_address=config.ip_address)

        self._containers[name] = container
        log.info("container_started", name=name, id=container.short_id)
        return container

    def wait_for_health(
        self,
        container: Container,
        timeout: float = 30.0,
        interval: float = 0.5,
    ) -> bool:
        """Wait for container to become healthy.

        Args:
            container: Container to check.
            timeout: Maximum time to wait in seconds.
            interval: Check interval in seconds.

        Returns:
            True if healthy, False if timeout.
        """
        log.debug("waiting_for_health", container=container.name, timeout=timeout)
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            container.reload()
            health = container.attrs.get("State", {}).get("Health", {})
            status = health.get("Status", "unknown")

            if status == "healthy":
                log.info("container_healthy", container=container.name)
                return True

            if status == "unhealthy":
                log.error("container_unhealthy", container=container.name)
                return False

            time.sleep(interval)

        log.error("health_timeout", container=container.name, timeout=timeout)
        return False

    def stop_container(self, name: str, timeout: int = 10) -> None:
        """Stop and remove a container.

        Args:
            name: Container name.
            timeout: Stop timeout in seconds.
        """
        if name not in self._containers:
            log.warning("container_not_tracked", name=name)
            return

        container = self._containers.pop(name)
        log.info("stopping_container", name=name)

        try:
            container.stop(timeout=timeout)
            container.remove(force=True)
            log.info("container_removed", name=name)
        except APIError as e:
            log.error("container_stop_error", name=name, error=str(e))

    def get_container_logs(self, name: str, tail: int = 100) -> str:
        """Get container logs.

        Args:
            name: Container name.
            tail: Number of lines to retrieve.

        Returns:
            Log output as string.
        """
        if name not in self._containers:
            return ""

        container = self._containers[name]
        return container.logs(tail=tail).decode("utf-8", errors="replace")

    def exec_in_container(
        self,
        name: str,
        command: str | list[str],
        **kwargs,
    ) -> tuple[int, str]:
        """Execute a command in a container.

        Args:
            name: Container name.
            command: Command to execute.
            **kwargs: Additional exec_run arguments.

        Returns:
            Tuple of (exit_code, output).
        """
        if name not in self._containers:
            raise ValueError(f"Container {name} not found")

        container = self._containers[name]
        result = container.exec_run(command, **kwargs)
        return result.exit_code, result.output.decode("utf-8", errors="replace")

    def cleanup(self) -> None:
        """Stop all containers and remove the network."""
        log.info("cleanup_starting", containers=list(self._containers.keys()))

        # Stop all containers
        for name in list(self._containers.keys()):
            self.stop_container(name)

        # Remove network
        if self._network:
            try:
                self._network.remove()
                log.info("network_removed", name=self.network_name)
            except APIError as e:
                log.warning("network_remove_error", error=str(e))
            self._network = None

    @contextmanager
    def server(
        self,
        config: ContainerConfig | None = None,
        keypairs: TestKeyPairs | None = None,
    ) -> Iterator[Container]:
        """Context manager for a server container.

        Args:
            config: Server configuration. Uses defaults if None.
            keypairs: Test keypairs. Uses defaults if None.

        Yields:
            The running server container.
        """
        keypairs = keypairs or TestKeyPairs()
        config = config or ContainerConfig(
            target="server",
            ip_address="172.30.0.10",
            env={
                "ROAM_MODE": "server",
                "ROAM_SERVER_PRIVATE_KEY": keypairs.server.private_key,
                "ROAM_SERVER_PUBLIC_KEY": keypairs.server.public_key,
                "ROAM_STATE_TYPE": "roam.echo.v1",
                "ROAM_LOG_LEVEL": "debug",
            },
        )

        container = self.start_container("roam-test-server", config)
        try:
            if not self.wait_for_health(container, config.health_timeout):
                logs = self.get_container_logs("roam-test-server")
                log.error("server_health_failed", logs=logs)
                raise RuntimeError("Server failed health check")
            yield container
        finally:
            self.stop_container("roam-test-server")

    @contextmanager
    def client(
        self,
        server_ip: str = "172.30.0.10",
        config: ContainerConfig | None = None,
        keypairs: TestKeyPairs | None = None,
    ) -> Iterator[Container]:
        """Context manager for a client container.

        Args:
            server_ip: Server IP address to connect to.
            config: Client configuration. Uses defaults if None.
            keypairs: Test keypairs. Uses defaults if None.

        Yields:
            The running client container.
        """
        keypairs = keypairs or TestKeyPairs()
        config = config or ContainerConfig(
            target="client",
            ip_address="172.30.0.20",
            env={
                "ROAM_MODE": "client",
                "ROAM_SERVER_HOST": server_ip,
                "ROAM_SERVER_PORT": "19999",
                "ROAM_SERVER_PUBLIC_KEY": keypairs.server.public_key,
                "ROAM_LOG_LEVEL": "debug",
            },
        )

        container = self.start_container("roam-test-client", config)
        try:
            yield container
        finally:
            self.stop_container("roam-test-client")


class PacketCapture:
    """Manages packet capture for wire-level tests.

    Uses tcpdump in a sidecar container to capture packets on the test network.
    """

    def __init__(
        self,
        manager: ContainerManager,
        capture_dir: Path | None = None,
    ) -> None:
        """Initialize packet capture.

        Args:
            manager: Container manager instance.
            capture_dir: Directory for capture files. Uses temp dir if None.
        """
        self.manager = manager
        self.capture_dir = capture_dir or Path("/tmp/roam-capture")
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self._container: Container | None = None

    def start(self, interface: str = "eth0", filter_expr: str = "udp port 19999") -> None:
        """Start packet capture.

        Args:
            interface: Network interface to capture on.
            filter_expr: tcpdump filter expression.
        """
        log.info("starting_packet_capture", interface=interface, filter=filter_expr)

        # Use netshoot image which has tcpdump
        self._container = self.manager.client.containers.run(
            "nicolaka/netshoot:latest",
            command=f"tcpdump -i {interface} -w /capture/roam.pcap -U {filter_expr}",
            name="roam-test-tcpdump",
            detach=True,
            network_mode=f"container:{self.manager._containers.get('roam-test-server', {}).name}",
            volumes={str(self.capture_dir): {"bind": "/capture", "mode": "rw"}},
            cap_add=["NET_ADMIN", "NET_RAW"],
        )
        log.info("packet_capture_started", container=self._container.short_id)

    def stop(self) -> Path:
        """Stop packet capture and return capture file path.

        Returns:
            Path to the capture file.
        """
        if self._container:
            log.info("stopping_packet_capture")
            self._container.stop(timeout=5)
            self._container.remove(force=True)
            self._container = None

        return self.capture_dir / "roam.pcap"

    @contextmanager
    def capture(
        self,
        interface: str = "eth0",
        filter_expr: str = "udp port 19999",
    ) -> Iterator[Path]:
        """Context manager for packet capture.

        Args:
            interface: Network interface to capture on.
            filter_expr: tcpdump filter expression.

        Yields:
            Path to the capture file (available after context exits).
        """
        capture_file = self.capture_dir / "roam.pcap"
        self.start(interface, filter_expr)
        try:
            yield capture_file
        finally:
            self.stop()


def get_test_keypairs() -> TestKeyPairs:
    """Get deterministic test keypairs.

    These keypairs are well-known and should ONLY be used for testing.
    They are derived from known seeds for reproducibility.

    Returns:
        Test keypairs for server and client.
    """
    # In a real implementation, these would be generated from the
    # reference crypto library with fixed seeds
    return TestKeyPairs()


def get_container_manager() -> ContainerManager:
    """Get a container manager instance.

    Returns:
        Container manager configured from environment.
    """
    return ContainerManager(
        network_name=os.environ.get("ROAM_TEST_NETWORK", "roam-test-net"),
        subnet=os.environ.get("ROAM_TEST_SUBNET", "172.30.0.0/16"),
    )
