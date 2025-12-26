"""
Docker container management for Nomad conformance tests.

This module provides utilities for managing Docker containers during testing:
- Starting/stopping server and client containers
- Health checking
- Container lifecycle management
- Packet capture management

The design allows plugging in any Nomad implementation by pointing
SERVER_CONTEXT/SERVER_DOCKERFILE environment variables to the implementation.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import docker
import structlog
from docker.errors import APIError, NotFound

if TYPE_CHECKING:
    from docker import DockerClient
    from docker.models.containers import Container
    from docker.models.networks import Network


def require_env(name: str) -> str:
    """Get required environment variable or fail with clear error.

    Args:
        name: Environment variable name.

    Returns:
        The environment variable value.

    Raises:
        RuntimeError: If the variable is not set.
    """
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Required environment variable {name} is not set.\n"
            f"Copy docker/.env.example to docker/.env and source it."
        )
    return value


log = structlog.get_logger()


class ContainerCrashError(Exception):
    """Raised when a container crashes during a test.

    This exception provides detailed information about the crash
    including container logs for debugging.
    """

    def __init__(self, container_name: str, exit_code: int, logs: str) -> None:
        """Initialize crash error.

        Args:
            container_name: Name of the crashed container.
            exit_code: Exit code from the container.
            logs: Last N lines of container logs.
        """
        self.container_name = container_name
        self.exit_code = exit_code
        self.logs = logs
        super().__init__(
            f"Container '{container_name}' crashed with exit code {exit_code}\nLast logs:\n{logs}"
        )


# Default paths relative to repo root
DOCKER_DIR = Path(__file__).parent.parent.parent / "docker"
DEFAULT_COMPOSE_FILE = DOCKER_DIR / "docker-compose.yml"


@dataclass
class ContainerConfig:
    """Configuration for a Nomad container."""

    # Build context (path to implementation directory)
    context: Path = field(default_factory=lambda: DOCKER_DIR)

    # Dockerfile to use
    dockerfile: str = "Dockerfile.stub"

    # Build target (server or client)
    target: str = "server"

    # Environment variables
    env: dict[str, str] = field(default_factory=dict)

    # Network settings
    network: str = "nomad-net"
    ip_address: str | None = None

    # Health check settings
    health_timeout: float = 30.0
    health_interval: float = 0.5


@dataclass
class KeyPair:
    """A Nomad keypair for testing."""

    private_key: str  # Base64-encoded
    public_key: str  # Base64-encoded


@dataclass
class TestKeyPairs:
    """Deterministic keypairs for reproducible tests.

    These are well-known test keys. DO NOT USE IN PRODUCTION.
    """

    # Server keypair (well-known for testing)
    # Generated from Rust implementation with TEST_MODE=1
    # These are deterministic test keys - DO NOT USE IN PRODUCTION
    server: KeyPair = field(
        default_factory=lambda: KeyPair(
            # Rust test key: seed bytes 0x00-0x1F with high bit set
            private_key="SAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHn8=",
            public_key="gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=",
        )
    )

    # Client keypair (well-known for testing)
    # Generated from Rust implementation with TEST_MODE=1
    client: KeyPair = field(
        default_factory=lambda: KeyPair(
            # Client uses different seed for distinct keypair
            private_key="IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            public_key="Wv2lKXBgODc0LhcVOhNLRRMBFxEGFhQSEw8ODAwKCAY=",
        )
    )


class ContainerManager:
    """Manages Docker containers for Nomad protocol testing."""

    def __init__(
        self,
        client: DockerClient | None = None,
        network_name: str | None = None,
        subnet: str | None = None,
    ) -> None:
        """Initialize container manager.

        Args:
            client: Docker client instance. If None, creates from environment.
            network_name: Name of the Docker network. If None, reads from NOMAD_TEST_NETWORK.
            subnet: Subnet for the Docker network. If None, reads from NOMAD_TEST_SUBNET.

        Required environment variables (if not passed as arguments):
            NOMAD_TEST_NETWORK: Docker network name for tests
            NOMAD_TEST_SUBNET: Subnet for test network (CIDR notation)
        """
        self._docker: DockerClient = client or docker.from_env()
        self.network_name = network_name or require_env("NOMAD_TEST_NETWORK")
        self.subnet = subnet or require_env("NOMAD_TEST_SUBNET")
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
            network = self._docker.networks.get(self.network_name)
            log.debug("network_exists", name=self.network_name)
            return network
        except NotFound:
            log.info("creating_network", name=self.network_name, subnet=self.subnet)
            return self._docker.networks.create(
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

        image, build_logs = self._docker.images.build(
            path=str(config.context),
            dockerfile=config.dockerfile,
            target=config.target,
            tag=tag,
            rm=True,
        )

        for log_entry in build_logs:
            if isinstance(log_entry, dict) and "stream" in log_entry:
                stream = log_entry.get("stream")
                if isinstance(stream, str):
                    line = stream.strip()
                    if line:
                        log.debug("build_log", line=line)

        image_id: str = image.id  # type: ignore[assignment]
        return image_id

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
            image = self.build_image(config, tag=f"nomad-test-{name}")

        log.info(
            "starting_container",
            name=name,
            image=image,
            ip=config.ip_address,
        )

        container = self._docker.containers.run(
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

    def check_container_health(self, name: str) -> None:
        """Check if container is still running, raise if crashed.

        This should be called periodically during E2E tests to detect
        container crashes early and provide meaningful error messages.

        Args:
            name: Container name to check.

        Raises:
            ContainerCrashError: If the container has exited unexpectedly.
        """
        container = self._containers.get(name)
        if not container:
            return

        container.reload()
        status = container.status

        if status == "exited":
            exit_code = container.attrs["State"]["ExitCode"]
            logs = self.get_container_logs(name, tail=50)
            log.error(
                "container_crashed",
                name=name,
                exit_code=exit_code,
            )
            raise ContainerCrashError(name, exit_code, logs)

    def check_all_containers(self) -> None:
        """Check health of all managed containers.

        Raises:
            ContainerCrashError: If any container has crashed.
        """
        for name in self._containers:
            self.check_container_health(name)

    def exec_in_container(
        self,
        name: str,
        command: str | list[str],
        **kwargs: Any,
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
            config: Server configuration. Uses defaults from env if None.
            keypairs: Test keypairs. Uses defaults if None.

        Required environment variables (if config is None):
            NOMAD_TEST_SERVER_IP: Server IP address in test network
            NOMAD_STATE_TYPE: State type for sync layer
            NOMAD_LOG_LEVEL: Logging verbosity
            NOMAD_PORT: UDP port for protocol
            NOMAD_SERVER_CONTAINER: Container name for server

        Yields:
            The running server container.
        """
        keypairs = keypairs or TestKeyPairs()
        container_name = require_env("NOMAD_SERVER_CONTAINER")
        config = config or ContainerConfig(
            target="server",
            ip_address=require_env("NOMAD_TEST_SERVER_IP"),
            env={
                "NOMAD_MODE": "server",
                "NOMAD_SERVER_PRIVATE_KEY": keypairs.server.private_key,
                "NOMAD_SERVER_PUBLIC_KEY": keypairs.server.public_key,
                "NOMAD_STATE_TYPE": require_env("NOMAD_STATE_TYPE"),
                "NOMAD_LOG_LEVEL": require_env("NOMAD_LOG_LEVEL"),
                "NOMAD_BIND_ADDR": f"0.0.0.0:{require_env('NOMAD_PORT')}",
            },
        )

        container = self.start_container(container_name, config)
        try:
            if not self.wait_for_health(container, config.health_timeout):
                logs = self.get_container_logs(container_name)
                log.error("server_health_failed", logs=logs)
                raise RuntimeError("Server failed health check")
            yield container
        finally:
            self.stop_container(container_name)

    @contextmanager
    def client(
        self,
        server_ip: str | None = None,
        config: ContainerConfig | None = None,
        keypairs: TestKeyPairs | None = None,
    ) -> Iterator[Container]:
        """Context manager for a client container.

        Args:
            server_ip: Server IP address to connect to. If None, reads from env.
            config: Client configuration. Uses defaults from env if None.
            keypairs: Test keypairs. Uses defaults if None.

        Required environment variables (if not passed as arguments):
            NOMAD_TEST_SERVER_IP: Server IP to connect to
            NOMAD_TEST_CLIENT_IP: Client IP address in test network
            NOMAD_PORT: UDP port for protocol
            NOMAD_LOG_LEVEL: Logging verbosity
            NOMAD_CLIENT_CONTAINER: Container name for client

        Yields:
            The running client container.
        """
        keypairs = keypairs or TestKeyPairs()
        server_ip = server_ip or require_env("NOMAD_TEST_SERVER_IP")
        container_name = require_env("NOMAD_CLIENT_CONTAINER")
        config = config or ContainerConfig(
            target="client",
            ip_address=require_env("NOMAD_TEST_CLIENT_IP"),
            env={
                "NOMAD_MODE": "client",
                "NOMAD_SERVER_HOST": server_ip,
                "NOMAD_SERVER_PORT": require_env("NOMAD_PORT"),
                "NOMAD_SERVER_PUBLIC_KEY": keypairs.server.public_key,
                "NOMAD_LOG_LEVEL": require_env("NOMAD_LOG_LEVEL"),
            },
        )

        container = self.start_container(container_name, config)
        try:
            yield container
        finally:
            self.stop_container(container_name)


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
        self.capture_dir = capture_dir or Path("/tmp/nomad-capture")
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self._container: Container | None = None

    def start(
        self,
        interface: str | None = None,
        filter_expr: str | None = None,
    ) -> None:
        """Start packet capture.

        Args:
            interface: Network interface to capture on. If None, reads from NOMAD_TEST_INTERFACE.
            filter_expr: tcpdump filter expression. If None, uses "udp port $NOMAD_PORT".

        Required environment variables (if not passed as arguments):
            NOMAD_TEST_INTERFACE: Network interface for capture
            NOMAD_PORT: UDP port for filter expression
            NOMAD_SERVER_CONTAINER: Server container to attach to
            NOMAD_TCPDUMP_CONTAINER: Container name for tcpdump
        """
        interface = interface or require_env("NOMAD_TEST_INTERFACE")
        filter_expr = filter_expr or f"udp port {require_env('NOMAD_PORT')}"
        server_container = require_env("NOMAD_SERVER_CONTAINER")
        tcpdump_container = require_env("NOMAD_TCPDUMP_CONTAINER")

        log.info("starting_packet_capture", interface=interface, filter=filter_expr)

        # Use netshoot image which has tcpdump
        server = self.manager._containers.get(server_container)
        if not server:
            raise RuntimeError(f"Server container '{server_container}' not running")

        self._container = self.manager._docker.containers.run(
            "nicolaka/netshoot:latest",
            command=f"tcpdump -i {interface} -w /capture/nomad.pcap -U {filter_expr}",
            name=tcpdump_container,
            detach=True,
            network_mode=f"container:{server.name}",
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

        return self.capture_dir / "nomad.pcap"

    @contextmanager
    def capture(
        self,
        interface: str | None = None,
        filter_expr: str | None = None,
    ) -> Iterator[Path]:
        """Context manager for packet capture.

        Args:
            interface: Network interface to capture on. If None, reads from env.
            filter_expr: tcpdump filter expression. If None, reads from env.

        Yields:
            Path to the capture file (available after context exits).
        """
        capture_file = self.capture_dir / "nomad.pcap"
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

    Required environment variables:
        NOMAD_TEST_NETWORK: Docker network name for tests
        NOMAD_TEST_SUBNET: Subnet for test network (CIDR notation)

    Returns:
        Container manager configured from environment.
    """
    return ContainerManager(
        network_name=require_env("NOMAD_TEST_NETWORK"),
        subnet=require_env("NOMAD_TEST_SUBNET"),
    )
