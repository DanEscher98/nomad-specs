"""
Pytest configuration and fixtures for Nomad Protocol conformance tests.

This module provides:
- Container fixtures for server/client lifecycle
- Packet capture fixtures for wire-level tests
- Test keypair fixtures for reproducible cryptographic tests
- Network simulation fixtures for resilience tests

Two modes are supported:

1. External mode (for E2E with pre-built images):
   - Set NOMAD_EXTERNAL_CONTAINERS=1
   - Start containers first: cd docker && docker compose up -d
   - Fixtures connect to already-running containers
   - Stop containers after: docker compose down

2. Managed mode (for testing test infrastructure):
   - Fixtures build and manage container lifecycle
   - Requires all NOMAD_* env vars to be set

All fixtures follow the contracts defined in .octopus/contracts/interfaces.md
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import structlog

from lib.containers import (
    ContainerConfig,
    ContainerManager,
    PacketCapture,
    TestKeyPairs,
    get_test_keypairs,
)


def require_env(name: str, default: str | None = None) -> str:
    """Get required environment variable or fail with clear error.

    Args:
        name: Environment variable name.
        default: Default value if not set (None means required).

    Returns:
        The environment variable value.

    Raises:
        RuntimeError: If the variable is not set and no default.
    """
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(
            f"Required environment variable {name} is not set.\n"
            f"Copy docker/.env.example to docker/.env and configure it."
        )
    return value


def is_external_mode() -> bool:
    """Check if using external (pre-running) containers."""
    return os.environ.get("NOMAD_EXTERNAL_CONTAINERS", "").lower() in ("1", "true", "yes")


def wait_for_port(host: str, port: int, timeout: float = 30.0) -> bool:
    """Wait for a TCP port to become available.

    Args:
        host: Host to connect to.
        port: Port number.
        timeout: Maximum time to wait.

    Returns:
        True if port is available, False if timeout.
    """
    import time

    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.5)
    return False


if TYPE_CHECKING:
    from docker.models.containers import Container

# Configure structlog for tests
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
)
log = structlog.get_logger()


# =============================================================================
# Session-scoped fixtures (shared across all tests)
# =============================================================================


@pytest.fixture(scope="session")
def docker_client():
    """Docker client for container operations.

    Session-scoped to reuse connection across all tests.
    """
    import docker

    return docker.from_env()


@pytest.fixture(scope="session")
def test_keypairs() -> TestKeyPairs:
    """Deterministic keypairs for reproducible tests.

    These are well-known test keys that should NEVER be used in production.
    They enable reproducible cryptographic tests across runs and implementations.

    Returns:
        TestKeyPairs with server and client keypairs.
    """
    return get_test_keypairs()


@pytest.fixture(scope="session")
def container_manager(docker_client) -> Iterator[ContainerManager | None]:
    """Container manager for test lifecycle.

    In external mode (NOMAD_EXTERNAL_CONTAINERS=1), returns None since
    containers are managed externally via docker-compose.

    In managed mode, creates an isolated network for tests and manages
    container lifecycle. Cleans up all containers and network after tests.

    Required environment variables (managed mode only):
        NOMAD_TEST_NETWORK: Docker network name for tests
        NOMAD_TEST_SUBNET: Subnet for test network (CIDR notation)
    """
    if is_external_mode():
        log.info("external_mode", msg="Using pre-running containers")
        yield None
        return

    manager = ContainerManager(
        client=docker_client,
        network_name=require_env("NOMAD_TEST_NETWORK"),
        subnet=require_env("NOMAD_TEST_SUBNET"),
    )

    # Ensure network exists
    _ = manager.network

    yield manager

    # Cleanup after all tests
    manager.cleanup()


@pytest.fixture(scope="session")
def server_address() -> tuple[str, int]:
    """Server address for E2E tests.

    Returns the server's (host, port) for connecting.
    Works in both external and managed modes.

    In external mode: Uses NOMAD_SERVER_HOST (default: 172.28.0.10) and port 19999
    In managed mode: Uses NOMAD_TEST_SERVER_IP

    Returns:
        Tuple of (host, port).
    """
    if is_external_mode():
        host = require_env("NOMAD_SERVER_HOST", "172.28.0.10")
        port = int(require_env("NOMAD_PORT", "19999"))
    else:
        host = require_env("NOMAD_TEST_SERVER_IP")
        port = int(require_env("NOMAD_PORT"))
    return (host, port)


@pytest.fixture(scope="session")
def server_public_key() -> str:
    """Server's public key for handshake.

    Returns the server's Curve25519 public key (base64-encoded).
    Uses the well-known test key by default.

    Returns:
        Base64-encoded public key.
    """
    # Default is the Rust implementation test key
    return require_env("NOMAD_SERVER_PUBLIC_KEY", "gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=")


# =============================================================================
# Function-scoped fixtures (fresh for each test)
# =============================================================================


@pytest.fixture
def server_container(
    container_manager: ContainerManager | None,
    test_keypairs: TestKeyPairs,
    docker_client,
) -> Iterator[Container | None]:
    """Running server container with health check passed.

    In external mode: Returns the pre-running container (or None if not found).
    In managed mode: Starts a fresh server container for each test.

    Yields:
        Container: The running, healthy server container (or None in external mode).

    Raises:
        RuntimeError: If server fails health check (managed mode only).
    """
    if is_external_mode():
        # In external mode, try to get the existing container
        try:
            container = docker_client.containers.get("nomad-server")
            yield container
        except Exception:
            # Container may not exist if running tests outside Docker
            yield None
        return

    if container_manager is None:
        yield None
        return

    with container_manager.server(keypairs=test_keypairs) as container:
        yield container


@pytest.fixture
def client_container(
    container_manager: ContainerManager | None,
    server_container: Container | None,
    test_keypairs: TestKeyPairs,
    docker_client,
) -> Iterator[Container | None]:
    """Running client container connected to server.

    In external mode: Returns the pre-running container (or None if not found).
    In managed mode: Starts a fresh client container for each test.

    Depends on server_container to ensure server is running first.

    Yields:
        Container: The running client container (or None in external mode).
    """
    if is_external_mode():
        # In external mode, try to get the existing container
        try:
            container = docker_client.containers.get("nomad-client")
            yield container
        except Exception:
            yield None
        return

    if container_manager is None:
        yield None
        return

    # Get server IP from environment
    server_ip = require_env("NOMAD_TEST_SERVER_IP")

    with container_manager.client(
        server_ip=server_ip,
        keypairs=test_keypairs,
    ) as container:
        yield container


@pytest.fixture
def packet_capture(
    container_manager: ContainerManager | None,
    tmp_path: Path,
) -> Iterator[PacketCapture | None]:
    """Packet capture for wire-level tests.

    Provides a PacketCapture instance that can capture traffic
    on the test network using tcpdump.

    In external mode, returns None (use docker-compose --profile capture).

    Yields:
        PacketCapture: Capture manager for starting/stopping capture.
    """
    if container_manager is None:
        yield None
        return

    capture = PacketCapture(
        manager=container_manager,
        capture_dir=tmp_path / "capture",
    )
    yield capture


@pytest.fixture
def udp_socket(server_address: tuple[str, int]) -> Iterator[socket.socket]:
    """UDP socket connected to the server.

    Provides a UDP socket that can send/receive packets to the server.
    Useful for E2E tests that need to send raw protocol messages.

    Yields:
        socket.socket: UDP socket connected to server.
    """
    host, port = server_address
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    sock.connect((host, port))
    yield sock
    sock.close()


# =============================================================================
# Configuration fixtures
# =============================================================================


@pytest.fixture
def server_config(test_keypairs: TestKeyPairs) -> ContainerConfig:
    """Server container configuration from environment.

    Required environment variables:
        NOMAD_TEST_SERVER_IP: Server IP address in test network
        NOMAD_STATE_TYPE: State type for sync layer
        NOMAD_LOG_LEVEL: Logging verbosity

    Returns:
        ContainerConfig: Configuration for starting a server.
    """
    return ContainerConfig(
        target="server",
        ip_address=require_env("NOMAD_TEST_SERVER_IP"),
        env={
            "NOMAD_MODE": "server",
            "NOMAD_SERVER_PRIVATE_KEY": test_keypairs.server.private_key,
            "NOMAD_SERVER_PUBLIC_KEY": test_keypairs.server.public_key,
            "NOMAD_STATE_TYPE": require_env("NOMAD_STATE_TYPE"),
            "NOMAD_LOG_LEVEL": require_env("NOMAD_LOG_LEVEL"),
            "NOMAD_BIND_ADDR": f"0.0.0.0:{require_env('NOMAD_PORT')}",
        },
    )


@pytest.fixture
def client_config(test_keypairs: TestKeyPairs) -> ContainerConfig:
    """Client container configuration from environment.

    Required environment variables:
        NOMAD_TEST_SERVER_IP: Server IP to connect to
        NOMAD_TEST_CLIENT_IP: Client IP address in test network
        NOMAD_LOG_LEVEL: Logging verbosity

    Returns:
        ContainerConfig: Configuration for starting a client.
    """
    return ContainerConfig(
        target="client",
        ip_address=require_env("NOMAD_TEST_CLIENT_IP"),
        env={
            "NOMAD_MODE": "client",
            "NOMAD_SERVER_HOST": require_env("NOMAD_TEST_SERVER_IP"),
            "NOMAD_SERVER_PORT": require_env("NOMAD_PORT"),
            "NOMAD_SERVER_PUBLIC_KEY": test_keypairs.server.public_key,
            "NOMAD_LOG_LEVEL": require_env("NOMAD_LOG_LEVEL"),
        },
    )


# =============================================================================
# Marker-based fixtures
# =============================================================================


@pytest.fixture
def skip_without_docker():
    """Skip test if Docker is not available.

    Use this for tests that require Docker but should be skipped
    in environments without Docker access.
    """
    import docker
    from docker.errors import DockerException

    try:
        client = docker.from_env()
        client.ping()
    except DockerException:
        pytest.skip("Docker not available")


# =============================================================================
# Pytest hooks and configuration
# =============================================================================


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "container: tests requiring docker containers")
    config.addinivalue_line("markers", "network: tests requiring network access")
    config.addinivalue_line("markers", "adversarial: security/fuzzing tests")
    config.addinivalue_line("markers", "interop: cross-implementation tests")


def pytest_collection_modifyitems(config, items):
    """Modify collected tests based on markers and environment."""
    # Check if Docker is available
    docker_available = True
    try:
        import docker
        from docker.errors import DockerException

        client = docker.from_env()
        client.ping()
    except (ImportError, DockerException):
        docker_available = False

    skip_docker = pytest.mark.skip(reason="Docker not available")

    for item in items:
        # Skip container tests if Docker unavailable
        if not docker_available and "container" in item.keywords:
            item.add_marker(skip_docker)


def pytest_report_header(config):
    """Add information to the pytest header."""
    lines = []
    lines.append("Nomad Protocol Conformance Test Suite")
    lines.append(f"  Docker dir: {Path(__file__).parent.parent / 'docker'}")

    # Show mode
    if is_external_mode():
        lines.append("  Mode: External (using pre-running containers)")
        host = os.environ.get("NOMAD_SERVER_HOST", "172.28.0.10")
        port = os.environ.get("NOMAD_PORT", "19999")
        lines.append(f"  Server: {host}:{port}")
    else:
        lines.append("  Mode: Managed (fixtures control containers)")

    # Check Docker status
    try:
        import docker

        client = docker.from_env()
        info = client.info()
        lines.append(f"  Docker: {info.get('ServerVersion', 'unknown')}")
    except Exception as e:
        lines.append(f"  Docker: unavailable ({e})")

    return lines
