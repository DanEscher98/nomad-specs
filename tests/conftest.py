"""
Pytest configuration and fixtures for Nomad Protocol conformance tests.

This module provides:
- Container fixtures for server/client lifecycle
- Packet capture fixtures for wire-level tests
- Test keypair fixtures for reproducible cryptographic tests
- Network simulation fixtures for resilience tests

All fixtures follow the contracts defined in .octopus/contracts/interfaces.md
"""

from __future__ import annotations

import os
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
            f"Copy docker/.env.example to docker/.env and configure it."
        )
    return value

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
def container_manager(docker_client) -> Iterator[ContainerManager]:
    """Container manager for test lifecycle.

    Creates an isolated network for tests and manages container lifecycle.
    Cleans up all containers and network after tests complete.

    Required environment variables:
        NOMAD_TEST_NETWORK: Docker network name for tests
        NOMAD_TEST_SUBNET: Subnet for test network (CIDR notation)
    """
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


# =============================================================================
# Function-scoped fixtures (fresh for each test)
# =============================================================================


@pytest.fixture
def server_container(
    container_manager: ContainerManager,
    test_keypairs: TestKeyPairs,
) -> Iterator[Container]:
    """Running server container with health check passed.

    Starts a fresh server container for each test.
    Container is stopped and removed after the test.

    Yields:
        Container: The running, healthy server container.

    Raises:
        RuntimeError: If server fails health check.
    """
    with container_manager.server(keypairs=test_keypairs) as container:
        yield container


@pytest.fixture
def client_container(
    container_manager: ContainerManager,
    server_container: Container,
    test_keypairs: TestKeyPairs,
) -> Iterator[Container]:
    """Running client container connected to server.

    Depends on server_container to ensure server is running first.

    Yields:
        Container: The running client container.
    """
    # Get server IP from environment
    server_ip = require_env("NOMAD_TEST_SERVER_IP")

    with container_manager.client(
        server_ip=server_ip,
        keypairs=test_keypairs,
    ) as container:
        yield container


@pytest.fixture
def packet_capture(
    container_manager: ContainerManager,
    tmp_path: Path,
) -> Iterator[PacketCapture]:
    """Packet capture for wire-level tests.

    Provides a PacketCapture instance that can capture traffic
    on the test network using tcpdump.

    Yields:
        PacketCapture: Capture manager for starting/stopping capture.
    """
    capture = PacketCapture(
        manager=container_manager,
        capture_dir=tmp_path / "capture",
    )
    yield capture


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
    config.addinivalue_line(
        "markers", "container: tests requiring docker containers"
    )
    config.addinivalue_line(
        "markers", "network: tests requiring network access"
    )
    config.addinivalue_line(
        "markers", "adversarial: security/fuzzing tests"
    )
    config.addinivalue_line(
        "markers", "interop: cross-implementation tests"
    )


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

    # Check Docker status
    try:
        import docker

        client = docker.from_env()
        info = client.info()
        lines.append(f"  Docker: {info.get('ServerVersion', 'unknown')}")
    except Exception as e:
        lines.append(f"  Docker: unavailable ({e})")

    return lines
