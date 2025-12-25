"""
Pytest configuration and fixtures for Roam Protocol conformance tests.

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
    """
    manager = ContainerManager(
        client=docker_client,
        network_name=os.environ.get("ROAM_TEST_NETWORK", "roam-conformance-net"),
        subnet=os.environ.get("ROAM_TEST_SUBNET", "172.31.0.0/16"),
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
    # Get server IP from the container
    server_ip = "172.31.0.10"  # Fixed IP from container manager

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
    """Default server container configuration.

    Returns:
        ContainerConfig: Configuration for starting a server.
    """
    return ContainerConfig(
        target="server",
        ip_address="172.31.0.10",
        env={
            "ROAM_MODE": "server",
            "ROAM_SERVER_PRIVATE_KEY": test_keypairs.server.private_key,
            "ROAM_SERVER_PUBLIC_KEY": test_keypairs.server.public_key,
            "ROAM_STATE_TYPE": "roam.echo.v1",
            "ROAM_LOG_LEVEL": "debug",
            "ROAM_BIND_ADDR": "0.0.0.0:19999",
        },
    )


@pytest.fixture
def client_config(test_keypairs: TestKeyPairs) -> ContainerConfig:
    """Default client container configuration.

    Returns:
        ContainerConfig: Configuration for starting a client.
    """
    return ContainerConfig(
        target="client",
        ip_address="172.31.0.20",
        env={
            "ROAM_MODE": "client",
            "ROAM_SERVER_HOST": "172.31.0.10",
            "ROAM_SERVER_PORT": "19999",
            "ROAM_SERVER_PUBLIC_KEY": test_keypairs.server.public_key,
            "ROAM_LOG_LEVEL": "debug",
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
    lines.append("Roam Protocol Conformance Test Suite")
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
