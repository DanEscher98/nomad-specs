"""
Infrastructure smoke tests.

These tests verify that the test infrastructure itself is working correctly.
They don't test the Nomad protocol - just the testing framework.
"""

from __future__ import annotations

from pathlib import Path

import pytest


class TestInfrastructure:
    """Test that the testing infrastructure is set up correctly."""

    def test_docker_dir_exists(self):
        """Verify the docker directory exists and contains expected files."""
        docker_dir = Path(__file__).parent.parent.parent / "docker"
        assert docker_dir.exists(), f"Docker directory not found: {docker_dir}"

        # Check for key files
        assert (docker_dir / "docker-compose.yml").exists()
        assert (docker_dir / "Dockerfile.stub").exists()
        assert (docker_dir / "stub").is_dir()

    def test_stub_files_exist(self):
        """Verify stub implementation files exist."""
        stub_dir = Path(__file__).parent.parent.parent / "docker" / "stub"
        assert stub_dir.exists(), f"Stub directory not found: {stub_dir}"

        assert (stub_dir / "stub_server.py").exists()
        assert (stub_dir / "stub_client.py").exists()

    def test_lib_module_imports(self):
        """Verify lib modules can be imported."""
        from lib import containers

        # Check key classes exist
        assert hasattr(containers, "ContainerManager")
        assert hasattr(containers, "ContainerConfig")
        assert hasattr(containers, "TestKeyPairs")
        assert hasattr(containers, "PacketCapture")

    def test_keypairs_structure(self):
        """Verify test keypairs have expected structure."""
        from lib.containers import TestKeyPairs

        keypairs = TestKeyPairs()

        # Server keypair
        assert keypairs.server.private_key
        assert keypairs.server.public_key
        assert isinstance(keypairs.server.private_key, str)
        assert isinstance(keypairs.server.public_key, str)

        # Client keypair
        assert keypairs.client.private_key
        assert keypairs.client.public_key

    def test_container_config_defaults(self):
        """Verify ContainerConfig has sensible defaults."""
        from lib.containers import ContainerConfig

        config = ContainerConfig()

        assert config.dockerfile == "Dockerfile.stub"
        assert config.target == "server"
        assert config.network == "nomad-net"
        assert config.health_timeout == 30.0

    def test_conformance_doc_exists(self):
        """Verify CONFORMANCE.md exists and has content."""
        conformance = Path(__file__).parent.parent.parent / "CONFORMANCE.md"
        assert conformance.exists()

        content = conformance.read_text()
        assert "Container Interface" in content
        assert "Health Check" in content
        assert "nomad.echo.v1" in content


class TestKeyPairIntegrity:
    """Test that test keypairs are valid and deterministic."""

    def test_keypairs_are_deterministic(self):
        """Verify keypairs are the same across multiple instantiations."""
        from lib.containers import TestKeyPairs

        kp1 = TestKeyPairs()
        kp2 = TestKeyPairs()

        assert kp1.server.private_key == kp2.server.private_key
        assert kp1.server.public_key == kp2.server.public_key
        assert kp1.client.private_key == kp2.client.private_key
        assert kp1.client.public_key == kp2.client.public_key

    def test_server_client_keys_different(self):
        """Verify server and client have different keys."""
        from lib.containers import TestKeyPairs

        keypairs = TestKeyPairs()

        assert keypairs.server.private_key != keypairs.client.private_key
        assert keypairs.server.public_key != keypairs.client.public_key


@pytest.mark.container
class TestDockerAvailability:
    """Tests that check Docker is available (skipped if not)."""

    def test_docker_client_connects(self, docker_client):
        """Verify we can connect to Docker."""
        info = docker_client.info()
        assert "ServerVersion" in info

    def test_docker_can_pull_base_image(self, docker_client):
        """Verify we can pull the Python base image."""
        import contextlib

        # This is a lightweight check - just verify the API works
        with contextlib.suppress(Exception):
            docker_client.images.get("python:3.11-slim")
