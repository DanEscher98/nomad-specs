# Nomad Protocol Conformance Test Suite
#
# Commands for running tests and managing Docker infrastructure.
#
# Usage:
#   just              # List available commands
#   just test         # Run all tests
#   just docker-up    # Start containers

# Default recipe - show help
default:
    @just --list

# =============================================================================
# Docker Infrastructure
# =============================================================================

# Build Docker images for testing
docker-build:
    docker compose -f docker/docker-compose.yml build

# Start test containers (server + client)
docker-up:
    docker compose -f docker/docker-compose.yml up -d

# Start with packet capture enabled
docker-up-capture:
    docker compose -f docker/docker-compose.yml --profile capture up -d

# Start with network chaos enabled
docker-up-chaos:
    docker compose -f docker/docker-compose.yml --profile chaos up -d

# Start with test-runner (for scapy-based tests)
docker-up-runner:
    docker compose -f docker/docker-compose.yml --profile test-runner up -d

# Run tests inside test-runner container (for network-level tests)
docker-test-runner *args:
    docker compose -f docker/docker-compose.yml exec test-runner uv run pytest {{ args }}

# Stop and remove test containers
docker-down:
    docker compose -f docker/docker-compose.yml down -v

# Show container logs
docker-logs service="nomad-server":
    docker compose -f docker/docker-compose.yml logs -f {{ service }}

# Get shell in a container
docker-shell service="nomad-server":
    docker compose -f docker/docker-compose.yml exec {{ service }} /bin/sh

# Check container health
docker-health:
    @echo "Server:"
    @curl -s http://localhost:8080/health || echo "Not healthy"
    @echo ""
    @echo "Status:"
    @curl -s http://localhost:8080/status | python3 -m json.tool 2>/dev/null || echo "No status"

# =============================================================================
# Test Commands
# =============================================================================

# Install test dependencies
install:
    cd tests && uv sync

# Run all tests
test: install
    cd tests && uv run pytest -v

# -----------------------------------------------------------------------------
# Test Categories (by infrastructure required)
# -----------------------------------------------------------------------------

# Run spec tests (Python reference codec only - NO Docker)
# Tests: unit/test_spec_*, protocol/test_spec_*, wire/test_spec_*, adversarial/test_spec_*
test-spec: install
    cd tests && uv run pytest -k "test_spec" -v

# Run server tests (Python client → Docker server)
# Tests: protocol/test_server_*, wire/test_server_*, adversarial/test_server_*
# Requires: docker-up
test-server: install
    set -a && source docker/.env && set +a && cd tests && uv run pytest -k "test_server" -v

# Run E2E tests (Docker client ↔ Docker server + packet capture)
# Tests: protocol/test_e2e_*, wire/test_e2e_*, resilience/test_e2e_*
# Requires: docker-up-capture
test-e2e: install
    cd tests && uv run pytest -k "test_e2e" -v

# Run a specific test file
test-file file: install
    cd tests && uv run pytest {{ file }} -v

# Run a specific test file with .env loaded (for server/e2e tests)
test-file-env file: install
    set -a && source docker/.env && set +a && cd tests && uv run pytest {{ file }} -v

# Quick server test: start containers, test, stop
quick-server: docker-up test-server docker-down

# Quick E2E: start containers with capture, test, stop
quick-e2e: docker-up-capture test-e2e docker-down

# -----------------------------------------------------------------------------
# Legacy/Directory-based Commands
# -----------------------------------------------------------------------------

# Run unit directory (now all test_spec_*)
test-unit: install
    cd tests && uv run pytest unit/ -v

# Run protocol directory (mix of spec/server/e2e)
test-protocol: install
    cd tests && uv run pytest protocol/ -v

# Run wire directory (mix of spec/server/e2e)
test-wire: install
    cd tests && uv run pytest wire/ -v

# Run adversarial directory (mix of spec/server)
test-adversarial: install
    cd tests && uv run pytest adversarial/ -v

# Run resilience directory (all E2E - requires chaos)
test-resilience: install docker-up-chaos
    cd tests && uv run pytest resilience/ -v --timeout=120

# Run interop tests (multiple implementations)
test-interop: install
    cd tests && uv run pytest interop/ -v

# Run tests with coverage
test-cov: install
    cd tests && uv run pytest --cov=lib --cov-report=html -v
    @echo "Coverage report: tests/htmlcov/index.html"

# Run tests in parallel
test-parallel: install
    cd tests && uv run pytest -n auto -v

# =============================================================================
# Development
# =============================================================================

# Format code
fmt:
    cd tests && uv run ruff format .

# Lint code
lint:
    cd tests && uv run ruff check .

# Type check
typecheck:
    cd tests && uv run mypy lib/

# Run all checks (format, lint, typecheck)
check: fmt lint typecheck

# Generate test vectors (placeholder - implemented by t6-vectors)
gen-vectors:
    @echo "Test vector generation is handled by t6-vectors tentacle"
    @echo "See: specs/generate_vectors.py"

# =============================================================================
# Cleanup
# =============================================================================

# Clean up everything
clean: docker-down
    rm -rf tests/.pytest_cache
    rm -rf tests/htmlcov
    rm -rf tests/.coverage
    rm -rf docker/capture/*.pcap
    find tests -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# =============================================================================
# CI/CD Helpers
# =============================================================================

# Run CI checks (no interactivity)
ci: install
    cd tests && uv run pytest -v --tb=short
    cd tests && uv run ruff check .
    cd tests && uv run mypy lib/ || true

# Build and test with a specific implementation
ci-impl impl_path:
    SERVER_CONTEXT={{ impl_path }} CLIENT_CONTEXT={{ impl_path }} just test

# =============================================================================
# Documentation
# =============================================================================

# Show conformance test instructions
help-conformance:
    @cat CONFORMANCE.md

# Show container interface
help-interface:
    @echo "Container Interface:"
    @echo ""
    @echo "Environment Variables:"
    @echo "  NOMAD_MODE=server|client"
    @echo "  NOMAD_SERVER_PRIVATE_KEY=base64"
    @echo "  NOMAD_SERVER_PUBLIC_KEY=base64"
    @echo "  NOMAD_STATE_TYPE=nomad.echo.v1"
    @echo "  NOMAD_LOG_LEVEL=debug|info|warn"
    @echo ""
    @echo "Ports:"
    @echo "  19999/udp - Nomad protocol"
    @echo "  8080/tcp  - Health check (GET /health -> 200 OK)"
