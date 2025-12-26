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

# Run E2E tests against running containers (requires docker-up first)
test-e2e: install
    set -a && source docker/.env && set +a && cd tests && uv run pytest protocol/test_e2e_handshake.py -v

# Quick E2E: start containers, test, stop
e2e: docker-up test-e2e docker-down

# Run unit tests (no containers needed)
test-unit: install
    cd tests && uv run pytest unit/ -v

# Run protocol tests (requires containers)
test-protocol: install docker-up
    cd tests && uv run pytest protocol/ -v

# Run wire-level tests (requires containers + capture)
test-wire: install docker-up-capture
    cd tests && uv run pytest wire/ -v

# Run adversarial tests (E2E - requires containers)
test-adversarial: install
    set -a && source docker/.env && set +a && cd tests && uv run pytest adversarial/ -v -m adversarial

# Run resilience tests (network chaos)
test-resilience: install docker-up
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

# Run a specific test file (without .env - for unit tests)
test-file file: install
    cd tests && uv run pytest {{ file }} -v

# Run a specific E2E test file (with .env)
test-e2e-file file: install
    set -a && source docker/.env && set +a && cd tests && uv run pytest {{ file }} -v

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
