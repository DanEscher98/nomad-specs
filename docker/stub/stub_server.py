"""
Roam Protocol Stub Server

A minimal stub server that:
1. Exposes health check endpoint on HTTP 8080
2. Listens for UDP on 19999 and echoes back
3. Logs all activity for debugging

This is NOT a real Roam implementation. It's used to test the
test infrastructure (Docker orchestration, fixtures, etc.).
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import sys

import structlog
from aiohttp import web

# Configure logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        structlog.stdlib.NAME_TO_LEVEL.get(
            os.environ.get("ROAM_LOG_LEVEL", "debug").lower(), 10
        )
    ),
)
log = structlog.get_logger()


class StubServer:
    """Minimal stub server for testing infrastructure."""

    def __init__(self) -> None:
        self.bind_addr = os.environ.get("ROAM_BIND_ADDR", "0.0.0.0:19999")
        self.state_type = os.environ.get("ROAM_STATE_TYPE", "roam.echo.v1")
        self.server_public_key = os.environ.get("ROAM_SERVER_PUBLIC_KEY", "")
        self.running = False
        self.udp_transport: asyncio.DatagramTransport | None = None
        self.packets_received = 0
        self.packets_sent = 0

    async def start_health_server(self) -> web.AppRunner:
        """Start HTTP health check server on port 8080."""
        app = web.Application()
        app.router.add_get("/health", self.health_handler)
        app.router.add_get("/status", self.status_handler)
        app.router.add_get("/ready", self.ready_handler)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", 8080)
        await site.start()
        log.info("health_server_started", port=8080)
        return runner

    async def health_handler(self, _request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.Response(text="OK", status=200)

    async def status_handler(self, _request: web.Request) -> web.Response:
        """Status endpoint with server info."""
        import json

        status = {
            "state_type": self.state_type,
            "running": self.running,
            "packets_received": self.packets_received,
            "packets_sent": self.packets_sent,
            "has_public_key": bool(self.server_public_key),
        }
        return web.Response(
            text=json.dumps(status),
            status=200,
            content_type="application/json",
        )

    async def ready_handler(self, _request: web.Request) -> web.Response:
        """Readiness check - are we ready to accept connections?"""
        if self.running and self.udp_transport is not None:
            return web.Response(text="READY", status=200)
        return web.Response(text="NOT READY", status=503)

    async def start_udp_server(self) -> None:
        """Start UDP echo server."""
        host, port_str = self.bind_addr.rsplit(":", 1)
        port = int(port_str)

        loop = asyncio.get_running_loop()

        class EchoProtocol(asyncio.DatagramProtocol):
            def __init__(self, server: StubServer) -> None:
                self.server = server

            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                self.server.udp_transport = transport
                log.info("udp_server_started", bind=self.server.bind_addr)

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                self.server.packets_received += 1
                log.debug(
                    "packet_received",
                    size=len(data),
                    from_addr=f"{addr[0]}:{addr[1]}",
                    preview=data[:32].hex(),
                )

                # Echo back the data (stub behavior)
                if self.server.udp_transport:
                    self.server.udp_transport.sendto(data, addr)
                    self.server.packets_sent += 1
                    log.debug("packet_echoed", size=len(data), to_addr=f"{addr[0]}:{addr[1]}")

            def error_received(self, exc: Exception) -> None:
                log.error("udp_error", error=str(exc))

        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: EchoProtocol(self),
            local_addr=(host, port),
            family=socket.AF_INET,
        )

        self.udp_transport = transport
        self.running = True

    async def run(self) -> None:
        """Run the stub server."""
        log.info(
            "stub_server_starting",
            bind_addr=self.bind_addr,
            state_type=self.state_type,
        )

        # Start both servers
        health_runner = await self.start_health_server()
        await self.start_udp_server()

        # Wait for shutdown signal
        stop_event = asyncio.Event()

        def signal_handler() -> None:
            log.info("shutdown_signal_received")
            stop_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)

        await stop_event.wait()

        # Cleanup
        log.info("shutting_down")
        self.running = False
        if self.udp_transport:
            self.udp_transport.close()
        await health_runner.cleanup()
        log.info("shutdown_complete")


async def main() -> None:
    """Entry point."""
    server = StubServer()
    await server.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
