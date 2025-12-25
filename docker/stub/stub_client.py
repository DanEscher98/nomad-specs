"""
Roam Protocol Stub Client

A minimal stub client that:
1. Connects to server via UDP
2. Sends periodic ping packets
3. Logs responses

This is NOT a real Roam implementation. It's used to test the
test infrastructure (Docker orchestration, fixtures, etc.).
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import sys
import time

import structlog

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


class StubClient:
    """Minimal stub client for testing infrastructure."""

    def __init__(self) -> None:
        self.server_host = os.environ.get("ROAM_SERVER_HOST", "127.0.0.1")
        self.server_port = int(os.environ.get("ROAM_SERVER_PORT", "19999"))
        self.server_public_key = os.environ.get("ROAM_SERVER_PUBLIC_KEY", "")
        self.running = False
        self.transport: asyncio.DatagramTransport | None = None
        self.packets_sent = 0
        self.packets_received = 0
        self.last_rtt: float | None = None

    async def run(self) -> None:
        """Run the stub client."""
        log.info(
            "stub_client_starting",
            server=f"{self.server_host}:{self.server_port}",
        )

        loop = asyncio.get_running_loop()

        class ClientProtocol(asyncio.DatagramProtocol):
            def __init__(self, client: StubClient) -> None:
                self.client = client
                self.pending_pings: dict[int, float] = {}

            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                self.client.transport = transport
                self.client.running = True
                log.info("connected", server=f"{self.client.server_host}:{self.client.server_port}")

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                self.client.packets_received += 1

                # Check if this is a ping response
                if len(data) >= 8 and data[:4] == b"PING":
                    try:
                        seq = int.from_bytes(data[4:8], "little")
                        if seq in self.pending_pings:
                            rtt = (time.monotonic() - self.pending_pings.pop(seq)) * 1000
                            self.client.last_rtt = rtt
                            log.debug("pong_received", seq=seq, rtt_ms=f"{rtt:.2f}")
                    except Exception:
                        pass
                else:
                    log.debug(
                        "packet_received",
                        size=len(data),
                        from_addr=f"{addr[0]}:{addr[1]}",
                        preview=data[:32].hex(),
                    )

            def error_received(self, exc: Exception) -> None:
                log.error("udp_error", error=str(exc))

            def send_ping(self, seq: int) -> None:
                """Send a ping packet."""
                if self.client.transport:
                    data = b"PING" + seq.to_bytes(4, "little")
                    self.pending_pings[seq] = time.monotonic()
                    self.client.transport.sendto(
                        data, (self.client.server_host, self.client.server_port)
                    )
                    self.client.packets_sent += 1
                    log.debug("ping_sent", seq=seq)

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: ClientProtocol(self),
            family=socket.AF_INET,
        )

        # Shutdown handling
        stop_event = asyncio.Event()

        def signal_handler() -> None:
            log.info("shutdown_signal_received")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)

        # Ping loop
        seq = 0
        try:
            while not stop_event.is_set():
                protocol.send_ping(seq)
                seq += 1

                # Wait 1 second or until shutdown
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=1.0)
                    break
                except asyncio.TimeoutError:
                    pass

                # Log stats periodically
                if seq % 10 == 0:
                    log.info(
                        "stats",
                        sent=self.packets_sent,
                        received=self.packets_received,
                        last_rtt_ms=f"{self.last_rtt:.2f}" if self.last_rtt else "N/A",
                    )
        finally:
            log.info("shutting_down")
            self.running = False
            transport.close()
            log.info(
                "shutdown_complete",
                total_sent=self.packets_sent,
                total_received=self.packets_received,
            )


async def main() -> None:
    """Entry point."""
    client = StubClient()
    await client.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
