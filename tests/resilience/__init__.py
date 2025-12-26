"""
Resilience tests for Nomad Protocol.

This module contains tests that verify protocol behavior under adverse network conditions:
- Packet loss (10%, 30%, 50%)
- Latency (100ms, 500ms, variable)
- Jitter (±100ms, ±300ms)
- Packet reordering
- Packet duplication
- Network partitions
- IP migration (roaming)

All tests use @pytest.mark.resilience marker and require Docker with tc/netem support.
Tests use pumba (gaiaadm/pumba) for chaos injection.

Test pattern:
1. Apply chaos condition
2. Send state updates
3. Verify sync converges
4. Clean up chaos
"""
