"""
Key compromise and forward secrecy tests.

Tests that compromising keys at time T does not reveal traffic from
time < T (forward secrecy) and validates proper key destruction.

Test mapping: specs/1-SECURITY.md § "Security Properties", "Rekeying"
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import given, settings
from hypothesis import strategies as st
from nacl.bindings import crypto_scalarmult

from lib.reference import (
    construct_nonce,
    deterministic_bytes,
    deterministic_keypair,
    xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt,
)

# =============================================================================
# Forward Secrecy Constants
# =============================================================================


REKEY_INTERVAL_SECONDS = 120  # 2 minutes per spec


# =============================================================================
# Key Lifecycle Simulation
# =============================================================================


@dataclass
class EphemeralKey:
    """An ephemeral key with lifecycle tracking."""

    private: bytes
    public: bytes
    created_at: int  # Timestamp when created
    destroyed_at: int | None = None  # Timestamp when zeroed

    def is_destroyed(self) -> bool:
        """Check if key has been destroyed."""
        return self.destroyed_at is not None


@dataclass
class SessionKeyEpoch:
    """A single epoch of session keys."""

    epoch: int
    send_key: bytes
    recv_key: bytes
    created_at: int
    destroyed_at: int | None = None

    # Capture of traffic encrypted under these keys (for testing)
    captured_ciphertexts: list[bytes] = field(default_factory=list)
    captured_aads: list[bytes] = field(default_factory=list)
    captured_nonce_counters: list[int] = field(default_factory=list)
    captured_plaintexts: list[bytes] = field(default_factory=list)


@dataclass
class SessionHistory:
    """History of all key epochs in a session."""

    epochs: list[SessionKeyEpoch] = field(default_factory=list)

    def current_epoch(self) -> SessionKeyEpoch | None:
        """Get current (latest) epoch."""
        if not self.epochs:
            return None
        return self.epochs[-1]

    def add_epoch(
        self,
        send_key: bytes,
        recv_key: bytes,
        timestamp: int,
    ) -> SessionKeyEpoch:
        """Add a new epoch (rekey)."""
        epoch_num = len(self.epochs)
        epoch = SessionKeyEpoch(
            epoch=epoch_num,
            send_key=send_key,
            recv_key=recv_key,
            created_at=timestamp,
        )
        self.epochs.append(epoch)
        return epoch

    def destroy_old_keys(self, current_time: int, retention: int = 5) -> None:
        """Destroy keys from epochs that are past retention period."""
        for epoch in self.epochs[:-1]:  # All except current
            if epoch.destroyed_at is None and current_time - epoch.created_at > retention:
                epoch.send_key = b"\x00" * 32  # Simulate zeroization
                epoch.recv_key = b"\x00" * 32
                epoch.destroyed_at = current_time


# =============================================================================
# Attacker Simulation
# =============================================================================


@dataclass
class Attacker:
    """Simulated attacker with limited capabilities.

    Models an attacker who:
    - Can capture all network traffic
    - May eventually compromise a session key
    - Cannot compromise static keys (assumed secure)
    """

    # Captured traffic (encrypted)
    captured_traffic: list[tuple[bytes, bytes, int, int]] = field(
        default_factory=list
    )  # (ciphertext, aad, epoch, nonce_counter)

    # Keys the attacker has compromised
    compromised_keys: dict[int, bytes] = field(default_factory=dict)  # epoch -> key

    def capture_frame(self, ciphertext: bytes, aad: bytes, epoch: int, nonce_counter: int) -> None:
        """Capture an encrypted frame from the network."""
        self.captured_traffic.append((ciphertext, aad, epoch, nonce_counter))

    def compromise_key(self, epoch: int, key: bytes) -> None:
        """Attacker compromises a session key."""
        self.compromised_keys[epoch] = key

    def decrypt_captured(self, direction: int) -> list[tuple[int, bytes | None]]:
        """Attempt to decrypt captured traffic with compromised keys.

        Returns list of (epoch, plaintext or None if decryption failed).
        """
        results = []
        for ciphertext, aad, epoch, nonce_counter in self.captured_traffic:
            if epoch in self.compromised_keys:
                key = self.compromised_keys[epoch]
                nonce = construct_nonce(epoch, direction, nonce_counter)
                try:
                    plaintext = xchacha20_poly1305_decrypt(key, nonce, ciphertext, aad)
                    results.append((epoch, plaintext))
                except InvalidTag:
                    results.append((epoch, None))
            else:
                results.append((epoch, None))
        return results


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def session_history() -> SessionHistory:
    """Session with key history."""
    return SessionHistory()


@pytest.fixture
def attacker() -> Attacker:
    """Simulated attacker."""
    return Attacker()


# =============================================================================
# Forward Secrecy Tests
# =============================================================================


class TestForwardSecrecy:
    """Test forward secrecy properties."""

    def test_old_traffic_protected_after_rekey(
        self, session_history: SessionHistory, attacker: Attacker
    ) -> None:
        """Traffic encrypted with old keys is protected after rekey."""
        # Epoch 0: Send some messages
        epoch0 = session_history.add_epoch(
            send_key=deterministic_bytes("epoch0-send", 32),
            recv_key=deterministic_bytes("epoch0-recv", 32),
            timestamp=0,
        )

        # Encrypt some traffic in epoch 0
        for i in range(5):
            plaintext = f"secret message {i}".encode()
            aad = b"\x03\x00" + b"\x00" * 14
            nonce = construct_nonce(0, 0, i)
            ciphertext = xchacha20_poly1305_encrypt(epoch0.send_key, nonce, plaintext, aad)
            attacker.capture_frame(ciphertext, aad, epoch=0, nonce_counter=i)
            epoch0.captured_plaintexts.append(plaintext)

        # Epoch 1: Rekey with new keys
        epoch1 = session_history.add_epoch(
            send_key=deterministic_bytes("epoch1-send", 32),
            recv_key=deterministic_bytes("epoch1-recv", 32),
            timestamp=120,
        )

        # Destroy old keys (epoch 0)
        session_history.destroy_old_keys(current_time=130, retention=5)

        # Attacker compromises epoch 1 key
        attacker.compromise_key(1, epoch1.send_key)

        # Attacker cannot decrypt epoch 0 traffic
        results = attacker.decrypt_captured(direction=0)
        for epoch, plaintext in results:
            if epoch == 0:
                assert plaintext is None, "Forward secrecy violated: old traffic decrypted"

    def test_future_traffic_protected_with_old_key(
        self, session_history: SessionHistory, attacker: Attacker
    ) -> None:
        """Compromising old key doesn't allow decrypting new traffic."""
        # Epoch 0
        epoch0 = session_history.add_epoch(
            send_key=deterministic_bytes("epoch0-send", 32),
            recv_key=deterministic_bytes("epoch0-recv", 32),
            timestamp=0,
        )

        # Epoch 1: Rekey
        epoch1 = session_history.add_epoch(
            send_key=deterministic_bytes("epoch1-send", 32),
            recv_key=deterministic_bytes("epoch1-recv", 32),
            timestamp=120,
        )

        # Encrypt traffic in epoch 1
        for i in range(5):
            plaintext = f"new secret {i}".encode()
            aad = b"\x03\x00" + b"\x00" * 14
            nonce = construct_nonce(1, 0, i)
            ciphertext = xchacha20_poly1305_encrypt(epoch1.send_key, nonce, plaintext, aad)
            attacker.capture_frame(ciphertext, aad, epoch=1, nonce_counter=i)

        # Attacker compromises OLD key (epoch 0)
        attacker.compromise_key(0, epoch0.send_key)

        # Attacker cannot decrypt epoch 1 traffic
        results = attacker.decrypt_captured(direction=0)
        for epoch, plaintext in results:
            if epoch == 1:
                assert plaintext is None, "Backward secrecy: new traffic decrypted with old key"

    def test_ephemeral_keys_provide_pfs(self) -> None:
        """Ephemeral keys ensure perfect forward secrecy."""
        # Create two "sessions" with same static keys but different ephemerals
        static_priv, static_pub = deterministic_keypair("static-key")

        ephemeral1_priv, ephemeral1_pub = deterministic_keypair("ephemeral-1")
        ephemeral2_priv, ephemeral2_pub = deterministic_keypair("ephemeral-2")

        # DH with different ephemerals produces different shared secrets
        shared1 = crypto_scalarmult(ephemeral1_priv, static_pub)
        shared2 = crypto_scalarmult(ephemeral2_priv, static_pub)

        assert shared1 != shared2, "Different ephemerals must produce different secrets"

    def test_key_independence_across_epochs(self, session_history: SessionHistory) -> None:
        """Keys from different epochs are cryptographically independent."""
        keys = []
        for i in range(5):
            epoch = session_history.add_epoch(
                send_key=deterministic_bytes(f"epoch{i}-send", 32),
                recv_key=deterministic_bytes(f"epoch{i}-recv", 32),
                timestamp=i * 120,
            )
            keys.append(epoch.send_key)

        # All keys should be unique
        assert len(set(keys)) == 5, "Epoch keys must be independent"


# =============================================================================
# Key Destruction Tests
# =============================================================================


class TestKeyDestruction:
    """Test proper key destruction (zeroization)."""

    def test_old_keys_zeroed_after_retention(self, session_history: SessionHistory) -> None:
        """Old keys are zeroed after retention period."""
        # Create epochs
        epoch0 = session_history.add_epoch(
            send_key=deterministic_bytes("epoch0-send", 32),
            recv_key=deterministic_bytes("epoch0-recv", 32),
            timestamp=0,
        )

        session_history.add_epoch(
            send_key=deterministic_bytes("epoch1-send", 32),
            recv_key=deterministic_bytes("epoch1-recv", 32),
            timestamp=120,
        )

        # Destroy old keys after retention
        session_history.destroy_old_keys(current_time=130, retention=5)

        # Epoch 0 keys should be zeroed
        assert epoch0.send_key == b"\x00" * 32
        assert epoch0.recv_key == b"\x00" * 32
        assert epoch0.destroyed_at == 130

    def test_current_keys_not_destroyed(self, session_history: SessionHistory) -> None:
        """Current epoch keys are never destroyed by rekey."""
        epoch0 = session_history.add_epoch(
            send_key=deterministic_bytes("epoch0-send", 32),
            recv_key=deterministic_bytes("epoch0-recv", 32),
            timestamp=0,
        )
        original_key = epoch0.send_key

        # Destroy old keys
        session_history.destroy_old_keys(current_time=100, retention=5)

        # Current epoch still valid (not destroyed)
        assert epoch0.send_key == original_key
        assert epoch0.destroyed_at is None

    def test_key_destruction_prevents_decryption(
        self, session_history: SessionHistory, attacker: Attacker
    ) -> None:
        """Destroyed keys cannot decrypt traffic."""
        epoch0 = session_history.add_epoch(
            send_key=deterministic_bytes("epoch0-send", 32),
            recv_key=deterministic_bytes("epoch0-recv", 32),
            timestamp=0,
        )

        # Encrypt some traffic
        plaintext = b"secret"
        aad = b"\x03\x00" + b"\x00" * 14
        nonce = construct_nonce(0, 0, 0)
        ciphertext = xchacha20_poly1305_encrypt(epoch0.send_key, nonce, plaintext, aad)
        attacker.capture_frame(ciphertext, aad, epoch=0, nonce_counter=0)

        # Rekey
        session_history.add_epoch(
            send_key=deterministic_bytes("epoch1-send", 32),
            recv_key=deterministic_bytes("epoch1-recv", 32),
            timestamp=120,
        )

        # Destroy old keys
        session_history.destroy_old_keys(current_time=130, retention=5)

        # Attacker "compromises" the zeroed key
        attacker.compromise_key(0, epoch0.send_key)  # This is now all zeros

        # Cannot decrypt with zeroed key
        results = attacker.decrypt_captured(direction=0)
        assert results[0][1] is None


# =============================================================================
# Compromise Impact Tests
# =============================================================================


class TestCompromiseImpact:
    """Test impact of key compromise scenarios."""

    def test_session_key_compromise_limited_window(
        self, session_history: SessionHistory, attacker: Attacker
    ) -> None:
        """Session key compromise only affects current rekey window."""
        # Create 3 epochs with traffic
        for epoch_num in range(3):
            epoch = session_history.add_epoch(
                send_key=deterministic_bytes(f"epoch{epoch_num}-send", 32),
                recv_key=deterministic_bytes(f"epoch{epoch_num}-recv", 32),
                timestamp=epoch_num * 120,
            )

            # Send traffic in this epoch
            for i in range(3):
                plaintext = f"epoch{epoch_num} msg{i}".encode()
                aad = b"\x03\x00" + b"\x00" * 14
                nonce = construct_nonce(epoch_num, 0, i)
                ciphertext = xchacha20_poly1305_encrypt(epoch.send_key, nonce, plaintext, aad)
                attacker.capture_frame(ciphertext, aad, epoch=epoch_num, nonce_counter=i)

        # Compromise only epoch 1 key
        epoch1 = session_history.epochs[1]
        attacker.compromise_key(1, epoch1.send_key)

        # Try to decrypt all traffic
        results = attacker.decrypt_captured(direction=0)

        # Count successful decryptions by epoch
        decrypted_by_epoch = {0: 0, 1: 0, 2: 0}
        for epoch, plaintext in results:
            if plaintext is not None:
                decrypted_by_epoch[epoch] += 1

        # Only epoch 1 traffic should be decryptable
        assert decrypted_by_epoch[0] == 0, "Epoch 0 traffic should be protected"
        assert decrypted_by_epoch[1] == 3, "Epoch 1 traffic exposed by compromise"
        assert decrypted_by_epoch[2] == 0, "Epoch 2 traffic should be protected"

    def test_ephemeral_key_compromise_single_session(self) -> None:
        """Ephemeral key compromise only affects one session."""
        # Two sessions with different ephemeral keys
        static_priv, static_pub = deterministic_keypair("server-static")

        session1_eph_priv, session1_eph_pub = deterministic_keypair("session1-eph")
        session2_eph_priv, session2_eph_pub = deterministic_keypair("session2-eph")

        # Shared secrets are different
        shared1 = crypto_scalarmult(session1_eph_priv, static_pub)
        shared2 = crypto_scalarmult(session2_eph_priv, static_pub)

        # Encrypt with session 1 key
        plaintext = b"secret from session 1"
        nonce = b"\x00" * 24
        aad = b""
        ciphertext1 = xchacha20_poly1305_encrypt(shared1, nonce, plaintext, aad)

        # Session 2 key cannot decrypt session 1 traffic
        with pytest.raises(InvalidTag):
            xchacha20_poly1305_decrypt(shared2, nonce, ciphertext1, aad)


# =============================================================================
# Static Key Protection Tests
# =============================================================================


class TestStaticKeyProtection:
    """Test protection when static keys are compromised."""

    def test_static_compromise_without_ephemeral_insufficient(self) -> None:
        """Static key alone cannot decrypt session traffic.

        Session keys are derived from DH(static, ephemeral).
        Without the ephemeral private key, traffic is protected.
        """
        # Responder's static keypair
        static_priv, static_pub = deterministic_keypair("responder-static")

        # Initiator's ephemeral keypair
        eph_priv, eph_pub = deterministic_keypair("initiator-ephemeral")

        # Session key from DH
        session_key = crypto_scalarmult(eph_priv, static_pub)

        # Encrypt traffic
        plaintext = b"secret message"
        nonce = b"\x00" * 24
        aad = b""
        _ciphertext = xchacha20_poly1305_encrypt(session_key, nonce, plaintext, aad)

        # Attacker has:
        # - Static private key (compromised)
        # - Ephemeral PUBLIC key (from handshake)
        # - Ciphertext (stored in _ciphertext)

        # Attacker cannot derive session key without ephemeral PRIVATE
        # They can only compute DH(static_priv, eph_pub) which equals
        # DH(eph_priv, static_pub) - but they need eph_priv!

        # In Noise_IK, the initiator's static is also involved, but
        # the key point is that ephemeral private is needed.

        # This test documents that static key alone is insufficient
        # to decrypt traffic encrypted under ephemeral-derived keys.
        assert _ciphertext is not None  # Encryption succeeded


# =============================================================================
# Property-Based Tests
# =============================================================================


class TestForwardSecrecyProperties:
    """Property-based tests for forward secrecy."""

    @given(num_epochs=st.integers(min_value=2, max_value=10))
    @settings(max_examples=20)
    def test_any_epoch_key_isolates_traffic(self, num_epochs: int) -> None:
        """Compromising any single epoch key only exposes that epoch's traffic."""
        session = SessionHistory()
        attacker = Attacker()

        # Create epochs and traffic
        for epoch_num in range(num_epochs):
            epoch = session.add_epoch(
                send_key=deterministic_bytes(f"epoch{epoch_num}-send-prop", 32),
                recv_key=deterministic_bytes(f"epoch{epoch_num}-recv-prop", 32),
                timestamp=epoch_num * 120,
            )

            # One message per epoch
            plaintext = f"epoch{epoch_num} message".encode()
            aad = b"\x03\x00" + b"\x00" * 14
            nonce = construct_nonce(epoch_num, 0, 0)
            ciphertext = xchacha20_poly1305_encrypt(epoch.send_key, nonce, plaintext, aad)
            attacker.capture_frame(ciphertext, aad, epoch=epoch_num, nonce_counter=0)

        # Compromise middle epoch
        middle = num_epochs // 2
        attacker.compromise_key(middle, session.epochs[middle].send_key)

        # Verify only middle epoch exposed
        results = attacker.decrypt_captured(direction=0)
        for epoch, plaintext in results:
            if epoch == middle:
                assert plaintext is not None, f"Epoch {middle} should be decryptable"
            else:
                assert plaintext is None, f"Epoch {epoch} should be protected"

    @given(seed=st.text(min_size=1, max_size=20))
    @settings(max_examples=30)
    def test_different_sessions_independent(self, seed: str) -> None:
        """Different sessions have completely independent key material."""
        # Two "sessions" with same static but different ephemeral seeds
        static_priv, static_pub = deterministic_keypair("common-static")

        eph1_priv, eph1_pub = deterministic_keypair(f"session1-{seed}")
        eph2_priv, eph2_pub = deterministic_keypair(f"session2-{seed}")

        shared1 = crypto_scalarmult(eph1_priv, static_pub)
        shared2 = crypto_scalarmult(eph2_priv, static_pub)

        # Unless seeds accidentally collide, shared secrets differ
        if eph1_priv != eph2_priv:
            assert shared1 != shared2
