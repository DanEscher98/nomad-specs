#!/usr/bin/env python3
"""
NOMAD Protocol Test Vector Generator

Generates canonical test vectors for the NOMAD protocol v1.0.
These vectors are the SOURCE OF TRUTH for all implementations.

Usage:
    python generate_vectors.py
    # or
    just gen-vectors

Output:
    ../tests/vectors/handshake_vectors.json5
    ../tests/vectors/aead_vectors.json5
    ../tests/vectors/frame_vectors.json5
    ../tests/vectors/sync_vectors.json5

Requirements:
    pip install cryptography pynacl json5

The script is IDEMPOTENT: running twice produces identical output.
All randomness uses fixed seeds for reproducibility.
"""

import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Check dependencies
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    from cryptography.hazmat.primitives import hashes
    from nacl.bindings import (
        crypto_scalarmult,
        crypto_scalarmult_base,
    )
    from nacl.hash import blake2b
    import json5
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install cryptography pynacl json5")
    sys.exit(1)


# =============================================================================
# Constants (from PROTOCOL.md)
# =============================================================================

PROTOCOL_VERSION = 0x0001
NOMAD_VERSION = "1.0.0"

# Frame types
FRAME_HANDSHAKE_INIT = 0x01
FRAME_HANDSHAKE_RESP = 0x02
FRAME_DATA = 0x03
FRAME_REKEY = 0x04
FRAME_CLOSE = 0x05

# Sizes
SESSION_ID_SIZE = 6
AEAD_TAG_SIZE = 16
AEAD_NONCE_SIZE = 24  # XChaCha20
PUBLIC_KEY_SIZE = 32
PRIVATE_KEY_SIZE = 32

# Key derivation constants (from SECURITY.md)
SESSION_KEY_INFO = b"nomad v1 session keys"
REKEY_AUTH_INFO = b"nomad v1 rekey auth"
REKEY_INFO_PREFIX = b"nomad v1 rekey"

# Output directory
VECTORS_DIR = Path(__file__).parent.parent / "tests" / "vectors"


# =============================================================================
# Deterministic Key Generation
# =============================================================================

def deterministic_keypair(seed: str) -> tuple[bytes, bytes]:
    """Generate X25519 keypair from seed string.

    Uses BLAKE2b to derive a 32-byte private key from the seed,
    then computes the public key via scalar multiplication.
    """
    # Derive private key from seed
    private = blake2b(seed.encode(), digest_size=32)

    # Clamp private key for X25519
    private_bytes = bytearray(private)
    private_bytes[0] &= 248
    private_bytes[31] &= 127
    private_bytes[31] |= 64
    private = bytes(private_bytes)

    # Compute public key
    public = crypto_scalarmult_base(private)

    return private, public


def deterministic_bytes(seed: str, length: int) -> bytes:
    """Generate deterministic bytes from seed."""
    result = b""
    counter = 0
    while len(result) < length:
        chunk = blake2b(f"{seed}:{counter}".encode(), digest_size=32)
        result += chunk
        counter += 1
    return result[:length]


# =============================================================================
# HKDF Key Derivation (from SECURITY.md)
# =============================================================================


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand using SHA-256."""
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    )
    return hkdf.derive(prk)


def derive_session_keys(handshake_hash: bytes) -> tuple[bytes, bytes]:
    """Derive session keys for epoch 0 from handshake hash."""
    key_material = hkdf_expand(handshake_hash, SESSION_KEY_INFO, 64)
    return key_material[:32], key_material[32:]


def derive_rekey_auth_key(static_dh_secret: bytes) -> bytes:
    """Derive rekey authentication key from static DH secret."""
    return hkdf_expand(static_dh_secret, REKEY_AUTH_INFO, 32)


def derive_rekey_keys(ephemeral_dh: bytes, rekey_auth_key: bytes, epoch: int) -> tuple[bytes, bytes]:
    """Derive new session keys during rekey (with PCS).

    Per SECURITY.md §Post-Rekey Keys:
        (new_initiator_key, new_responder_key) = HKDF-Expand(
            ephemeral_dh || rekey_auth_key,
            "nomad v1 rekey" || LE32(epoch),
            64
        )
    """
    prk = ephemeral_dh + rekey_auth_key
    info = REKEY_INFO_PREFIX + struct.pack("<I", epoch)
    key_material = hkdf_expand(prk, info, 64)
    return key_material[:32], key_material[32:]


# =============================================================================
# XChaCha20-Poly1305 Implementation
# =============================================================================

def hchacha20(key: bytes, nonce: bytes) -> bytes:
    """HChaCha20 - derives subkey from first 16 bytes of nonce.

    This is the key derivation step that makes XChaCha20 work.
    """
    # HChaCha20 constants
    constants = b"expand 32-byte k"

    # Build state
    state = list(struct.unpack('<16I', constants + key + nonce[:16]))

    # 20 rounds (10 double-rounds)
    def quarter_round(a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF

        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF

    for _ in range(10):
        # Column rounds
        quarter_round(0, 4, 8, 12)
        quarter_round(1, 5, 9, 13)
        quarter_round(2, 6, 10, 14)
        quarter_round(3, 7, 11, 15)
        # Diagonal rounds
        quarter_round(0, 5, 10, 15)
        quarter_round(1, 6, 11, 12)
        quarter_round(2, 7, 8, 13)
        quarter_round(3, 4, 9, 14)

    # Extract subkey (first and last 4 words)
    return struct.pack('<8I',
        state[0], state[1], state[2], state[3],
        state[12], state[13], state[14], state[15]
    )


def xchacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """XChaCha20-Poly1305 AEAD encryption.

    1. Use HChaCha20 to derive subkey from first 16 bytes of nonce
    2. Use ChaCha20-Poly1305 with subkey and last 8 bytes of nonce
    """
    assert len(key) == 32, f"Key must be 32 bytes, got {len(key)}"
    assert len(nonce) == 24, f"Nonce must be 24 bytes, got {len(nonce)}"

    # Derive subkey using HChaCha20
    subkey = hchacha20(key, nonce)

    # Build 12-byte nonce for ChaCha20-Poly1305: 4 zero bytes + last 8 bytes of XChaCha nonce
    chacha_nonce = b'\x00\x00\x00\x00' + nonce[16:24]

    # Encrypt with standard ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(subkey)
    return cipher.encrypt(chacha_nonce, plaintext, aad)


def xchacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """XChaCha20-Poly1305 AEAD decryption."""
    assert len(key) == 32
    assert len(nonce) == 24

    subkey = hchacha20(key, nonce)
    chacha_nonce = b'\x00\x00\x00\x00' + nonce[16:24]

    cipher = ChaCha20Poly1305(subkey)
    return cipher.decrypt(chacha_nonce, ciphertext, aad)


# =============================================================================
# Nonce Construction (from SECURITY.md)
# =============================================================================

def construct_nonce(epoch: int, direction: int, counter: int) -> bytes:
    """Construct 24-byte XChaCha20 nonce.

    Layout:
    - Bytes 0-3: Epoch (LE32)
    - Byte 4: Direction (0x00 = initiator->responder, 0x01 = responder->initiator)
    - Bytes 5-15: Zeros (padding)
    - Bytes 16-23: Counter (LE64)
    """
    nonce = bytearray(24)
    struct.pack_into('<I', nonce, 0, epoch)      # Epoch at offset 0
    nonce[4] = direction                          # Direction at offset 4
    # Bytes 5-15 are zeros (already initialized)
    struct.pack_into('<Q', nonce, 16, counter)   # Counter at offset 16
    return bytes(nonce)


# =============================================================================
# Frame Encoding
# =============================================================================

def encode_data_frame_header(flags: int, session_id: bytes, nonce_counter: int) -> bytes:
    """Encode data frame header (16 bytes, used as AAD)."""
    assert len(session_id) == SESSION_ID_SIZE
    header = bytearray(16)
    header[0] = FRAME_DATA
    header[1] = flags
    header[2:8] = session_id
    struct.pack_into('<Q', header, 8, nonce_counter)
    return bytes(header)


def encode_sync_message(sender_state: int, acked_state: int, base_state: int, diff: bytes) -> bytes:
    """Encode sync message."""
    header = struct.pack('<QQQ', sender_state, acked_state, base_state)
    length = struct.pack('<I', len(diff))
    return header + length + diff


# =============================================================================
# Vector Generators
# =============================================================================

def generate_aead_vectors() -> dict[str, Any]:
    """Generate XChaCha20-Poly1305 AEAD test vectors."""
    vectors = {
        "_metadata": {
            "description": "XChaCha20-Poly1305 AEAD test vectors for NOMAD v1.0",
            "generated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "generator": "specs/generate_vectors.py",
            "protocol_version": NOMAD_VERSION,
        },
        "_notes": [
            "All hex values are lowercase",
            "Nonce is 24 bytes (XChaCha20 extended nonce)",
            "Tag is 16 bytes (Poly1305)",
            "Ciphertext includes the tag appended",
        ],
        "vectors": []
    }

    # Vector 1: Basic encryption
    key = deterministic_bytes("aead-key-1", 32)
    nonce = construct_nonce(epoch=0, direction=0, counter=0)
    plaintext = b"Hello, NOMAD!"
    aad = encode_data_frame_header(flags=0, session_id=b"\x01\x02\x03\x04\x05\x06", nonce_counter=0)
    ciphertext = xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    vectors["vectors"].append({
        "name": "basic_encryption",
        "description": "Basic AEAD encryption with minimal payload",
        "key": key.hex(),
        "nonce": nonce.hex(),
        "nonce_components": {
            "epoch": 0,
            "direction": 0,
            "counter": 0,
        },
        "plaintext": plaintext.hex(),
        "plaintext_ascii": plaintext.decode('utf-8'),
        "aad": aad.hex(),
        "aad_components": {
            "frame_type": "0x03 (Data)",
            "flags": "0x00",
            "session_id": "010203040506",
            "nonce_counter": 0,
        },
        "ciphertext": ciphertext.hex(),
        "tag": ciphertext[-16:].hex(),
    })

    # Vector 2: Empty plaintext (ack-only)
    nonce2 = construct_nonce(epoch=0, direction=0, counter=1)
    aad2 = encode_data_frame_header(flags=0x01, session_id=b"\x01\x02\x03\x04\x05\x06", nonce_counter=1)
    ciphertext2 = xchacha20_poly1305_encrypt(key, nonce2, b"", aad2)

    vectors["vectors"].append({
        "name": "empty_plaintext_ack_only",
        "description": "AEAD with empty plaintext (ack-only frame)",
        "key": key.hex(),
        "nonce": nonce2.hex(),
        "nonce_components": {
            "epoch": 0,
            "direction": 0,
            "counter": 1,
        },
        "plaintext": "",
        "aad": aad2.hex(),
        "aad_components": {
            "frame_type": "0x03 (Data)",
            "flags": "0x01 (ACK_ONLY)",
            "session_id": "010203040506",
            "nonce_counter": 1,
        },
        "ciphertext": ciphertext2.hex(),
        "tag": ciphertext2[-16:].hex(),
    })

    # Vector 3: Responder direction
    nonce3 = construct_nonce(epoch=0, direction=1, counter=0)
    key_resp = deterministic_bytes("aead-key-responder", 32)
    plaintext3 = b"Response from server"
    aad3 = encode_data_frame_header(flags=0, session_id=b"\x01\x02\x03\x04\x05\x06", nonce_counter=0)
    ciphertext3 = xchacha20_poly1305_encrypt(key_resp, nonce3, plaintext3, aad3)

    vectors["vectors"].append({
        "name": "responder_direction",
        "description": "AEAD with responder->initiator direction",
        "key": key_resp.hex(),
        "nonce": nonce3.hex(),
        "nonce_components": {
            "epoch": 0,
            "direction": 1,
            "counter": 0,
        },
        "plaintext": plaintext3.hex(),
        "aad": aad3.hex(),
        "ciphertext": ciphertext3.hex(),
    })

    # Vector 4: After rekey (epoch > 0)
    nonce4 = construct_nonce(epoch=1, direction=0, counter=0)
    key_epoch1 = deterministic_bytes("aead-key-epoch1", 32)
    plaintext4 = b"After rekey"
    aad4 = encode_data_frame_header(flags=0, session_id=b"\x01\x02\x03\x04\x05\x06", nonce_counter=0)
    ciphertext4 = xchacha20_poly1305_encrypt(key_epoch1, nonce4, plaintext4, aad4)

    vectors["vectors"].append({
        "name": "after_rekey_epoch_1",
        "description": "AEAD after first rekey (epoch=1, counter reset to 0)",
        "key": key_epoch1.hex(),
        "nonce": nonce4.hex(),
        "nonce_components": {
            "epoch": 1,
            "direction": 0,
            "counter": 0,
        },
        "plaintext": plaintext4.hex(),
        "aad": aad4.hex(),
        "ciphertext": ciphertext4.hex(),
    })

    # Vector 5: Large counter value
    nonce5 = construct_nonce(epoch=0, direction=0, counter=0xFFFFFFFF)
    plaintext5 = b"High counter"
    aad5 = encode_data_frame_header(flags=0, session_id=b"\xAA\xBB\xCC\xDD\xEE\xFF", nonce_counter=0xFFFFFFFF)
    ciphertext5 = xchacha20_poly1305_encrypt(key, nonce5, plaintext5, aad5)

    vectors["vectors"].append({
        "name": "high_counter_value",
        "description": "AEAD with high counter value (4 billion)",
        "key": key.hex(),
        "nonce": nonce5.hex(),
        "nonce_components": {
            "epoch": 0,
            "direction": 0,
            "counter": 0xFFFFFFFF,
        },
        "plaintext": plaintext5.hex(),
        "aad": aad5.hex(),
        "ciphertext": ciphertext5.hex(),
    })

    return vectors


def generate_frame_vectors() -> dict[str, Any]:
    """Generate frame encoding test vectors."""
    vectors = {
        "_metadata": {
            "description": "Frame encoding test vectors for NOMAD v1.0",
            "generated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "generator": "specs/generate_vectors.py",
            "protocol_version": NOMAD_VERSION,
        },
        "_notes": [
            "All integers are little-endian unless noted",
            "Session ID is 6 bytes",
            "Nonce counter is 8 bytes (LE64)",
        ],
        "data_frame_headers": [],
        "sync_messages": [],
    }

    # Data frame headers
    headers = [
        {
            "name": "basic_data_frame",
            "description": "Basic data frame header",
            "frame_type": FRAME_DATA,
            "flags": 0x00,
            "session_id": "010203040506",
            "nonce_counter": 0,
        },
        {
            "name": "ack_only_frame",
            "description": "Ack-only data frame",
            "frame_type": FRAME_DATA,
            "flags": 0x01,
            "session_id": "AABBCCDDEEFF",
            "nonce_counter": 42,
        },
        {
            "name": "with_extension_flag",
            "description": "Data frame with extension flag",
            "frame_type": FRAME_DATA,
            "flags": 0x02,
            "session_id": "112233445566",
            "nonce_counter": 1000,
        },
    ]

    for h in headers:
        session_id = bytes.fromhex(h["session_id"])
        encoded = encode_data_frame_header(h["flags"], session_id, h["nonce_counter"])
        h["encoded"] = encoded.hex()
        h["encoded_length"] = len(encoded)
        vectors["data_frame_headers"].append(h)

    # Sync messages
    sync_msgs = [
        {
            "name": "basic_sync",
            "description": "Basic sync message with diff",
            "sender_state_num": 5,
            "acked_state_num": 3,
            "base_state_num": 4,
            "diff": "48656c6c6f",  # "Hello"
        },
        {
            "name": "ack_only_sync",
            "description": "Ack-only sync message (empty diff)",
            "sender_state_num": 10,
            "acked_state_num": 10,
            "base_state_num": 0,
            "diff": "",
        },
        {
            "name": "initial_sync",
            "description": "Initial sync (all zeros except sender)",
            "sender_state_num": 1,
            "acked_state_num": 0,
            "base_state_num": 0,
            "diff": "696e697469616c",  # "initial"
        },
    ]

    for s in sync_msgs:
        diff = bytes.fromhex(s["diff"])
        encoded = encode_sync_message(
            s["sender_state_num"],
            s["acked_state_num"],
            s["base_state_num"],
            diff
        )
        s["encoded"] = encoded.hex()
        s["encoded_length"] = len(encoded)
        s["diff_length"] = len(diff)
        vectors["sync_messages"].append(s)

    return vectors


def generate_nonce_vectors() -> dict[str, Any]:
    """Generate nonce construction test vectors."""
    vectors = {
        "_metadata": {
            "description": "Nonce construction test vectors for NOMAD v1.0",
            "generated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "generator": "specs/generate_vectors.py",
            "protocol_version": NOMAD_VERSION,
        },
        "_notes": [
            "Nonce is 24 bytes for XChaCha20",
            "Layout: [epoch:4][direction:1][zeros:11][counter:8]",
            "Epoch and counter are little-endian",
        ],
        "vectors": []
    }

    test_cases = [
        {"epoch": 0, "direction": 0, "counter": 0, "name": "initial_initiator"},
        {"epoch": 0, "direction": 1, "counter": 0, "name": "initial_responder"},
        {"epoch": 0, "direction": 0, "counter": 1, "name": "second_frame"},
        {"epoch": 1, "direction": 0, "counter": 0, "name": "after_rekey"},
        {"epoch": 0, "direction": 0, "counter": 0xFFFFFFFFFFFFFFFF, "name": "max_counter"},
        {"epoch": 0xFFFFFFFF, "direction": 0, "counter": 0, "name": "max_epoch"},
    ]

    for tc in test_cases:
        nonce = construct_nonce(tc["epoch"], tc["direction"], tc["counter"])
        vectors["vectors"].append({
            "name": tc["name"],
            "epoch": tc["epoch"],
            "direction": tc["direction"],
            "direction_meaning": "initiator->responder" if tc["direction"] == 0 else "responder->initiator",
            "counter": tc["counter"],
            "nonce": nonce.hex(),
        })

    return vectors


def generate_sync_vectors() -> dict[str, Any]:
    """Generate sync layer test vectors.

    These vectors test:
    - Sync message encoding/decoding
    - State version tracking
    - Ack-only messages
    - Full sync sessions
    """
    vectors = {
        "_metadata": {
            "description": "Sync layer test vectors for NOMAD v1.0",
            "generated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "generator": "specs/generate_vectors.py",
            "protocol_version": NOMAD_VERSION,
        },
        "_notes": [
            "All integers are little-endian",
            "Sync message header: sender(8) + acked(8) + base(8) + diff_len(4) = 28 bytes",
            "Diff payload is application-defined, here we use simple ASCII for testing",
        ],
        "sync_messages": [],
        "convergence_scenarios": [],
    }

    # Basic sync message vectors
    sync_cases = [
        {
            "name": "initial_state",
            "description": "First sync message from initiator (state 1, acking nothing)",
            "sender_state_num": 1,
            "acked_state_num": 0,
            "base_state_num": 0,
            "diff_ascii": "initial state",
        },
        {
            "name": "normal_sync",
            "description": "Normal sync with state update and ack",
            "sender_state_num": 5,
            "acked_state_num": 3,
            "base_state_num": 4,
            "diff_ascii": "state delta",
        },
        {
            "name": "ack_only",
            "description": "Ack-only message (no state change, empty diff)",
            "sender_state_num": 10,
            "acked_state_num": 10,
            "base_state_num": 0,
            "diff_ascii": "",
        },
        {
            "name": "large_version_numbers",
            "description": "Large version numbers (near max uint64)",
            "sender_state_num": 0xFFFFFFFFFFFF,  # 48-bit max (realistic)
            "acked_state_num": 0xFFFFFFFFFFFE,
            "base_state_num": 0xFFFFFFFFFFFD,
            "diff_ascii": "big",
        },
        {
            "name": "binary_diff",
            "description": "Sync with binary diff payload (not ASCII)",
            "sender_state_num": 100,
            "acked_state_num": 99,
            "base_state_num": 99,
            "diff_hex": "deadbeef00112233",  # Binary data
        },
        {
            "name": "empty_initial",
            "description": "Empty initial state (all zeros except sender=1)",
            "sender_state_num": 1,
            "acked_state_num": 0,
            "base_state_num": 0,
            "diff_ascii": "",
        },
        {
            "name": "retransmit_scenario",
            "description": "Retransmit of state 5 (ack moved forward)",
            "sender_state_num": 5,
            "acked_state_num": 7,
            "base_state_num": 4,
            "diff_ascii": "retransmit",
        },
    ]

    for case in sync_cases:
        if "diff_hex" in case:
            diff = bytes.fromhex(case["diff_hex"])
            diff_repr = {"hex": case["diff_hex"]}
        else:
            diff = case["diff_ascii"].encode("utf-8")
            diff_repr = {"ascii": case["diff_ascii"], "hex": diff.hex()}

        encoded = encode_sync_message(
            case["sender_state_num"],
            case["acked_state_num"],
            case["base_state_num"],
            diff,
        )

        vectors["sync_messages"].append({
            "name": case["name"],
            "description": case["description"],
            "sender_state_num": case["sender_state_num"],
            "acked_state_num": case["acked_state_num"],
            "base_state_num": case["base_state_num"],
            "diff": diff_repr,
            "diff_length": len(diff),
            "encoded": encoded.hex(),
            "encoded_length": len(encoded),
        })

    # Convergence scenarios - multi-message sequences
    # Scenario 1: Normal exchange
    scenario1_messages = [
        ("A->B", 1, 0, 0, "hello"),       # A sends initial
        ("B->A", 1, 1, 0, "world"),        # B sends initial, acks A's 1
        ("A->B", 2, 1, 1, "update1"),      # A updates, acks B's 1
        ("B->A", 2, 2, 1, "update2"),      # B updates, acks A's 2
    ]

    scenario1 = {
        "name": "normal_convergence",
        "description": "Normal sync convergence between two peers",
        "messages": [],
    }

    for direction, sender, acked, base, diff_text in scenario1_messages:
        diff = diff_text.encode("utf-8")
        encoded = encode_sync_message(sender, acked, base, diff)
        scenario1["messages"].append({
            "direction": direction,
            "sender_state_num": sender,
            "acked_state_num": acked,
            "base_state_num": base,
            "diff_ascii": diff_text,
            "encoded": encoded.hex(),
        })

    vectors["convergence_scenarios"].append(scenario1)

    # Scenario 2: Packet loss and recovery
    scenario2 = {
        "name": "packet_loss_recovery",
        "description": "Recovery from lost packets (idempotent diffs)",
        "messages": [],
        "notes": [
            "Message 2 is lost in transit",
            "Peer retransmits and receiver handles idempotently",
        ],
    }

    scenario2_messages = [
        ("A->B", 1, 0, 0, "msg1", "delivered"),
        ("A->B", 2, 0, 1, "msg2", "LOST"),
        ("A->B", 3, 0, 2, "msg3", "delivered"),  # B receives 3, skips 2
        ("B->A", 1, 3, 0, "ack", "delivered"),   # B acks 3
        ("A->B", 3, 1, 2, "msg3", "retransmit"), # A retransmits 3 (idempotent)
    ]

    for direction, sender, acked, base, diff_text, status in scenario2_messages:
        diff = diff_text.encode("utf-8")
        encoded = encode_sync_message(sender, acked, base, diff)
        scenario2["messages"].append({
            "direction": direction,
            "sender_state_num": sender,
            "acked_state_num": acked,
            "base_state_num": base,
            "diff_ascii": diff_text,
            "status": status,
            "encoded": encoded.hex(),
        })

    vectors["convergence_scenarios"].append(scenario2)

    return vectors


def generate_handshake_vectors() -> dict[str, Any]:
    """Generate handshake test vectors.

    Note: Full Noise_IK vectors require the snow library.
    These are simplified vectors for frame structure testing.
    """
    vectors = {
        "_metadata": {
            "description": "Handshake structure test vectors for NOMAD v1.0",
            "generated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "generator": "specs/generate_vectors.py",
            "protocol_version": NOMAD_VERSION,
        },
        "_notes": [
            "Full Noise_IK test vectors require the snow library",
            "These vectors test frame structure, not crypto correctness",
            "For crypto validation, use snow's test vectors",
            "rekey_auth_key is derived from static DH for post-compromise security",
        ],
        "keypairs": [],
        "handshake_init_structure": {},
        "handshake_resp_structure": {},
        "key_derivation": {},
    }

    # Generate deterministic keypairs for testing
    keypairs = [
        ("initiator_static", "nomad-initiator-static-seed"),
        ("initiator_ephemeral", "nomad-initiator-ephemeral-seed"),
        ("responder_static", "nomad-responder-static-seed"),
        ("responder_ephemeral", "nomad-responder-ephemeral-seed"),
    ]

    keypair_data = {}
    for name, seed in keypairs:
        priv, pub = deterministic_keypair(seed)
        keypair_data[name] = {"private": priv, "public": pub}
        vectors["keypairs"].append({
            "name": name,
            "seed": seed,
            "private_key": priv.hex(),
            "public_key": pub.hex(),
        })

    # HandshakeInit structure (not cryptographically valid, just structure)
    init_ephemeral = vectors["keypairs"][1]["public_key"]
    vectors["handshake_init_structure"] = {
        "description": "HandshakeInit frame structure (Type 0x01)",
        "fields": [
            {"name": "type", "offset": 0, "size": 1, "value": "01"},
            {"name": "reserved", "offset": 1, "size": 1, "value": "00"},
            {"name": "protocol_version", "offset": 2, "size": 2, "value": "0100", "decoded": PROTOCOL_VERSION},
            {"name": "initiator_ephemeral", "offset": 4, "size": 32, "value": init_ephemeral},
            {"name": "encrypted_static", "offset": 36, "size": 48, "value": "(encrypted, 32 bytes + 16 tag)"},
            {"name": "encrypted_payload", "offset": 84, "size": "variable", "value": "(state_type_id + extensions + tag)"},
        ],
        "minimum_size": 100,
    }

    # HandshakeResp structure
    resp_ephemeral = vectors["keypairs"][3]["public_key"]
    session_id = deterministic_bytes("session-id-seed", SESSION_ID_SIZE)
    vectors["handshake_resp_structure"] = {
        "description": "HandshakeResp frame structure (Type 0x02)",
        "fields": [
            {"name": "type", "offset": 0, "size": 1, "value": "02"},
            {"name": "reserved", "offset": 1, "size": 1, "value": "00"},
            {"name": "session_id", "offset": 2, "size": 6, "value": session_id.hex()},
            {"name": "responder_ephemeral", "offset": 8, "size": 32, "value": resp_ephemeral},
            {"name": "encrypted_payload", "offset": 40, "size": "variable", "value": "(negotiated extensions + tag)"},
        ],
        "minimum_size": 56,
    }

    # Key derivation vectors (PCS fix)
    # Compute static DH: DH(s_initiator, S_responder)
    initiator_static_priv = keypair_data["initiator_static"]["private"]
    responder_static_pub = keypair_data["responder_static"]["public"]
    static_dh = crypto_scalarmult(initiator_static_priv, responder_static_pub)

    # Derive rekey_auth_key
    rekey_auth_key = derive_rekey_auth_key(static_dh)

    # Use a deterministic handshake hash for session key derivation example
    handshake_hash = deterministic_bytes("handshake-hash-seed", 32)
    initiator_key, responder_key = derive_session_keys(handshake_hash)

    vectors["key_derivation"] = {
        "description": "Key derivation test vectors (SECURITY.md §Session Key Derivation)",
        "_notes": [
            "static_dh = DH(initiator_static_priv, responder_static_pub)",
            "rekey_auth_key = HKDF-Expand(static_dh, 'nomad v1 rekey auth', 32)",
            "session_keys = HKDF-Expand(handshake_hash, 'nomad v1 session keys', 64)",
            "rekey_auth_key provides post-compromise security during rekeying",
        ],
        "static_dh": {
            "initiator_static_private": initiator_static_priv.hex(),
            "responder_static_public": responder_static_pub.hex(),
            "shared_secret": static_dh.hex(),
        },
        "rekey_auth_key": {
            "input_static_dh": static_dh.hex(),
            "info": REKEY_AUTH_INFO.decode("utf-8"),
            "output": rekey_auth_key.hex(),
            "output_length": 32,
        },
        "session_keys": {
            "handshake_hash": handshake_hash.hex(),
            "info": SESSION_KEY_INFO.decode("utf-8"),
            "initiator_key": initiator_key.hex(),
            "responder_key": responder_key.hex(),
        },
    }

    return vectors


def generate_rekey_vectors() -> dict[str, Any]:
    """Generate rekey test vectors for post-compromise security.

    These vectors test the PCS fix: rekey key derivation that mixes
    rekey_auth_key to prevent active attackers from maintaining access.
    """
    vectors = {
        "_metadata": {
            "description": "Rekey test vectors for NOMAD v1.0 (PCS fix)",
            "generated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "generator": "specs/generate_vectors.py",
            "protocol_version": NOMAD_VERSION,
        },
        "_notes": [
            "These vectors test the Post-Compromise Security (PCS) fix",
            "rekey_auth_key is derived from static DH during handshake",
            "New keys = HKDF(ephemeral_dh || rekey_auth_key, 'nomad v1 rekey' || LE32(epoch), 64)",
            "An attacker with only session keys cannot derive new rekey keys",
        ],
        "rekey_vectors": [],
    }

    # Use same keypairs as handshake vectors for consistency
    initiator_static_priv, initiator_static_pub = deterministic_keypair("nomad-initiator-static-seed")
    responder_static_priv, responder_static_pub = deterministic_keypair("nomad-responder-static-seed")

    # Compute static DH and rekey_auth_key (established during handshake)
    static_dh = crypto_scalarmult(initiator_static_priv, responder_static_pub)
    rekey_auth_key = derive_rekey_auth_key(static_dh)

    # Vector 1: Epoch 0 → 1 transition
    e1_init_priv, e1_init_pub = deterministic_keypair("rekey-epoch1-initiator-ephemeral")
    e1_resp_priv, e1_resp_pub = deterministic_keypair("rekey-epoch1-responder-ephemeral")
    e1_ephemeral_dh = crypto_scalarmult(e1_init_priv, e1_resp_pub)
    e1_init_key, e1_resp_key = derive_rekey_keys(e1_ephemeral_dh, rekey_auth_key, epoch=1)

    vectors["rekey_vectors"].append({
        "name": "epoch_0_to_1",
        "description": "First rekey: transition from epoch 0 to epoch 1",
        "epoch": 1,
        "initiator_ephemeral": {
            "seed": "rekey-epoch1-initiator-ephemeral",
            "private_key": e1_init_priv.hex(),
            "public_key": e1_init_pub.hex(),
        },
        "responder_ephemeral": {
            "seed": "rekey-epoch1-responder-ephemeral",
            "private_key": e1_resp_priv.hex(),
            "public_key": e1_resp_pub.hex(),
        },
        "ephemeral_dh": e1_ephemeral_dh.hex(),
        "rekey_auth_key": rekey_auth_key.hex(),
        "info": (REKEY_INFO_PREFIX + struct.pack("<I", 1)).hex(),
        "info_decoded": {
            "prefix": REKEY_INFO_PREFIX.decode("utf-8"),
            "epoch_le32": 1,
        },
        "new_initiator_key": e1_init_key.hex(),
        "new_responder_key": e1_resp_key.hex(),
    })

    # Vector 2: Epoch 1 → 2 transition (the PCS case)
    e2_init_priv, e2_init_pub = deterministic_keypair("rekey-epoch2-initiator-ephemeral")
    e2_resp_priv, e2_resp_pub = deterministic_keypair("rekey-epoch2-responder-ephemeral")
    e2_ephemeral_dh = crypto_scalarmult(e2_init_priv, e2_resp_pub)
    e2_init_key, e2_resp_key = derive_rekey_keys(e2_ephemeral_dh, rekey_auth_key, epoch=2)

    vectors["rekey_vectors"].append({
        "name": "epoch_1_to_2_pcs_case",
        "description": "Second rekey: epoch 1→2 (PCS test - attacker with epoch 1 keys cannot derive epoch 2)",
        "epoch": 2,
        "_pcs_note": "Even if attacker has epoch 1 keys, they need rekey_auth_key to compute epoch 2 keys",
        "initiator_ephemeral": {
            "seed": "rekey-epoch2-initiator-ephemeral",
            "private_key": e2_init_priv.hex(),
            "public_key": e2_init_pub.hex(),
        },
        "responder_ephemeral": {
            "seed": "rekey-epoch2-responder-ephemeral",
            "private_key": e2_resp_priv.hex(),
            "public_key": e2_resp_pub.hex(),
        },
        "ephemeral_dh": e2_ephemeral_dh.hex(),
        "rekey_auth_key": rekey_auth_key.hex(),
        "info": (REKEY_INFO_PREFIX + struct.pack("<I", 2)).hex(),
        "info_decoded": {
            "prefix": REKEY_INFO_PREFIX.decode("utf-8"),
            "epoch_le32": 2,
        },
        "new_initiator_key": e2_init_key.hex(),
        "new_responder_key": e2_resp_key.hex(),
    })

    # Vector 3: High epoch number
    e100_init_priv, e100_init_pub = deterministic_keypair("rekey-epoch100-initiator-ephemeral")
    e100_resp_priv, e100_resp_pub = deterministic_keypair("rekey-epoch100-responder-ephemeral")
    e100_ephemeral_dh = crypto_scalarmult(e100_init_priv, e100_resp_pub)
    e100_init_key, e100_resp_key = derive_rekey_keys(e100_ephemeral_dh, rekey_auth_key, epoch=100)

    vectors["rekey_vectors"].append({
        "name": "epoch_high_number",
        "description": "High epoch number (100) - tests epoch encoding in info parameter",
        "epoch": 100,
        "initiator_ephemeral": {
            "seed": "rekey-epoch100-initiator-ephemeral",
            "private_key": e100_init_priv.hex(),
            "public_key": e100_init_pub.hex(),
        },
        "responder_ephemeral": {
            "seed": "rekey-epoch100-responder-ephemeral",
            "private_key": e100_resp_priv.hex(),
            "public_key": e100_resp_pub.hex(),
        },
        "ephemeral_dh": e100_ephemeral_dh.hex(),
        "rekey_auth_key": rekey_auth_key.hex(),
        "info": (REKEY_INFO_PREFIX + struct.pack("<I", 100)).hex(),
        "info_decoded": {
            "prefix": REKEY_INFO_PREFIX.decode("utf-8"),
            "epoch_le32": 100,
        },
        "new_initiator_key": e100_init_key.hex(),
        "new_responder_key": e100_resp_key.hex(),
    })

    # Add intermediate values section for debugging
    vectors["intermediate_values"] = {
        "description": "Intermediate values for debugging implementations",
        "static_keys": {
            "initiator_static_private": initiator_static_priv.hex(),
            "initiator_static_public": initiator_static_pub.hex(),
            "responder_static_private": responder_static_priv.hex(),
            "responder_static_public": responder_static_pub.hex(),
        },
        "static_dh": static_dh.hex(),
        "rekey_auth_key": {
            "input": static_dh.hex(),
            "info": REKEY_AUTH_INFO.decode("utf-8"),
            "output": rekey_auth_key.hex(),
        },
    }

    return vectors


# =============================================================================
# Main
# =============================================================================

def write_json5(data: dict, path: Path) -> None:
    """Write data as JSON5 with comments preserved."""
    # json5 library doesn't support writing comments, so we use regular json
    # but with a .json5 extension and add _notes fields for documentation
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, 'w') as f:
        # Write header comment
        f.write(f"// NOMAD Protocol v{NOMAD_VERSION} Test Vectors\n")
        f.write(f"// Generated by specs/generate_vectors.py\n")
        f.write(f"// DO NOT EDIT - regenerate with: python specs/generate_vectors.py\n")
        f.write("//\n")
        f.write("// These vectors are the SOURCE OF TRUTH for all implementations.\n")
        f.write("// If your implementation doesn't match these values, your implementation is wrong.\n")
        f.write("\n")

        # Write JSON with indentation
        json.dump(data, f, indent=2)
        f.write("\n")

    print(f"  Written: {path}")


def main():
    print(f"NOMAD Protocol Test Vector Generator v{NOMAD_VERSION}")
    print("=" * 60)
    print()

    # Generate all vector sets
    print("Generating vectors...")

    aead_vectors = generate_aead_vectors()
    write_json5(aead_vectors, VECTORS_DIR / "aead_vectors.json5")

    frame_vectors = generate_frame_vectors()
    write_json5(frame_vectors, VECTORS_DIR / "frame_vectors.json5")

    nonce_vectors = generate_nonce_vectors()
    write_json5(nonce_vectors, VECTORS_DIR / "nonce_vectors.json5")

    handshake_vectors = generate_handshake_vectors()
    write_json5(handshake_vectors, VECTORS_DIR / "handshake_vectors.json5")

    sync_vectors = generate_sync_vectors()
    write_json5(sync_vectors, VECTORS_DIR / "sync_vectors.json5")

    rekey_vectors = generate_rekey_vectors()
    write_json5(rekey_vectors, VECTORS_DIR / "rekey_vectors.json5")

    print()
    print("=" * 60)
    print(f"Generated 6 vector files in {VECTORS_DIR}")
    print()
    print("To verify idempotency, run again - output should be identical.")
    print("(Except for _metadata.generated timestamp)")


if __name__ == "__main__":
    main()
