"""
IoT-CBDC Dual-Offline Payment Protocol Simulator
=================================================
Core simulation engine for PUF-CBDC protocol on resource-constrained
IoT devices (ESP32/nRF52840). All cryptographic operations use real
primitives (Curve25519, Ed25519, AES-256-GCM, SHA-256, HKDF).

Matches the protocol described in IEEE_Full_Paper.tex:
  - 5-message BLE handshake
  - PUF boot with BCH error correction
  - Schnorr NIZKP mutual authentication
  - ECDH + HKDF session key
  - Pedersen commitments for amount privacy
  - Dual-table token lifecycle (Unspent / Pending)
  - WAL-protected atomic operations
  - Compliance enforcement (V_MAX, S_MAX, R_MAX, N_MAX)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import re
import statistics
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Real cryptography via `cryptography` library
# ---------------------------------------------------------------------------
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ARM_SCALE_FACTOR = 87  # Apple Silicon → ARM Cortex-M4 240 MHz (legacy uniform factor)

# ── Per-primitive ARM scaling (v2) ─────────────────────────────────
# A single uniform factor over-penalizes symmetric crypto: the ESP32 has
# AES-128/256 and SHA-256 hardware accelerators, so AES-GCM/SHA/HKDF run
# within ~10x of desktop speed, while big-integer ECC (software, micro-ecc
# class) scales by ~87x. BLE air time is platform-independent (1x).
ARM_SCALE_FACTORS = {
    "ecc": 87.0,   # Curve25519/Ed25519/Schnorr/Pedersen big-int ops
    "sym": 10.0,   # AES-256-GCM, SHA-256, HKDF (ESP32 HW accelerators)
    "ble": 1.0,    # air time, platform-independent
}

# ── SE050 I/O model (v2, analytical) ───────────────────────────────
# Per-object secure-store operation costs over I2C @ 400 kHz including
# APDU/SCP03 overhead (order-of-magnitude from NXP SE05x datasheet and
# application notes). Used for ARM projections only; not added to the
# measured (host) timings.
SE050_IO_US = {
    "session": 500.0,   # SCP03 session touch per transaction side
    "write": 1800.0,    # store one token object
    "delete": 1500.0,   # atomic delete of one token object
}


def se050_io_us(n_tokens: int) -> float:
    """Analytical SE050 I/O time for one transaction (sender deletes n,
    receiver stores n, both touch counters/session)."""
    return 2 * SE050_IO_US["session"] + n_tokens * (SE050_IO_US["delete"] + SE050_IO_US["write"])


# ── v3: compact binary wire size for BLE messages ──────────────────
# The simulator exchanges JSON with hex strings for convenience; device firmware
# sends raw bytes. BLE air time is therefore costed on the binary encoding:
# hex fields -> raw bytes, denomination -> 1 B, other integers -> 4 B,
# identifiers -> UTF-8 bytes, JSON keys and punctuation not transmitted.
_HEX_RE = re.compile(r"^[0-9a-f]+$")
AES_GCM_OVERHEAD = 12 + 16  # nonce + tag


def wire_size(obj, key: str = "") -> int:
    if isinstance(obj, dict):
        return sum(wire_size(v, k) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return sum(wire_size(v, key) for v in obj)
    if isinstance(obj, bool):
        return 1
    if isinstance(obj, int):
        return 1 if key == "denomination" else 4
    if isinstance(obj, float):
        return 8
    if isinstance(obj, (bytes, bytearray)):
        return len(obj)
    if isinstance(obj, str):
        if len(obj) >= 16 and len(obj) % 2 == 0 and _HEX_RE.match(obj):
            return len(obj) // 2
        return len(obj.encode())
    return 0


# ===================================================================
# Timing helper
# ===================================================================
class Timer:
    """Microsecond-precision timer that records measured + ARM-scaled."""

    def __init__(self):
        self._start = 0.0
        self.elapsed_us = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_):
        self.elapsed_us = (time.perf_counter() - self._start) * 1_000_000

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_us / 1000.0

    @property
    def arm_us(self) -> float:
        return self.elapsed_us * ARM_SCALE_FACTOR

    @property
    def arm_ms(self) -> float:
        return self.arm_us / 1000.0


# ===================================================================
# Crypto primitives with per-operation timing
# ===================================================================
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_derive(ikm: bytes, info: bytes, length: int = 32, salt: Optional[bytes] = None) -> bytes:
    kdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return kdf.derive(ikm)


def ed25519_keygen() -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return sk, pk


def ed25519_sign(sk, message: bytes) -> bytes:
    return sk.sign(message)


def ed25519_verify(pk_bytes: bytes, message: bytes, sig: bytes) -> bool:
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
        pk.verify(sig, message)
        return True
    except Exception:
        return False


def x25519_keygen() -> Tuple[x25519.X25519PrivateKey, bytes]:
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return sk, pk


def ecdh_shared_secret(sk, peer_pk_bytes: bytes) -> bytes:
    peer_pk = x25519.X25519PublicKey.from_public_bytes(peer_pk_bytes)
    return sk.exchange(peer_pk)


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce, ct[:-16], ct[-16:]


def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct + tag, None)


# ===================================================================
# Ed25519 curve arithmetic (for real Schnorr NIZKP & Pedersen commits)
# Paper Section III-C & IV-F: twisted Edwards -x²+y²=1+d·x²·y²
# Uses extended projective coordinates (X:Y:Z:T) for performance
# ===================================================================
_ED_P = 2**255 - 19
_ED_D = -121665 * pow(121666, 2**255 - 21, 2**255 - 19) % (2**255 - 19)
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_ED_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_ED_IDENT = (0, 1, 1, 0)
_ED_B = (_ED_BX, _ED_BY, 1, _ED_BX * _ED_BY % _ED_P)


def _ed_add(P1, P2):
    """Extended twisted Edwards point addition (add-2008-hwcd)."""
    X1, Y1, Z1, T1 = P1
    X2, Y2, Z2, T2 = P2
    A = X1 * X2 % _ED_P
    B = Y1 * Y2 % _ED_P
    C = T1 * _ED_D % _ED_P * T2 % _ED_P
    D = Z1 * Z2 % _ED_P
    E = ((X1 + Y1) * (X2 + Y2) - A - B) % _ED_P
    F = (D - C) % _ED_P
    G = (D + C) % _ED_P
    H = (B + A) % _ED_P  # a=-1: H = B - a*A = B + A
    X3 = E * F % _ED_P
    Y3 = G * H % _ED_P
    T3 = E * H % _ED_P
    Z3 = F * G % _ED_P
    return (X3, Y3, Z3, T3)


def _ed_double(P):
    """Extended twisted Edwards point doubling (dbl-2008-hwcd)."""
    X1, Y1, Z1, _ = P
    A = X1 * X1 % _ED_P
    B = Y1 * Y1 % _ED_P
    C = 2 * Z1 * Z1 % _ED_P
    D = (_ED_P - A) % _ED_P  # a*A = -A
    E = ((X1 + Y1) * (X1 + Y1) - A - B) % _ED_P
    G = (D + B) % _ED_P
    F = (G - C) % _ED_P
    H_ = (D - B) % _ED_P
    X3 = E * F % _ED_P
    Y3 = G * H_ % _ED_P
    T3 = E * H_ % _ED_P
    Z3 = F * G % _ED_P
    return (X3, Y3, Z3, T3)


def _ed_scalarmult(s, P):
    """Scalar multiplication via double-and-add."""
    s = s % _ED_L
    result = _ED_IDENT
    current = P
    while s > 0:
        if s & 1:
            result = _ed_add(result, current)
        current = _ed_double(current)
        s >>= 1
    return result


def _ed_encode(P):
    """Encode extended point to 32-byte compressed form (RFC 8032)."""
    X, Y, Z, _ = P
    zi = pow(Z, _ED_P - 2, _ED_P)
    x = X * zi % _ED_P
    y = Y * zi % _ED_P
    s = bytearray(y.to_bytes(32, 'little'))
    if x & 1:
        s[31] |= 0x80
    return bytes(s)


def _ed_decode(b):
    """Decode 32-byte compressed point to extended coordinates."""
    y = int.from_bytes(b, 'little')
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    y2 = y * y % _ED_P
    den = (_ED_D * y2 + 1) % _ED_P
    x2 = (y2 - 1) * pow(den, _ED_P - 2, _ED_P) % _ED_P
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if x * x % _ED_P != x2:
        x = x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
    if x * x % _ED_P != x2:
        raise ValueError("point not on curve")
    if (x & 1) != sign:
        x = _ED_P - x
    return (x, y, 1, x * y % _ED_P)


def _ed_sk_scalar(ed_sk) -> int:
    """Extract Ed25519 signing scalar from private key object."""
    seed = ed_sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(bytes(a), 'little')


def _hash_to_ed_point(tag: bytes):
    """Nothing-up-my-sleeve hash-to-curve for second Pedersen generator."""
    for i in range(256):
        y = int.from_bytes(sha256(tag + bytes([i])), 'little') % _ED_P
        y2 = y * y % _ED_P
        den = (_ED_D * y2 + 1) % _ED_P
        x2 = (y2 - 1) * pow(den, _ED_P - 2, _ED_P) % _ED_P
        x = pow(x2, (_ED_P + 3) // 8, _ED_P)
        if x * x % _ED_P == x2:
            return (x, y, 1, x * y % _ED_P)
        x = x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
        if x * x % _ED_P == x2:
            return (x, y, 1, x * y % _ED_P)
    raise ValueError("hash_to_point failed")


_ED_H = _hash_to_ed_point(b"PUF_CBDC_Pedersen_Generator_H")


# ===================================================================
# Schnorr NIZKP (Paper Section IV-F: real (R, s) proof structure)
# ===================================================================
def schnorr_prove(ed_sk, pk_bytes: bytes, context: bytes) -> bytes:
    """Schnorr NIZKP proof: k <- random, R = k·B,
    e = SHA-256(pk||R||context), s = (k - e·sk) mod L.
    Returns R||s (64 bytes)."""
    sk_scalar = _ed_sk_scalar(ed_sk)
    k = int.from_bytes(os.urandom(32), 'little') % _ED_L
    if k == 0:
        k = 1
    R_point = _ed_scalarmult(k, _ED_B)
    R_bytes = _ed_encode(R_point)
    e = int.from_bytes(sha256(pk_bytes + R_bytes + context), 'little') % _ED_L
    s = (k - e * sk_scalar) % _ED_L
    return R_bytes + s.to_bytes(32, 'little')


def schnorr_verify(pk_bytes: bytes, context: bytes, proof: bytes) -> bool:
    """Verify Schnorr proof: check s·B + e·pk == R."""
    R_bytes, s_bytes = proof[:32], proof[32:]
    s = int.from_bytes(s_bytes, 'little')
    e = int.from_bytes(sha256(pk_bytes + R_bytes + context), 'little') % _ED_L
    sB = _ed_scalarmult(s, _ED_B)
    pk_point = _ed_decode(pk_bytes)
    ePK = _ed_scalarmult(e, pk_point)
    check = _ed_add(sB, ePK)
    return _ed_encode(check) == R_bytes


# ===================================================================
# Pedersen commitment (Paper Theorem 2: C = v·H + r·B, info-theoretic hiding)
# ===================================================================
def pedersen_commit(value: int, blinding: bytes) -> bytes:
    """EC Pedersen commitment C = v·H + r·B (32-byte encoded point)."""
    v = value % _ED_L
    r = int.from_bytes(blinding, 'little') % _ED_L
    vH = _ed_scalarmult(v, _ED_H)
    rB = _ed_scalarmult(r, _ED_B)
    C = _ed_add(vH, rB)
    return _ed_encode(C)


def pedersen_verify(value: int, blinding: bytes, commitment: bytes) -> bool:
    """Verify Pedersen commitment."""
    return pedersen_commit(value, blinding) == commitment


# ===================================================================
# PUF Simulator
# ===================================================================
@dataclass
class PUFEnrollment:
    fingerprint: bytes
    helper_data: bytes
    key: bytes
    dark_bits: set = field(default_factory=set)  # ~4% unstable SRAM cells


class PUFEngine:
    def __init__(self, bit_length: int = 2048, correction_bits: int = 50):
        # Paper: BCH(2048,50) with dark-bit noise model.
        # ~4% of SRAM cells are flagged unstable during enrollment;
        # only these cells may flip during noisy reads.
        self.bit_length = bit_length
        self.byte_length = bit_length // 8
        self.correction_bits = correction_bits
        self._db: Dict[str, PUFEnrollment] = {}

    def enroll(self, device_id: str, rng: random.Random) -> PUFEnrollment:
        fp = bytes(rng.getrandbits(8) for _ in range(self.byte_length))
        # Dark-bit model: ~4% of cells are unstable (paper Section VI-A)
        dark_bits = set()
        for i in range(self.bit_length):
            if rng.random() < 0.04:
                dark_bits.add(i)
        key = sha256(fp)
        rec = PUFEnrollment(fingerprint=fp, helper_data=fp, key=key, dark_bits=dark_bits)
        self._db[device_id] = rec
        return rec

    def noisy_read(self, device_id: str, rng: random.Random, ber: float) -> bytes:
        """Dark-bit noise: only ~4% unstable cells flip, p_dark = min(5·BER, 0.95)."""
        src = bytearray(self._db[device_id].fingerprint)
        dark_bits = self._db[device_id].dark_bits
        p_dark = min(5 * ber, 0.95)
        for bit_pos in dark_bits:
            if rng.random() < p_dark:
                byte_idx = bit_pos // 8
                bit_idx = bit_pos % 8
                src[byte_idx] ^= (1 << bit_idx)
        return bytes(src)

    def recover(self, device_id: str, noisy: bytes) -> Tuple[bytes, int]:
        ref = self._db[device_id].helper_data
        dist = sum(bin(a ^ b).count('1') for a, b in zip(noisy, ref))
        if dist > self.correction_bits:
            raise ValueError(f"PUF recovery failed: {dist} > {self.correction_bits}")
        return sha256(ref), dist

    def get_key(self, device_id: str) -> bytes:
        return self._db[device_id].key


# ===================================================================
# Token and transaction models
# ===================================================================
class TokenState(str, Enum):
    UNSPENT = "unspent"
    PENDING = "pending"
    SPENT = "spent"
    LOCKED = "locked"


class TxStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    LOCKED = "locked"


DENOMINATIONS = [1, 2, 5, 10, 20, 50, 100]  # ₹


@dataclass
class Token:
    tid: str
    denomination: int
    owner_pk: bytes
    issuer_bank: str
    cb_signature: bytes
    expiry_ts: int
    state: TokenState = TokenState.UNSPENT


@dataclass
class TxRecord:
    tx_id: str
    sender_id: str
    receiver_id: str
    amount: int
    n_tokens: int
    status: TxStatus
    failure_reason: str = ""
    # Timing breakdown (microseconds, measured)
    puf_boot_us: float = 0.0
    schnorr_prove_us: float = 0.0
    schnorr_verify_us: float = 0.0
    ecdh_us: float = 0.0
    encrypt_us: float = 0.0
    decrypt_us: float = 0.0
    cb_verify_us: float = 0.0
    transfer_sign_us: float = 0.0
    transfer_verify_us: float = 0.0
    pedersen_commit_us: float = 0.0
    pedersen_verify_us: float = 0.0
    hkdf_us: float = 0.0
    compliance_us: float = 0.0
    token_select_us: float = 0.0
    ble_us: float = 0.0
    se_io_us: float = 0.0      # v2: analytical SE050 I/O (ARM projection only)
    total_us: float = 0.0
    # RAM snapshot (bytes)
    ram_bytes: int = 0
    # Protocol messages — actual cryptographic payloads
    protocol_msgs: Optional[Dict[str, Any]] = None


@dataclass
class SyncRecord:
    device_id: str
    tokens_uploaded: int
    tokens_received: int
    tokens_swept: int = 0      # tokens returned to main wallet
    amount_swept: int = 0      # ₹ value swept back
    balance_before_sweep: int = 0
    balance_after_sweep: int = 0
    duration_us: float = 0.0


# ===================================================================
# IoT device compliance policy (matches paper Table II)
# ===================================================================
@dataclass(frozen=True)
class IoTPolicy:
    v_max: int = 200         # ₹200 per transaction
    n_max_tok: int = 50       # max tokens per transaction
    s_max_offline: int = 500  # ₹500 cumulative offline spend
    n_max_tx: int = 4         # max offline transactions before sync
    r_max_offline: int = 500  # ₹500 cumulative offline receive
    b_max: int = 500          # ₹500 max loading balance (bank→device); receive may push above temporarily
    n_max_dev: int = 300      # max tokens in SE050
    freshness_s: int = 15     # timestamp freshness window
    ack_timeout_s: int = 5    # ACK timeout
    token_expiry_days: int = 365


DEFAULT_IOT_POLICY = IoTPolicy()


# ===================================================================
# BLE transport simulator
# ===================================================================
@dataclass
class BLEFrame:
    msg_type: str
    payload_bytes: int
    delivered: bool


class BLETransport:
    MTU = 251  # BLE 5.0 L2CAP MTU
    PHY_RATE = 2_000_000  # 2 Mbps

    def __init__(self, drop_ack_prob: float = 0.0, rng_seed: int = 42):
        self._rng = random.Random(rng_seed)
        self.drop_ack_prob = drop_ack_prob
        self.frames: List[BLEFrame] = []
        self._force_drop_ack = False

    def force_drop_next_ack(self):
        self._force_drop_ack = True

    def send(self, msg_type: str, payload: dict, wire_bytes: Optional[int] = None) -> Tuple[Optional[dict], float, int]:
        """Returns (payload_or_None, ble_time_us, payload_bytes).
        v3: payload_bytes is the compact binary size (see wire_size); the JSON
        size is kept in json_bytes for reference."""
        self.json_bytes = getattr(self, "json_bytes", 0) + len(json.dumps(payload, separators=(",", ":")).encode())
        n_bytes = wire_bytes if wire_bytes is not None else wire_size(payload)
        n_frames = max(1, (n_bytes + self.MTU - 1) // self.MTU)
        ble_time_us = (n_bytes * 8 / self.PHY_RATE) * 1_000_000 + n_frames * 150  # 150 µs IFS

        if msg_type == "msg5_ack":
            if self._force_drop_ack:
                self._force_drop_ack = False
                self.frames.append(BLEFrame(msg_type, n_bytes, False))
                return None, ble_time_us, n_bytes
            if self._rng.random() < self.drop_ack_prob:
                self.frames.append(BLEFrame(msg_type, n_bytes, False))
                return None, ble_time_us, n_bytes

        self.frames.append(BLEFrame(msg_type, n_bytes, True))
        return payload, ble_time_us, n_bytes

    def total_payload_bytes(self) -> int:
        return sum(f.payload_bytes for f in self.frames)

    def total_frames(self) -> int:
        return sum(max(1, (f.payload_bytes + self.MTU - 1) // self.MTU) for f in self.frames)


# ===================================================================
# IoT Sub-Wallet device
# ===================================================================
class IoTDevice:
    """Simulates an ESP32/nRF52840 IoT Sub-Wallet."""

    SE050_STORAGE_BYTES = 50 * 1024  # 50 KB
    TOKEN_SIZE_BYTES = 137
    MCU_FLASH_BYTES = 4 * 1024 * 1024  # 4 MB
    RAM_BYTES = 520 * 1024  # 520 KB

    def __init__(
        self,
        device_id: str,
        bank_id: str,
        puf_engine: PUFEngine,
        cb_pk: bytes,
        cb_sk,
        policy: IoTPolicy = DEFAULT_IOT_POLICY,
        rng_seed: int = 1,
        ber: float = 0.03,
        wallet_id: str = "",
    ):
        self.device_id = device_id
        self.bank_id = bank_id
        self.wallet_id = wallet_id
        self.puf = puf_engine
        self.cb_pk = cb_pk
        self.cb_sk = cb_sk
        self.policy = policy
        self._rng = random.Random(rng_seed)
        self.ber = ber

        # Keys (derived from PUF on boot)
        self.ed_sk = None
        self.ed_pk: bytes = b""
        self.x_sk = None
        self.x_pk: bytes = b""

        # Token storage (dual-table)
        self.unspent: Dict[str, Token] = {}
        self.pending: Dict[str, Token] = {}

        # Compliance counters
        self.offline_tx_count = 0
        self.cumulative_spend = 0
        self.cumulative_receive = 0
        self.seq_no = 0

        # MW-visible state (what MW knows from loading + last sync)
        self.initial_loaded: int = 0  # ₹ loaded by MW at registration (MW knows this)

        # Logs
        self.tx_log: List[TxRecord] = []
        self.sync_log: List[SyncRecord] = []

        # PUF enroll + boot
        self.puf.enroll(device_id, self._rng)
        self.puf_boot_distance = 0
        self.last_puf_boot_us = 0.0

    def puf_boot(self) -> Tuple[float, int]:
        """PUF boot: noisy read → BCH recover → derive keys. Returns (time_us, bit_errors)."""
        with Timer() as t:
            noisy = self.puf.noisy_read(self.device_id, self._rng, self.ber)
            puf_key, dist = self.puf.recover(self.device_id, noisy)
            self.puf_boot_distance = dist

            ed_seed = hkdf_derive(puf_key, b"device-ed25519-seed")
            self.ed_sk = ed25519.Ed25519PrivateKey.from_private_bytes(ed_seed)
            self.ed_pk = self.ed_sk.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )

            x_seed = hkdf_derive(puf_key, b"device-x25519-seed")
            self.x_sk = x25519.X25519PrivateKey.from_private_bytes(x_seed)
            self.x_pk = self.x_sk.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        self.last_puf_boot_us = t.elapsed_us
        return t.elapsed_us, dist

    def balance(self) -> int:
        return sum(tok.denomination for tok in self.unspent.values())

    def token_count(self) -> int:
        return len(self.unspent)

    def se050_usage_bytes(self) -> int:
        return (len(self.unspent) + len(self.pending)) * self.TOKEN_SIZE_BYTES

    def load_tokens(self, denominations: List[int], enforce_bmax: bool = True) -> List[Token]:
        """Bank/MainWallet loads tokens onto this device (re-signed by CB).

        enforce_bmax=True  (default): protocol-conformant — the bank refuses
        to load past the B_max holding cap (paper Table II).
        enforce_bmax=False (legacy): reproduces the original paper run in
        which loading was not capped (stress-test configuration)."""
        loaded = []
        for d in denominations:
            if len(self.unspent) + len(self.pending) >= self.policy.n_max_dev:
                break  # SE050 full — firmware enforces n_max_dev
            if enforce_bmax and self.balance() + d > self.policy.b_max:
                continue  # loading cap B_max — try smaller denominations
            tid = sha256(os.urandom(32)).hex()[:16]
            expiry = int(time.time()) + self.policy.token_expiry_days * 86400
            # CB signature covers ALL token fields per paper Section IV.B
            payload = f"{tid}|{d}|{self.bank_id}|{self.ed_pk.hex()}|{expiry}".encode()
            sig = ed25519_sign(self.cb_sk, payload)
            tok = Token(
                tid=tid,
                denomination=d,
                owner_pk=self.ed_pk,
                issuer_bank=self.bank_id,
                cb_signature=sig,
                expiry_ts=expiry,
            )
            self.unspent[tid] = tok
            loaded.append(tok)
        self.initial_loaded = self.balance()  # MW knows this — it mediated the loading
        return loaded

    def select_tokens(self, amount: int) -> List[Token]:
        """Greedy token selection matching paper Algorithm 5: exact change only.

        Iterates denominations largest-first (₹100→₹1). For each denom,
        picks tokens of that value while remaining >= denom. Aborts if
        exact change cannot be made or >50 tokens selected.
        Also enforces Algorithm 6 checks: owner_pk and expiry.
        """
        now = time.time()
        # Group available tokens by denomination (skip expired/wrong-owner)
        by_denom: Dict[int, List[Token]] = {}
        for tok in self.unspent.values():
            if tok.owner_pk != self.ed_pk:  # Algorithm 6, line 7
                continue
            if now >= tok.expiry_ts:  # Algorithm 6, lines 4-5
                continue
            by_denom.setdefault(tok.denomination, []).append(tok)

        selected = []
        remaining = amount
        for d in [100, 50, 20, 10, 5, 2, 1]:
            pool = by_denom.get(d, [])
            idx = 0
            while remaining >= d and idx < len(pool):
                selected.append(pool[idx])
                remaining -= d
                idx += 1

        if remaining != 0 or len(selected) > 50:
            return []  # no exact change — abort per paper
        return selected

    def compliance_check_send(self, amount: int) -> Optional[str]:
        if amount > self.policy.v_max:
            return f"amount ₹{amount} > V_MAX ₹{self.policy.v_max}"
        if self.offline_tx_count >= self.policy.n_max_tx:
            return f"N_MAX reached ({self.policy.n_max_tx}), sync required"
        if self.cumulative_spend + amount > self.policy.s_max_offline:
            return f"S_MAX exceeded (₹{self.cumulative_spend}+₹{amount} > ₹{self.policy.s_max_offline})"
        return None

    def compliance_check_recv(self, amount: int, n_incoming_tokens: int = 0) -> Optional[str]:
        """Receiving is governed by R_MAX and N_MAX only.
        B_MAX is a *loading* cap (bank→device); offline receiving may
        temporarily push balance above B_MAX. The excess is swept back
        to the Main Wallet during the next synchronization."""
        if self.cumulative_receive + amount > self.policy.r_max_offline:
            return f"R_MAX exceeded (₹{self.cumulative_receive}+₹{amount} > ₹{self.policy.r_max_offline})"
        if self.offline_tx_count >= self.policy.n_max_tx:
            return f"N_MAX reached ({self.policy.n_max_tx}), sync required"
        if n_incoming_tokens > 0:
            current = len(self.unspent) + len(self.pending)
            if current + n_incoming_tokens > self.policy.n_max_dev:
                return f"SE050 full ({current}+{n_incoming_tokens} > {self.policy.n_max_dev})"
        return None

    def sync_with_bank(self) -> SyncRecord:
        """Simulate sync: upload tx_log, clear it, reset counters, move pending→unspent, sweep excess."""
        with Timer() as t:
            uploaded = len(self.tx_log)
            n_pending = len(self.pending)  # BUG-FIX: capture count BEFORE clearing
            # 1. Upload tx_log to bank — bank now has the records
            # 2. Clear local tx_log (bank ACKed receipt)
            self.tx_log.clear()
            # 3. Move pending to unspent (bank confirmed)
            #    LOCKED tokens are resolved by bank — bank decides final state
            for tid, tok in list(self.pending.items()):
                if tok.state == TokenState.LOCKED:
                    # Bank resolves: if receiver got them, discard from sender;
                    # if receiver didn't, restore to unspent
                    pass  # Remove locked tokens (bank handles resolution)
                else:
                    tok.state = TokenState.UNSPENT
                    self.unspent[tid] = tok
            self.pending.clear()
            # 4. Reset compliance counters
            self.offline_tx_count = 0
            self.cumulative_spend = 0
            self.cumulative_receive = 0
            # 5. Balance sweep: return excess tokens to main wallet
            #    Device should hold at most b_max after sync
            balance_before = self.balance()
            swept_count = 0
            swept_amount = 0
            if balance_before > self.policy.b_max:
                target = self.policy.b_max
                # Remove smallest tokens first (paper Section IV-I: smallest denominations first)
                removable = sorted(self.unspent.values(), key=lambda tk: tk.denomination)
                for tok in removable:
                    if self.balance() <= target:
                        break
                    del self.unspent[tok.tid]
                    swept_count += 1
                    swept_amount += tok.denomination
            balance_after = self.balance()
        rec = SyncRecord(
            device_id=self.device_id,
            tokens_uploaded=uploaded,
            tokens_received=n_pending,  # BUG-FIX: use pre-clear count
            tokens_swept=swept_count,
            amount_swept=swept_amount,
            balance_before_sweep=balance_before,
            balance_after_sweep=balance_after,
            duration_us=t.elapsed_us,
        )
        self.sync_log.append(rec)
        return rec


# ===================================================================
# 5-message transaction protocol
# ===================================================================
def run_transaction(
    sender: IoTDevice,
    receiver: IoTDevice,
    amount: int,
    transport: BLETransport,
) -> TxRecord:
    """Execute the full 5-message dual-offline BLE payment protocol."""

    tx_id = uuid.uuid4().hex[:16]
    timing: Dict[str, float] = {}
    ble_total_us = 0.0
    total_payload = 0

    # ── PUF boot (both devices) ─────────────────────────────────
    with Timer() as t_puf_s:
        sender.puf_boot()
    with Timer() as t_puf_r:
        receiver.puf_boot()
    timing["puf_boot"] = t_puf_s.elapsed_us + t_puf_r.elapsed_us

    # ── Compliance check (sender) ───────────────────────────────
    with Timer() as t_comp:
        err = sender.compliance_check_send(amount)
    timing["compliance"] = t_comp.elapsed_us
    if err:
        return _fail(tx_id, sender, receiver, amount, err, timing)

    # Compliance check (receiver)
    recv_err = receiver.compliance_check_recv(amount)
    if recv_err:
        return _fail(tx_id, sender, receiver, amount, recv_err, timing)

    # ── Pedersen commitment ─────────────────────────────────────
    with Timer() as t_ped_c:
        blinding = os.urandom(32)
        commitment = pedersen_commit(amount, blinding)
    timing["pedersen_commit"] = t_ped_c.elapsed_us

    # ── MSG 1: Sender → Receiver (init + commitment) ───────────
    now_ts = int(time.time())
    msg1 = {
        "sender_ed_pk": sender.ed_pk.hex(),
        "sender_x_pk": sender.x_pk.hex(),
        "commitment": commitment.hex(),
        "timestamp": now_ts,
        "device_id": sender.device_id,
    }
    msg1_result, ble1_us, ble1_bytes = transport.send("msg1_init", msg1)
    ble_total_us += ble1_us
    total_payload += ble1_bytes
    if msg1_result is None:
        return _fail(tx_id, sender, receiver, amount, "msg1 dropped", timing)

    # ── Receiver: timestamp freshness check (Algorithm 4, line 3) ──
    if abs(time.time() - now_ts) >= receiver.policy.freshness_s:
        return _fail(tx_id, sender, receiver, amount, "timestamp freshness exceeded", timing)

    # ── MSG 2: Receiver → Sender (Schnorr proof + receiver keys) ──
    context = f"auth|{sender.ed_pk.hex()}|{receiver.ed_pk.hex()}|{now_ts}".encode()

    with Timer() as t_sp_r:
        receiver_proof = schnorr_prove(receiver.ed_sk, receiver.ed_pk, context)
    timing["schnorr_prove_recv"] = t_sp_r.elapsed_us

    msg2 = {
        "receiver_ed_pk": receiver.ed_pk.hex(),
        "receiver_x_pk": receiver.x_pk.hex(),
        "receiver_proof": receiver_proof.hex(),
        "timestamp": now_ts,
    }
    msg2_result, ble2_us, ble2_bytes = transport.send("msg2_auth_resp", msg2)
    ble_total_us += ble2_us
    total_payload += ble2_bytes
    if msg2_result is None:
        return _fail(tx_id, sender, receiver, amount, "msg2 dropped", timing)

    # Sender verifies receiver's proof
    with Timer() as t_sv_r:
        ok = schnorr_verify(receiver.ed_pk, context, receiver_proof)
    timing["schnorr_verify_recv"] = t_sv_r.elapsed_us
    if not ok:
        return _fail(tx_id, sender, receiver, amount, "receiver auth failed", timing)

    # ── MSG 3: Sender → Receiver (Schnorr proof) ──────────────
    with Timer() as t_sp_s:
        sender_proof = schnorr_prove(sender.ed_sk, sender.ed_pk, context)
    timing["schnorr_prove_send"] = t_sp_s.elapsed_us

    msg3 = {"sender_proof": sender_proof.hex(), "timestamp": now_ts}
    msg3_result, ble3_us, ble3_bytes = transport.send("msg3_auth_proof", msg3)
    ble_total_us += ble3_us
    total_payload += ble3_bytes
    if msg3_result is None:
        return _fail(tx_id, sender, receiver, amount, "msg3 dropped", timing)

    # Receiver verifies sender's proof
    with Timer() as t_sv_s:
        ok2 = schnorr_verify(sender.ed_pk, context, sender_proof)
    timing["schnorr_verify_send"] = t_sv_s.elapsed_us
    if not ok2:
        return _fail(tx_id, sender, receiver, amount, "sender auth failed", timing)

    # ── Token selection ─────────────────────────────────────────
    with Timer() as t_sel:
        selected = sender.select_tokens(amount)
    timing["token_select"] = t_sel.elapsed_us
    if not selected:
        return _fail(tx_id, sender, receiver, amount, "insufficient tokens", timing)

    n_tokens = len(selected)

    # ── n_max_tok enforcement (bounds Schnorr proof computation) ──
    if n_tokens > sender.policy.n_max_tok:
        return _fail(tx_id, sender, receiver, amount,
                     f"too many tokens ({n_tokens} > n_max_tok {sender.policy.n_max_tok})", timing)

    # ── SE050 capacity check on receiver (deferred until n_tokens known) ──
    se050_err = receiver.compliance_check_recv(amount, n_incoming_tokens=n_tokens)
    if se050_err and "SE050" in se050_err:
        return _fail(tx_id, sender, receiver, amount, se050_err, timing)

    # ── Transfer proof signing ──────────────────────────────────
    with Timer() as t_tsign:
        token_wire = []
        next_seq = sender.seq_no + 1
        for tok in selected:
            xfer_msg = f"{tok.tid}|{receiver.ed_pk.hex()}|{next_seq}|{now_ts}".encode()
            xfer_sig = ed25519_sign(sender.ed_sk, xfer_msg)
            token_wire.append({
                "tid": tok.tid,
                "denomination": tok.denomination,
                "cb_sig": tok.cb_signature.hex(),
                "xfer_sig": xfer_sig.hex(),
                "issuer": tok.issuer_bank,
                "owner_pk": tok.owner_pk.hex(),
                "expiry_ts": tok.expiry_ts,
            })
    timing["transfer_sign"] = t_tsign.elapsed_us

    # ── ECDH + HKDF session key ────────────────────────────────
    with Timer() as t_ecdh:
        shared = ecdh_shared_secret(sender.x_sk, receiver.x_pk)
    timing["ecdh"] = t_ecdh.elapsed_us

    with Timer() as t_hkdf:
        # Paper: K = HKDF(IKM=DH, salt=t1||R_A||R_B, info="transaction")
        hkdf_salt = f"{now_ts}".encode() + sender_proof + receiver_proof
        session_key = hkdf_derive(shared, b"transaction", length=32, salt=hkdf_salt)
    timing["hkdf"] = t_hkdf.elapsed_us

    # ── AES-256-GCM encrypt ─────────────────────────────────────
    plain_obj = {
        "tx_id": tx_id,
        "seq_no": next_seq,
        "tokens": token_wire,
        "amount": amount,
        "blinding": blinding.hex(),
    }
    payload_plain = json.dumps(plain_obj).encode()

    with Timer() as t_enc:
        nonce, ct, tag = aes_gcm_encrypt(session_key, payload_plain)
    timing["encrypt"] = t_enc.elapsed_us

    # ── MSG 4: Sender → Receiver (encrypted payload) ───────────
    msg4 = {
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
        "sender_ed_pk": sender.ed_pk.hex(),
        "sender_x_pk": sender.x_pk.hex(),
        "timestamp": now_ts,
    }
    msg4_wire = (wire_size(plain_obj) + AES_GCM_OVERHEAD
                 + wire_size({k: v for k, v in msg4.items() if k not in ("nonce", "ciphertext", "tag")}))
    msg4_result, ble4_us, ble4_bytes = transport.send("msg4_payload", msg4, wire_bytes=msg4_wire)
    ble_total_us += ble4_us
    total_payload += ble4_bytes
    if msg4_result is None:
        return _fail(tx_id, sender, receiver, amount, "msg4 dropped", timing)

    # ── Receiver: decrypt + verify ──────────────────────────────
    # ECDH on receiver side
    with Timer() as t_ecdh_r:
        shared_r = ecdh_shared_secret(receiver.x_sk, sender.x_pk)
    with Timer() as t_hkdf_r:
        hkdf_salt_r = f"{now_ts}".encode() + sender_proof + receiver_proof
        session_key_r = hkdf_derive(shared_r, b"transaction", length=32, salt=hkdf_salt_r)

    with Timer() as t_dec:
        plaintext = aes_gcm_decrypt(session_key_r, nonce, ct, tag)
    timing["decrypt"] = t_dec.elapsed_us

    data = json.loads(plaintext)

    # CB signature verify + transfer proof verify (receiver uses its own CB public key)
    with Timer() as t_cb:
        for tw in data["tokens"]:
            # Verify owner_pk matches sender (Algorithm 4, line 21)
            if tw["owner_pk"] != sender.ed_pk.hex():
                return _fail(tx_id, sender, receiver, amount, "token owner_pk mismatch", timing)
            # Verify token not expired (Algorithm 6, lines 4-5)
            if time.time() >= tw["expiry_ts"]:
                return _fail(tx_id, sender, receiver, amount, "token expired", timing)
            # CB signature covers all fields per paper Section IV.B
            cb_payload = f"{tw['tid']}|{tw['denomination']}|{tw['issuer']}|{tw['owner_pk']}|{tw['expiry_ts']}".encode()
            ed25519_verify(receiver.cb_pk, cb_payload, bytes.fromhex(tw["cb_sig"]))
    timing["cb_verify"] = t_cb.elapsed_us

    with Timer() as t_tv:
        for tw in data["tokens"]:
            xfer_msg = f"{tw['tid']}|{receiver.ed_pk.hex()}|{next_seq}|{now_ts}".encode()
            ed25519_verify(sender.ed_pk, xfer_msg, bytes.fromhex(tw["xfer_sig"]))
    timing["transfer_verify"] = t_tv.elapsed_us

    # Pedersen verify
    with Timer() as t_ped_v:
        recv_blinding = bytes.fromhex(data["blinding"])
        pedersen_verify(data["amount"], recv_blinding, commitment)
    timing["pedersen_verify"] = t_ped_v.elapsed_us

    # ── MSG 5: Receiver → Sender (HMAC-authenticated ACK per paper Algorithm 4) ──
    tid_list = "|".join(tw["tid"] for tw in data["tokens"])
    ack_data = f"{tid_list}|{receiver.seq_no + 1}|{now_ts}".encode()
    h_ack = hmac.new(session_key_r, ack_data, hashlib.sha256).hexdigest()
    msg5 = {"h_ack": h_ack, "seq_no": receiver.seq_no + 1, "t_tx": now_ts}
    msg5_result, ble5_us, ble5_bytes = transport.send("msg5_ack", msg5)
    ble_total_us += ble5_us
    total_payload += ble5_bytes

    timing["ble"] = ble_total_us

    # ── State updates ───────────────────────────────────────────
    # With exact-change selection, token_value == amount
    token_value = sum(t.denomination for t in selected)

    if msg5_result is None:
        # ACK lost: sender locks tokens (can't re-spend), receiver already accepted
        for tok in selected:
            del sender.unspent[tok.tid]        # BUG-FIX: remove from unspent to prevent double-spend
            tok.state = TokenState.LOCKED
            sender.pending[tok.tid] = tok       # Move to pending (locked) for sync resolution
        # Receiver HAS the tokens (verified msg4) — ACK is just confirmation
        for tok in selected:
            receiver.pending[tok.tid] = tok     # BUG-FIX: receiver gets tokens despite lost ACK
        sender.offline_tx_count += 1
        sender.cumulative_spend += token_value  # BUG-FIX: track actual token value, not requested amount
        receiver.offline_tx_count += 1          # BUG-FIX: receiver participated in the txn
        receiver.cumulative_receive += token_value
        sender.seq_no = next_seq
        status = TxStatus.LOCKED
        fail_reason = "ACK lost (tokens locked)"
    else:
        # Success: delete from sender unspent, add to receiver pending
        for tok in selected:
            del sender.unspent[tok.tid]
            tok.state = TokenState.PENDING
            tok.owner_pk = receiver.ed_pk
            receiver.pending[tok.tid] = tok
        sender.offline_tx_count += 1
        sender.cumulative_spend += token_value  # BUG-FIX: track actual token value, not requested amount
        receiver.offline_tx_count += 1
        receiver.cumulative_receive += token_value
        sender.seq_no = next_seq
        status = TxStatus.SUCCESS
        fail_reason = ""

    # RAM estimate for this transaction
    ram = _estimate_ram(n_tokens)

    se_io = se050_io_us(n_tokens)  # v2: analytical, for ARM projection

    total_us = sum(timing.values())

    # ── Store actual cryptographic payloads for dashboard drill-down ──
    protocol_msgs = {
        "msg1_init": {
            "sender_ed_pk": sender.ed_pk.hex(),
            "sender_x_pk": sender.x_pk.hex(),
            "commitment": commitment.hex(),
            "timestamp": now_ts,
            "device_id": sender.device_id,
            "note": "amount hidden via Pedersen commitment; revealed only in encrypted Msg4",
            "ble_bytes": ble1_bytes,
        },
        "msg2_auth_resp": {
            "receiver_ed_pk": receiver.ed_pk.hex(),
            "receiver_x_pk": receiver.x_pk.hex(),
            "schnorr_proof": receiver_proof.hex(),
            "timestamp": now_ts,
            "ble_bytes": ble2_bytes,
        },
        "msg3_auth_proof": {
            "sender_proof": sender_proof.hex(),
            "timestamp": now_ts,
            "ble_bytes": ble3_bytes,
        },
        "msg4_payload": {
            "nonce": nonce.hex(),
            "ciphertext": ct.hex(),
            "tag": tag.hex(),
            "ciphertext_len": len(ct),
            "session_key": session_key.hex(),
            "shared_secret": shared.hex(),
            "tokens": token_wire,
            "blinding": blinding.hex(),
            "seq_no": next_seq,
            "ble_bytes": ble4_bytes,
        },
        "msg5_ack": {
            "h_ack": h_ack if msg5_result is not None else "(not delivered)",
            "seq_no": receiver.seq_no + 1,
            "t_tx": now_ts,
            "status": "delivered" if msg5_result is not None else "lost",
            "ble_bytes": ble5_bytes,
        },
        "pedersen": {
            "commitment": commitment.hex(),
            "blinding": blinding.hex(),
            "amount": amount,
        },
        "ble_summary": {
            "total_bytes": total_payload,
            "total_frames": len(transport.frames),
        },
    }

    rec = TxRecord(
        tx_id=tx_id,
        sender_id=sender.device_id,
        receiver_id=receiver.device_id,
        amount=amount,
        n_tokens=n_tokens,
        status=status,
        failure_reason=fail_reason,
        puf_boot_us=timing.get("puf_boot", 0),
        schnorr_prove_us=timing.get("schnorr_prove_recv", 0) + timing.get("schnorr_prove_send", 0),
        schnorr_verify_us=timing.get("schnorr_verify_recv", 0) + timing.get("schnorr_verify_send", 0),
        ecdh_us=timing.get("ecdh", 0) + t_ecdh_r.elapsed_us,
        encrypt_us=timing.get("encrypt", 0),
        decrypt_us=timing.get("decrypt", 0),
        cb_verify_us=timing.get("cb_verify", 0),
        transfer_sign_us=timing.get("transfer_sign", 0),
        transfer_verify_us=timing.get("transfer_verify", 0),
        pedersen_commit_us=timing.get("pedersen_commit", 0),
        pedersen_verify_us=timing.get("pedersen_verify", 0),
        hkdf_us=timing.get("hkdf", 0) + t_hkdf_r.elapsed_us,
        compliance_us=timing.get("compliance", 0),
        token_select_us=timing.get("token_select", 0),
        ble_us=ble_total_us,
        se_io_us=se_io,
        total_us=total_us,
        ram_bytes=ram,
        protocol_msgs=protocol_msgs,
    )
    sender.tx_log.append(rec)
    receiver.tx_log.append(rec)
    return rec


def _fail(tx_id, sender, receiver, amount, reason, timing) -> TxRecord:
    return TxRecord(
        tx_id=tx_id,
        sender_id=sender.device_id,
        receiver_id=receiver.device_id,
        amount=amount,
        n_tokens=0,
        status=TxStatus.FAILED,
        failure_reason=reason,
        total_us=sum(timing.values()),
    )


def _estimate_ram(n_tokens: int) -> int:
    """Estimate peak RAM during transaction (bytes).
    Paper Section VI-A: base = 892 B + 329 × n B per token.
    Accounts for session context, BLE buffer, stack, token structs,
    signatures, proofs, and Pedersen commitments."""
    return 892 + 329 * n_tokens


# ── v3: C-equivalent costing of the pure-Python EC code ─────────────
# The 87x ECC factor is a C-vs-C ratio (micro-ecc on Cortex-M4 vs. the host).
# Schnorr and Pedersen are written in pure Python here, which is far slower
# than the C code a device would run, so scaling their Python time by 87x
# overstates the ARM cost. They are costed instead as the same number of
# scalar multiplications in the C (OpenSSL) implementation on the same host:
#   single (one fixed-base scalar mult)      ~ Ed25519 sign
#   double (s*B + e*A double-scalar mult)    ~ Ed25519 verify
_C_EQ: Dict[str, float] = {}


def c_equiv_scalar_mult_us() -> Tuple[float, float]:
    if not _C_EQ:
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        m = b"c-equivalent calibration message"
        sg = sk.sign(m)

        def med(fn, n=400):
            for _ in range(50):
                fn()
            ts = []
            for _ in range(n):
                t0 = time.perf_counter()
                fn()
                ts.append((time.perf_counter() - t0) * 1_000_000)
            return statistics.median(ts)
        _C_EQ["single"] = med(lambda: sk.sign(m))
        _C_EQ["double"] = med(lambda: pk.verify(sg, m))
    return _C_EQ["single"], _C_EQ["double"]


def c_equiv_ecc_us(rec: "TxRecord") -> float:
    """C-equivalent host time of the pure-Python Schnorr/Pedersen work in one
    transaction: 2 Schnorr proves (single), 2 Schnorr verifies (double),
    Pedersen commit and re-commit (r*B single; the 8-bit v*H is negligible)."""
    single, double = c_equiv_scalar_mult_us()
    n_prove = 2 if rec.schnorr_prove_us > 0 else 0
    n_verify = 2 if rec.schnorr_verify_us > 0 else 0
    n_ped = (1 if rec.pedersen_commit_us > 0 else 0) + (1 if rec.pedersen_verify_us > 0 else 0)
    return n_prove * single + n_verify * double + n_ped * single


def arm_projected_ms_python(rec: "TxRecord") -> float:
    """v2 projection (kept for comparison): scales the Python Schnorr/Pedersen time by 87x."""
    ecc_us = (rec.schnorr_prove_us + rec.schnorr_verify_us + rec.ecdh_us
              + rec.cb_verify_us + rec.transfer_sign_us + rec.transfer_verify_us
              + rec.pedersen_commit_us + rec.pedersen_verify_us)
    sym_us = (rec.puf_boot_us + rec.encrypt_us + rec.decrypt_us + rec.hkdf_us
              + rec.compliance_us + rec.token_select_us)
    return (ecc_us * ARM_SCALE_FACTORS["ecc"]
            + sym_us * ARM_SCALE_FACTORS["sym"]
            + rec.ble_us * ARM_SCALE_FACTORS["ble"]
            + rec.se_io_us) / 1000.0


def arm_projected_ms(rec: "TxRecord") -> float:
    """v3: per-primitive ARM Cortex-M4 projection for one transaction.
    ECC ops x87 (Schnorr/Pedersen at C-equivalent cost), symmetric ops x10
    (HW accel), BLE x1 (binary wire size), plus analytical SE050 I/O."""
    ecc_us = (c_equiv_ecc_us(rec) + rec.ecdh_us
              + rec.cb_verify_us + rec.transfer_sign_us + rec.transfer_verify_us)
    sym_us = (rec.puf_boot_us + rec.encrypt_us + rec.decrypt_us + rec.hkdf_us
              + rec.compliance_us + rec.token_select_us)
    return (ecc_us * ARM_SCALE_FACTORS["ecc"]
            + sym_us * ARM_SCALE_FACTORS["sym"]
            + rec.ble_us * ARM_SCALE_FACTORS["ble"]
            + rec.se_io_us) / 1000.0


# ===================================================================
# Crypto micro-benchmark
# ===================================================================
def run_crypto_benchmark(iterations: int = 100) -> Dict[str, Dict[str, float]]:
    """Benchmark each cryptographic primitive. Returns {op: {mean_us, std_us, arm_us}}."""
    results = {}
    ops = {
        "SHA-256 (32 B)": lambda: sha256(b"x" * 32),
        "HKDF (RFC 5869)": lambda: hkdf_derive(b"x" * 32, b"info"),
        "Ed25519 keygen": lambda: ed25519_keygen(),
        "Ed25519 sign": None,  # set up below
        "Ed25519 verify": None,
        "X25519 keygen": lambda: x25519_keygen(),
        "ECDH shared secret": None,
        "AES-256-GCM enc (1KB)": lambda: aes_gcm_encrypt(os.urandom(32), b"x" * 1024),
        "AES-256-GCM dec (1KB)": None,
        "Schnorr prove": None,
        "Schnorr verify": None,
        "Pedersen commit": lambda: pedersen_commit(100, os.urandom(32)),
        "Pedersen verify": None,
    }

    # Setup keys for sign/verify benchmarks
    ed_sk, ed_pk = ed25519_keygen()
    msg = b"benchmark message 32 bytes long!"
    sig = ed25519_sign(ed_sk, msg)
    ops["Ed25519 sign"] = lambda: ed25519_sign(ed_sk, msg)
    ops["Ed25519 verify"] = lambda: ed25519_verify(ed_pk, msg, sig)

    x_sk, x_pk = x25519_keygen()
    x_sk2, x_pk2 = x25519_keygen()
    ops["ECDH shared secret"] = lambda: ecdh_shared_secret(x_sk, x_pk2)

    n, ct, tag = aes_gcm_encrypt(os.urandom(32), b"x" * 1024)
    aes_key = os.urandom(32)
    n2, ct2, tag2 = aes_gcm_encrypt(aes_key, b"x" * 1024)
    ops["AES-256-GCM dec (1KB)"] = lambda: aes_gcm_decrypt(aes_key, n2, ct2, tag2)

    ctx = b"schnorr benchmark context"
    proof = schnorr_prove(ed_sk, ed_pk, ctx)
    ops["Schnorr prove"] = lambda: schnorr_prove(ed_sk, ed_pk, ctx)
    ops["Schnorr verify"] = lambda: schnorr_verify(ed_pk, ctx, proof)

    bl = os.urandom(32)
    com = pedersen_commit(100, bl)
    ops["Pedersen verify"] = lambda: pedersen_verify(100, bl, com)

    for name, fn in ops.items():
        times = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            fn()
            times.append((time.perf_counter() - t0) * 1_000_000)
        results[name] = {
            "mean_us": statistics.mean(times),
            "std_us": statistics.stdev(times) if len(times) > 1 else 0,
            "arm_us_uniform87": statistics.mean(times) * ARM_SCALE_FACTOR,
        }
    # v3: ARM estimate with the per-primitive factors; pure-Python Schnorr and
    # Pedersen at the cost of their scalar multiplications in C.
    single, double = c_equiv_scalar_mult_us()
    c_eq = {"Schnorr prove": single, "Schnorr verify": double,
            "Pedersen commit": single, "Pedersen verify": single}
    sym_ops = ("SHA-256 (32 B)", "HKDF (RFC 5869)", "AES-256-GCM enc (1KB)", "AES-256-GCM dec (1KB)")
    for name, r in results.items():
        if name in c_eq:
            r["c_equiv_us"] = c_eq[name]
            r["arm_us"] = c_eq[name] * ARM_SCALE_FACTORS["ecc"]
        elif name in sym_ops:
            r["arm_us"] = r["mean_us"] * ARM_SCALE_FACTORS["sym"]
        else:
            r["arm_us"] = r["mean_us"] * ARM_SCALE_FACTORS["ecc"]
    return results


# ===================================================================
# Full IoT simulation experiment
# ===================================================================
@dataclass
class MainWallet:
    """Represents a user's Main Wallet (smartphone app) that manages IoT Sub-Wallets."""
    wallet_id: str
    bank_id: str
    device_ids: List[str]      # IoT Sub-Wallets registered under this wallet
    own_balance: int = 0       # Wallet's own retained balance (₹)
    total_loaded: int = 0      # Total ₹ loaded onto all IoT sub-wallets (initial loading)
    tokens_loaded: int = 0     # Total tokens distributed to sub-wallets
    swept_back: int = 0        # ₹ swept back from sub-wallets during sync
    # --- MW-Known vs Actual (Simulator Ground Truth) ---
    mw_known_iot_bal: int = 0  # What MW *thinks* IoT devices hold (loaded - spent_reported - swept)
    actual_iot_bal: int = 0    # Actual value on IoT devices (simulator truth)
    offline_received: int = 0  # ₹ received offline by IoT devs (unknown to MW until sync)
    unsynced_spent: int = 0    # ₹ spent offline by IoT devs (unknown to MW until sync)


@dataclass
class SimulationConfig:
    n_devices: int = 10
    n_banks: int = 2
    devices_per_bank: int = 5
    tokens_per_device: int = 150
    n_transactions: int = 100
    min_amount: int = 10
    max_amount: int = 200
    ack_drop_prob: float = 0.05
    ber: float = 0.03
    seed: int = 42
    # v2 options:
    enforce_bmax_at_load: bool = True     # False reproduces the legacy (paper v1) run
    loading_strategy: str = "balanced"    # "balanced" = B_max-conformant float; "random" = legacy
    sync_on_limit_failure: bool = True    # S_MAX/R_MAX failure => device syncs (SYNC_REQUIRED)
    sync_on_insufficient: bool = True     # exact-change failure => refill at next MW contact
    refill_below: int = 0                 # proactive refill when balance < this (0 = off)
    rebalance_at_sync: bool = True        # bank re-denominates the float at sync (splits
                                          # large tokens into a composable mix; paper VII-B)


@dataclass
class SimulationResult:
    config: SimulationConfig
    transactions: List[TxRecord]
    devices: Dict[str, IoTDevice]
    wallets: Dict[str, MainWallet]
    syncs: List[SyncRecord]
    crypto_bench: Dict[str, Dict[str, float]]
    puf_reliability: Dict[float, Dict[str, Any]]
    latency_scaling: List[Dict[str, Any]]
    resource_stress: List[Dict[str, Any]]

    @property
    def successful(self) -> List[TxRecord]:
        return [t for t in self.transactions if t.status == TxStatus.SUCCESS]

    @property
    def failed(self) -> List[TxRecord]:
        return [t for t in self.transactions if t.status == TxStatus.FAILED]

    @property
    def locked(self) -> List[TxRecord]:
        return [t for t in self.transactions if t.status == TxStatus.LOCKED]

    def success_rate(self) -> float:
        return len(self.successful) / len(self.transactions) * 100 if self.transactions else 0

    def failure_breakdown(self) -> Dict[str, int]:
        from collections import Counter
        return dict(Counter(t.failure_reason for t in self.transactions if t.status != TxStatus.SUCCESS))


# v2: a realistic "float" the bank would load onto a device: composable
# mix of denominations summing to B_max (500 = 1x100 + 2x50 + 5x20 +
# 10x10 + 10x5 + 15x2 + 20x1, 63 tokens).
BALANCED_FLOAT_TEMPLATE = ([100] * 1 + [50] * 2 + [20] * 5 + [10] * 10
                           + [5] * 10 + [2] * 15 + [1] * 20)


def topup_denominations(current_balance: int, target: int) -> List[int]:
    """Denominations to top a device up from current_balance to target,
    drawn from the balanced float template (largest first)."""
    room = target - current_balance
    out = []
    for d in BALANCED_FLOAT_TEMPLATE:
        if d <= room:
            out.append(d)
            room -= d
    return out


def run_simulation(config: SimulationConfig, light: bool = False) -> SimulationResult:
    """Run complete IoT-CBDC simulation experiment.

    light=True skips the crypto benchmark, PUF-reliability sweep, latency
    scaling, and resource stress tests (used by run_multi_seed, where these
    seed-independent extras would be redundantly recomputed)."""

    rng = random.Random(config.seed)

    # Central Bank keypair
    cb_sk, cb_pk = ed25519_keygen()
    puf_engine = PUFEngine(bit_length=2048, correction_bits=50)

    # Create devices across banks, grouped under Main Wallets
    # Paper Table VI: 2 banks (SBI, HDFC), 5 devices each
    bank_names = ["SBI", "HDFC"] if config.n_banks == 2 else [f"BANK_{chr(65 + i)}" for i in range(config.n_banks)]
    devices: Dict[str, IoTDevice] = {}
    device_list: List[IoTDevice] = []
    wallets: Dict[str, MainWallet] = {}

    # Distribute devices evenly: devices_per_bank per bank, ~2-3 sub-wallets per MW
    wallet_idx = 0
    dev_i = 0
    for bank_idx, bank in enumerate(bank_names):
        n_devs_bank = config.devices_per_bank
        bank_dev_count = 0
        while bank_dev_count < n_devs_bank and dev_i < config.n_devices:
            w_id = f"MW-{wallet_idx:02d}"
            # Each wallet gets 2-3 devices (last wallet in bank gets remainder)
            remaining_in_bank = n_devs_bank - bank_dev_count
            n_devs_this_wallet = min(2 + (wallet_idx % 2), remaining_in_bank)
            wallet_dev_ids = []
            for j in range(n_devs_this_wallet):
                dev_id = f"DEV-{dev_i:03d}"
                dev = IoTDevice(
                    device_id=dev_id,
                    bank_id=bank,
                    puf_engine=puf_engine,
                    cb_pk=cb_pk,
                    cb_sk=cb_sk,
                    rng_seed=config.seed + dev_i,
                    ber=config.ber,
                    wallet_id=w_id,
                )
                dev.puf_boot()
                if config.loading_strategy == "balanced":
                    denoms = topup_denominations(0, dev.policy.b_max)
                else:
                    denoms = [rng.choice(DENOMINATIONS) for _ in range(config.tokens_per_device)]
                dev.load_tokens(denoms, enforce_bmax=config.enforce_bmax_at_load)
                devices[dev_id] = dev
                device_list.append(dev)
                wallet_dev_ids.append(dev_id)
                dev_i += 1
                bank_dev_count += 1
            wallets[w_id] = MainWallet(wallet_id=w_id, bank_id=bank, device_ids=wallet_dev_ids)
            wallet_idx += 1

    # ── Run transactions ────────────────────────────────────────
    transactions: List[TxRecord] = []
    syncs: List[SyncRecord] = []

    for tx_idx in range(config.n_transactions):
        amount = rng.randint(config.min_amount, config.max_amount)
        # Pick sender and receiver (different devices)
        s_idx = rng.randint(0, config.n_devices - 1)
        r_idx = rng.randint(0, config.n_devices - 2)
        if r_idx >= s_idx:
            r_idx += 1

        sender = device_list[s_idx]
        receiver = device_list[r_idx]

        transport = BLETransport(
            drop_ack_prob=config.ack_drop_prob,
            rng_seed=config.seed + tx_idx,
        )

        rec = run_transaction(sender, receiver, amount, transport)
        transactions.append(rec)

        def _sync_and_reload(dev):
            sr = dev.sync_with_bank()
            syncs.append(sr)
            if config.rebalance_at_sync and config.loading_strategy == "balanced":
                # Bank-side float re-denomination (Section VII-B): confirmed
                # and residual tokens are re-issued as a composable mix and
                # the float is topped back up to B_max. Without this, sweeps
                # (smallest-first) strand devices with only large tokens and
                # exact change becomes impossible.
                dev.unspent.clear()
                denoms = topup_denominations(0, dev.policy.b_max)
            elif config.loading_strategy == "balanced":
                denoms = topup_denominations(dev.balance(), dev.policy.b_max)
            else:
                denoms = [rng.choice(DENOMINATIONS) for _ in range(20)]
            dev.load_tokens(denoms, enforce_bmax=config.enforce_bmax_at_load)

        # Auto-sync devices that hit N_MAX
        for dev in [sender, receiver]:
            if dev.offline_tx_count >= dev.policy.n_max_tx:
                _sync_and_reload(dev)

        # v2: S_MAX/R_MAX failures put a device into SYNC_REQUIRED (paper
        # Section IV-G); it synchronizes at the next opportunity.
        if config.sync_on_limit_failure and rec.status == TxStatus.FAILED:
            if "S_MAX" in rec.failure_reason and sender.offline_tx_count > 0:
                _sync_and_reload(sender)
            elif "R_MAX" in rec.failure_reason and receiver.offline_tx_count > 0:
                _sync_and_reload(receiver)

        # v2: a device that cannot compose exact change requests a refill at
        # its next Main-Wallet contact (bank tops the float back up to B_max)
        if (config.sync_on_insufficient and rec.status == TxStatus.FAILED
                and "insufficient" in rec.failure_reason):
            _sync_and_reload(sender)

        # v2: proactive auto top-up, mirroring real wallet behaviour (the
        # Main Wallet refills the float when it drops below a threshold)
        if config.refill_below > 0:
            for dev in [sender, receiver]:
                if dev.balance() < config.refill_below:
                    _sync_and_reload(dev)

    # ── Seed-independent extras (skipped in light mode) ─────────────
    if light:
        crypto_bench, puf_reliability, latency_scaling, resource_stress = {}, {}, [], []
    else:
        crypto_bench = run_crypto_benchmark(iterations=50)
        puf_reliability = _run_puf_reliability_test(config.seed)
        latency_scaling = _run_latency_scaling_test(cb_sk, cb_pk, puf_engine, config.seed)
        resource_stress = _run_resource_stress_test()

    # ── Populate wallet-level aggregates ────────────────────────
    # Key insight: MW only learns device state at two points:
    #   (a) Initial loading — MW mediated it, knows exactly what was loaded
    #   (b) Each sync — MW relays logs to bank, learns post-sync balance
    # Between syncs, IoT devices do P2P offline — MW has ZERO visibility.
    for w_id, mw in wallets.items():
        total_loaded_initial = 0  # ₹ loaded at registration (MW knows)
        total_tokens = 0
        total_swept = 0
        actual_on_device = 0      # What devices ACTUALLY hold right now
        mw_last_known_total = 0   # Sum of last-known balance per device
        offline_recv = 0          # ₹ received via P2P (MW doesn't know)
        unsynced_spend = 0        # ₹ spent via P2P (MW doesn't know)
        for d_id in mw.device_ids:
            dev = devices[d_id]
            dev_bal = dev.balance()  # unspent table
            dev_pending = sum(t.denomination for t in dev.pending.values())
            dev_actual = dev_bal + dev_pending  # what's physically on device now

            # What MW knows about THIS device:
            # If device synced → last sync's balance_after_sweep
            # If never synced → initial_loaded (what MW loaded at registration)
            if dev.sync_log:
                last_sync = dev.sync_log[-1]
                mw_last_known = getattr(last_sync, 'balance_after_sweep', dev.initial_loaded)
            else:
                mw_last_known = getattr(dev, 'initial_loaded', dev_actual)

            total_loaded_initial += getattr(dev, 'initial_loaded', 0)
            total_tokens += dev.token_count()
            actual_on_device += dev_actual
            mw_last_known_total += mw_last_known
            offline_recv += dev.cumulative_receive
            unsynced_spend += dev.cumulative_spend
            for sr in dev.sync_log:
                if hasattr(sr, 'amount_swept'):
                    total_swept += sr.amount_swept
        mw.total_loaded = total_loaded_initial
        mw.tokens_loaded = total_tokens
        mw.swept_back = total_swept
        mw.actual_iot_bal = actual_on_device
        mw.offline_received = offline_recv
        mw.unsynced_spent = unsynced_spend
        # MW's view = sum of last-known balances (from sync or initial load)
        mw.mw_known_iot_bal = mw_last_known_total
        # Own balance = 10000 - initially loaded + swept back
        mw.own_balance = max(0, 10000 - total_loaded_initial + total_swept)

    return SimulationResult(
        config=config,
        transactions=transactions,
        devices=devices,
        wallets=wallets,
        syncs=syncs,
        crypto_bench=crypto_bench,
        puf_reliability=puf_reliability,
        latency_scaling=latency_scaling,
        resource_stress=resource_stress,
    )


def _run_puf_reliability_test(seed: int) -> Dict[float, Dict[str, Any]]:
    """Test PUF boot reliability across different BER values."""
    results = {}
    for ber in [0.01, 0.03, 0.05, 0.08, 0.10]:
        puf = PUFEngine(bit_length=2048, correction_bits=50)
        rng = random.Random(seed)
        successes = 0
        distances = []
        boot_times = []
        for i in range(10):
            dev_id = f"PUF_TEST_{i}"
            puf.enroll(dev_id, rng)
            try:
                noisy = puf.noisy_read(dev_id, rng, ber)
                key, dist = puf.recover(dev_id, noisy)
                successes += 1
                distances.append(dist)
                # Time PUF boot
                t0 = time.perf_counter()
                puf.noisy_read(dev_id, rng, ber)
                puf.recover(dev_id, puf.noisy_read(dev_id, rng, ber))
                boot_times.append((time.perf_counter() - t0) * 1e6)
            except ValueError:
                pass
        results[ber] = {
            "success_rate": successes / 10 * 100,
            "avg_errors": statistics.mean(distances) if distances else 0,
            "max_errors": max(distances) if distances else 0,
            "stable_bits": 2048 - (int(statistics.mean(distances)) if distances else 0),
            "avg_boot_us": statistics.mean(boot_times) if boot_times else 0,
        }
    return results


def _run_latency_scaling_test(cb_sk, cb_pk, puf_engine: PUFEngine, seed: int) -> List[Dict[str, Any]]:
    """Measure latency vs token count (1, 5, 10, 20, 50 tokens)."""
    # Use a dedicated PUF engine with BER=0 for latency scaling (isolates latency from PUF noise)
    scale_puf = PUFEngine(bit_length=2048, correction_bits=170)
    results = []
    for n_tok in [1, 5, 10, 20, 50]:
        rng = random.Random(seed)
        dev_s = IoTDevice("SCALE_S", "BANK_A", scale_puf, cb_pk, cb_sk, rng_seed=seed + 100, ber=0.0)
        dev_r = IoTDevice("SCALE_R", "BANK_A", scale_puf, cb_pk, cb_sk, rng_seed=seed + 200, ber=0.0)
        dev_s.puf_boot()
        dev_r.puf_boot()
        # Load exactly ₹1 tokens so n_tok tokens = ₹n_tok amount
        dev_s.load_tokens([1] * (n_tok + 10))
        dev_r.load_tokens([1] * 10)

        transport = BLETransport(drop_ack_prob=0.0, rng_seed=seed + n_tok)
        rec = run_transaction(dev_s, dev_r, n_tok, transport)

        results.append({
            "tokens": n_tok,
            "measured_ms": rec.total_us / 1000,
            "arm_ms": rec.total_us / 1000 * ARM_SCALE_FACTOR,          # legacy uniform x87
            "arm_ms_v2": arm_projected_ms(rec),                        # v2 per-primitive
            "ble_ms": rec.ble_us / 1000,
            "se_io_ms": rec.se_io_us / 1000,
            "payload_bytes": transport.total_payload_bytes(),
            "ble_frames": transport.total_frames(),
            "ram_bytes": rec.ram_bytes,
        })
    return results


def _run_resource_stress_test() -> List[Dict[str, Any]]:
    """Validate SE050/flash/RAM/battery budgets."""
    TOKEN_SIZE = 137
    SE050_BYTES = 50 * 1024
    MCU_FLASH = 4 * 1024 * 1024
    RAM_TOTAL = 520 * 1024
    BATTERY_J = 6600  # 500 mAh LiPo
    ESP32_WATTS = 0.5

    results = []
    # Flash/SE050 capacity
    for n in [100, 300, 1000, 10000]:
        storage = n * TOKEN_SIZE
        if n <= 300:
            budget_label = "SE050 (50 KB)"
            budget = SE050_BYTES
        else:
            budget_label = "MCU Flash (4 MB)"
            budget = MCU_FLASH
        results.append({
            "category": "Storage",
            "scenario": f"{n} tokens",
            "measured": f"{storage / 1024:.1f} KB",
            "budget": budget_label,
            "within_budget": storage <= budget,
        })

    # RAM for transactions
    for n_tok in [1, 10, 50]:
        ram = _estimate_ram(n_tok)
        results.append({
            "category": "RAM",
            "scenario": f"{n_tok}-token tx",
            "measured": f"{ram:,} B",
            "budget": f"{RAM_TOTAL // 1024} KB",
            "within_budget": ram <= RAM_TOTAL,
        })

    # Battery life estimates
    for n_tok, label in [(1, "1-token"), (5, "5-token"), (50, "50-token")]:
        # Use approximate ARM timing
        arm_ms = {1: 400, 5: 800, 50: 5300}[n_tok]
        energy_j = ESP32_WATTS * arm_ms / 1000
        txns_per_charge = BATTERY_J / energy_j if energy_j > 0 else float("inf")
        results.append({
            "category": "Battery",
            "scenario": f"{label} tx",
            "measured": f"{energy_j * 1000:.1f} mJ",
            "budget": f"{BATTERY_J:,} J",
            "within_budget": True,
            "txns_per_charge": int(txns_per_charge),
        })

    return results


# ===================================================================
# v2: Multi-seed experiment runner (statistical rigour)
# ===================================================================
def run_multi_seed(config: SimulationConfig, seeds: List[int]) -> Dict[str, Any]:
    """Run the full simulation once per seed and aggregate statistics.

    Returns per-seed summaries plus mean/std for success rate, failure
    breakdown, latency, and ARM projections."""
    from dataclasses import replace
    from collections import Counter

    per_seed = []
    fail_counter = Counter()
    for s in seeds:
        cfg = replace(config, seed=s)
        res = run_simulation(cfg, light=True)
        succ = res.successful
        lat = [t.total_us / 1000 for t in succ]
        arm = [arm_projected_ms(t) for t in succ]
        n_tok = [t.n_tokens for t in succ]
        fb = res.failure_breakdown()
        fail_counter.update(fb)
        per_seed.append({
            "seed": s,
            "n_tx": len(res.transactions),
            "success": len(succ),
            "locked": len(res.locked),
            "failed": len(res.failed),
            "failure_breakdown": fb,
            "syncs": len(res.syncs),
            "mean_latency_ms": statistics.mean(lat) if lat else 0,
            "mean_arm_ms_v2": statistics.mean(arm) if arm else 0,
            "mean_tokens": statistics.mean(n_tok) if n_tok else 0,
        })

    def agg(key):
        vals = [d[key] for d in per_seed]
        return {
            "mean": statistics.mean(vals),
            "std": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "min": min(vals),
            "max": max(vals),
        }

    return {
        "seeds": list(seeds),
        "per_seed": per_seed,
        "success": agg("success"),
        "locked": agg("locked"),
        "failed": agg("failed"),
        "syncs": agg("syncs"),
        "mean_latency_ms": agg("mean_latency_ms"),
        "mean_arm_ms_v2": agg("mean_arm_ms_v2"),
        "mean_tokens": agg("mean_tokens"),
        "failure_totals": dict(fail_counter),
    }
