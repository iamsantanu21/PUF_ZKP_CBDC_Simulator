# v4 changes (MCU projection from published timings)

v3 projected MCU latency by scaling host times: 87x for elliptic-curve work
(a micro-ecc ratio, measured on a different curve) and 10x for symmetric work.
Published measurements on the two target MCUs show that this was too optimistic,
so v4 replaces the scaling with published per-operation timings.

## 1. Elliptic-curve operations: counted, then costed per MCU
`run_transaction()` executes, for n tokens (both devices together):

| Operation | Count |
|---|---|
| Ed25519 key derivation at PUF boot + Pedersen commit/re-commit (fixed-base) | 4 |
| Schnorr proofs + Ed25519 transfer signatures | 2 + n |
| Schnorr verifications + Ed25519 verifications (CB signature, transfer proof) | 2 + 2n |
| X25519 key derivation at PUF boot | 2 |
| X25519 shared secret (ECDH) | 2 |

Per-operation cost:

| Operation | nRF52840 (Cortex-M4F, 64 MHz) | ESP32 (Xtensa LX6, 240 MHz) |
|---|---|---|
| Source | Fujii & Aranha, LATINCRYPT 2017 (cycle counts / 64 MHz) | Oryx Embedded ESP32 benchmark (CycloneCRYPTO 2.5.0) |
| Fixed-base (key derivation, Pedersen) | 5.43 ms (347,225 cycles) | 29 ms (costed as a signature) |
| Ed25519 sign / Schnorr prove | 7.75 ms (496,039 cycles) | 29 ms |
| Ed25519 / Schnorr verify | 19.77 ms (1,265,078 cycles) | 28 ms |
| X25519 | 14.18 ms (907,240 cycles) | 17 ms key derivation, 16 ms shared secret |

The nRF52840's CryptoCell-310 could accelerate Curve25519, so the nRF52840 figures are
a software (conservative) estimate.

## 2. Symmetric work by bytes processed
AES-256-GCM over the whole payload (once to encrypt, once to decrypt) and SHA-256 over
the HKDF/HMAC/challenge input (`hashed_bytes()`):
- ESP32: hardware AES-256-GCM 1.773 MB/s, hardware SHA-256 27.777 MB/s (Oryx).
- nRF52840: CryptoCell-310 has no AES-256, so both are costed in software at the ESP32
  software rate scaled by clock (1.038 MB/s and 2.173 MB/s x 64/240), which is conservative.

The rest of the host-Python logic (PUF read-out and error correction, compliance checks,
token selection) is scaled by 10x (ESP32) or 37.5x (nRF52840). It adds under 7 ms.

## 3. Costs that v3 left out
- **Flash logging** (WAL + TxLog, `flash_records()`): 7 writes per transaction.
  ESP32 external NOR flash (W25Q32JV, 0.7 ms per 256-B page, typical); nRF52840 internal
  flash (41 us per 32-bit word). Sectors are erased when the TxLog is cleared at sync.
- **BLE connection setup** (`BLE_CONNECT_MS` = 45 ms): one advertising event at the
  20 ms minimum interval + up to 10 ms advDelay + two 7.5 ms connection events
  (ATT MTU exchange, data length update).

New functions: `ecc_op_counts()`, `MCU_PROFILES`, `flash_records()`, `flash_write_ms()`,
`hashed_bytes()`, `mcu_breakdown_ms()`, `mcu_projected_ms()`, `mcu_primitive_table()`.
`TxRecord` has a new `payload_bytes` field. `run_multi_seed()` also reports
`mean_mcu_ms_nrf52840` and `mean_mcu_ms_esp32`. The v3 `arm_projected_ms()` is kept.

Outcome counts do not change.

## Reproduce
    python3 run_results.py results_v4

## Results (5-token payment, `results_v4_mac/`)

| | nRF52840 | ESP32 |
|---|---|---|
| Elliptic-curve operations | 369.9 ms | 721.0 ms |
| Symmetric (AES-GCM, SHA-256) | 17.9 ms | 1.7 ms |
| Other logic | 6.6 ms | 1.8 ms |
| BLE air time | 6.9 ms | 6.9 ms |
| SE050 I/O | 17.5 ms | 17.5 ms |
| Flash logging | 14.9 ms | 7.7 ms |
| BLE connection setup | 45.0 ms | 45.0 ms |
| **Total** | **479 ms** | **802 ms** |
| Linear fit | 201 + 55.5 n ms | 351 + 90.0 n ms |
| Largest payment under 1 s | 14 tokens | 7 tokens |
| Campaign mean (5.14 tokens) | 490 +/- 26 ms | 815 +/- 43 ms |
| Energy per 5-token payment | 0.024 J (0.05 W) | 0.40 J (0.5 W) |
| Payments per 500 mAh (6.66 kJ) | ~278,000 | ~16,600 |

v3 gave 222 ms for the same payment ("ARM Cortex-M4").
A payment up to Rs 200 needs at most seven tokens when the denominations are available,
so it stays under 1 s on both MCUs.

Note: `paper_figures_v3/` and the dashboard's ARM column still use the v3/legacy
projection; the paper's numbers come from `run_results.py` (v4).
