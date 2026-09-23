# v3 changes (simulator accuracy fixes)

Two corrections to `iot_sim_engine.py` for the paper revision.

## 1. ARM projection of Schnorr and Pedersen
Schnorr proofs and Pedersen commitments are written in pure Python (edwards25519 math),
which is 30-60x slower than the C code a device would run. The 87x ECC factor is a
C-vs-C ratio (micro-ecc on Cortex-M4 vs. the host), so scaling the *Python* time by 87x
overstated the ARM latency (about 1.2-1.9 s per 5-token payment).

v3 costs these operations as the same number of scalar multiplications in the C
(OpenSSL) implementation, measured on the same host:
- Schnorr prove, Pedersen commit/re-commit: one fixed-base scalar mult (~ Ed25519 sign)
- Schnorr verify (s*B + e*A): one double-scalar mult (~ Ed25519 verify)

New functions: `c_equiv_scalar_mult_us()`, `c_equiv_ecc_us()`, `arm_projected_ms()` (v3);
the old projection is kept as `arm_projected_ms_python()`.

## 2. BLE message size
Messages were costed as JSON with hex strings (6,066 B for a 5-token payment). Device
firmware sends raw bytes, so BLE air time now uses a compact binary size (`wire_size()`):
raw keys/proofs, 1-byte denomination, 4-byte integers, no JSON keys, AES-GCM nonce+tag.

Outcome counts do not change (ACK drops use their own random generator).

## Reproduce
    python3 run_results.py results_v3
    python3 paper_experiments.py paper_figures_v3

## Results (Apple Silicon, Linux VM, Python 3.10; 5-token payment)
| Metric | Original code | v3 |
|---|---|---|
| Success / ACK loss / ceiling (per 100) | 93.5 / 4.2 / 2.3 | 93.5 / 4.2 / 2.3 |
| Host time | 49.4 ms | 9.4 ms (C-equivalent) |
| BLE payload | 6,066 B, 27 frames | 1,386 B, 9 frames |
| BLE air time | 28.3 ms | 6.9 ms |
| ARM projection | 1.85 s | 0.22 s |
| 1-second threshold crossed at | always above | ~30 tokens |

Full numbers: `results_original_mac/summary.txt`, `results_v3_mac/summary.txt`.
