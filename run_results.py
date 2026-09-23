"""Collect every number the paper reports from the simulator.
Usage: python3 run_results.py <out_dir>
Works with the original engine, the v3 engine (C-equivalent EC costing, binary
wire sizes) and the v4 engine (MCU projection from published per-operation
timings, plus flash logging and BLE connection setup)."""
import sys, os, json, statistics, platform, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import iot_sim_engine as E
from iot_sim_engine import (SimulationConfig, run_simulation, run_multi_seed, arm_projected_ms,
                            PUFEngine, IoTDevice, BLETransport, run_transaction,
                            ed25519_keygen, ARM_SCALE_FACTORS)

OUT = sys.argv[1] if len(sys.argv) > 1 else "results"
os.makedirs(OUT, exist_ok=True)
V3 = hasattr(E, "c_equiv_scalar_mult_us")
V4 = hasattr(E, "mcu_projected_ms")
PROFILES = list(E.MCU_PROFILES) if V4 else []
R = {"engine": "v4" if V4 else ("v3" if V3 else "original"), "host": platform.platform(), "machine": platform.machine(),
     "python": platform.python_version()}

# 1) crypto primitives (Table IV)
bench = E.run_crypto_benchmark(300)
R["crypto_bench"] = bench

# 2) 10-seed campaign (Section VI-B)
t0 = time.time()
ms = run_multi_seed(SimulationConfig(), list(range(42, 52)))
R["multi_seed"] = {k: v for k, v in ms.items() if k != "per_seed"}
R["multi_seed_per_seed"] = ms["per_seed"]
R["campaign_seconds"] = time.time() - t0

# 3) latency vs token count, repeated for stable medians (Section VI-C/D)
cb_sk, cb_pk = ed25519_keygen()
puf = PUFEngine(bit_length=2048, correction_bits=170)
PH = ["puf_boot_us", "schnorr_prove_us", "schnorr_verify_us", "ecdh_us", "encrypt_us", "decrypt_us",
      "cb_verify_us", "transfer_sign_us", "transfer_verify_us", "pedersen_commit_us", "pedersen_verify_us",
      "hkdf_us", "compliance_us", "token_select_us", "ble_us", "se_io_us"]
REPS = 15
def meas_c(x):
    """Host time with the pure-Python Schnorr/Pedersen replaced by their C-equivalent cost (v3)."""
    if not V3:
        return x.total_us
    return (x.total_us - x.schnorr_prove_us - x.schnorr_verify_us - x.pedersen_commit_us
            - x.pedersen_verify_us + E.c_equiv_ecc_us(x))
scaling = []
five_phase = None
for n in list(range(1, 16)) + [20, 30, 40, 50]:
    rows = []
    for rep in range(REPS):
        s = IoTDevice("SCALE_S", "BANK_A", puf, cb_pk, cb_sk, rng_seed=142 + rep, ber=0.0)
        r = IoTDevice("SCALE_R", "BANK_A", puf, cb_pk, cb_sk, rng_seed=242 + rep, ber=0.0)
        s.puf_boot(); r.puf_boot()
        s.load_tokens([1] * (n + 10)); r.load_tokens([1] * 10)
        tr = BLETransport(drop_ack_prob=0.0, rng_seed=42 + n)
        rec = run_transaction(s, r, n, tr)
        assert rec.n_tokens == n, (n, rec.failure_reason)
        rows.append((rec, tr))
    med = lambda xs: statistics.median(xs)
    d = {
        "tokens": n,
        "measured_ms": med([x.total_us / 1000 for x, _ in rows]),
        "ble_ms": med([x.ble_us / 1000 for x, _ in rows]),
        "compute_ms": med([(x.total_us - x.ble_us) / 1000 for x, _ in rows]),
        "arm_ms": med([arm_projected_ms(x) for x, _ in rows]),
        "measured_c_ms": med([meas_c(x) / 1000 for x, _ in rows]),
        "compute_c_ms": med([(meas_c(x) - x.ble_us) / 1000 for x, _ in rows]),
        "se_io_ms": rows[0][0].se_io_us / 1000,
        "payload_bytes": rows[0][1].total_payload_bytes(),
        "ble_frames": rows[0][1].total_frames(),
        "ram_bytes": rows[0][0].ram_bytes,
    }
    for prof in PROFILES:
        d[f"mcu_{prof}_ms"] = med([E.mcu_projected_ms(x, prof) for x, _ in rows])
    scaling.append(d)
    if n == 5:
        five_phase = {p: med([getattr(x, p) for x, _ in rows]) for p in PH}
        if V4:
            R["five_token_mcu_breakdown_ms"] = {
                prof: {k: med([E.mcu_breakdown_ms(x, prof)[k] for x, _ in rows])
                       for k in E.mcu_breakdown_ms(rows[0][0], prof)} for prof in PROFILES}
R["scaling"] = scaling
R["five_token_phase_us"] = five_phase

# linear fit of measured latency (1..15 tokens + 20..50)
xs = [d["tokens"] for d in scaling]; ys = [d["measured_c_ms"] for d in scaling]
mx, my = statistics.mean(xs), statistics.mean(ys)
b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
a = my - b * mx
ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys)); ss_tot = sum((y - my) ** 2 for y in ys)
R["fit_measured_ms"] = {"a": a, "b": b, "r2": 1 - ss_res / ss_tot}
ya = [d["arm_ms"] for d in scaling]
ma = statistics.mean(ya)
ba = sum((x - mx) * (y - ma) for x, y in zip(xs, ya)) / sum((x - mx) ** 2 for x in xs)
aa = ma - ba * mx
R["fit_arm_ms"] = {"a": aa, "b": ba}
cross = next((d["tokens"] for d in scaling if d["arm_ms"] > 1000), None)
R["arm_1s_threshold_first_n_above"] = cross
R["arm_1s_threshold_fit_n"] = (1000 - aa) / ba if ba > 0 else None

# energy (engine model: 0.5 W x ARM time, 500 mAh = 6600 J)
five = next(d for d in scaling if d["tokens"] == 5)
e_j = 0.5 * five["arm_ms"] / 1000
R["energy_5tok_J"] = e_j
R["tx_per_charge"] = 6600 / e_j

# v4: per-MCU fits, 1-second crossing, energy, primitive table
if V4:
    R["mcu"] = {}
    for prof in PROFILES:
        ys_p = [d[f"mcu_{prof}_ms"] for d in scaling]
        mp = statistics.mean(ys_p)
        bp = sum((x - mx) * (y - mp) for x, y in zip(xs, ys_p)) / sum((x - mx) ** 2 for x in xs)
        ap = mp - bp * mx
        five_p = next(d for d in scaling if d["tokens"] == 5)[f"mcu_{prof}_ms"]
        e5 = E.MCU_PROFILES[prof]["active_w"] * five_p / 1000
        R["mcu"][prof] = {
            "label": E.MCU_PROFILES[prof]["label"],
            "fit_ms": {"a": ap, "b": bp},
            "first_n_above_1s": next((d["tokens"] for d in scaling if d[f"mcu_{prof}_ms"] > 1000), None),
            "fit_crossing_n": (1000 - ap) / bp if bp > 0 else None,
            "five_token_ms": five_p,
            "energy_5tok_J": e5,
            "tx_per_charge": E.BATTERY_J_V4 / e5,
            "campaign_mean_ms": ms[f"mean_mcu_ms_{prof}"],
        }
    R["mcu_primitives_ms"] = E.mcu_primitive_table()
    R["ble_connect_ms"] = E.BLE_CONNECT_MS
    R["flash_ms_5tok"] = {prof: E.flash_write_ms(5, prof) for prof in PROFILES}
    R["host_keygen_us"] = E.host_keygen_us()

# 4) PUF reliability (deterministic)
rep = run_simulation(SimulationConfig())
R["puf_reliability"] = {str(k): v for k, v in rep.puf_reliability.items()}

if V3:
    R["c_equiv_us"] = dict(zip(["single_scalar_mult", "double_scalar_mult"], E.c_equiv_scalar_mult_us()))

json.dump(R, open(f"{OUT}/results.json", "w"), indent=1, default=str)

# readable summary
L = []
p = L.append
p(f"Engine: {R['engine']}   Host: {R['host']} ({R['machine']}), Python {R['python']}")
m = R["multi_seed"]
p(f"Outcomes (10 seeds x 100): success {m['success']['mean']:.1f} +/- {m['success']['std']:.1f}, "
  f"ACK-lost {m['locked']['mean']:.1f} +/- {m['locked']['std']:.1f}, ceiling {m['failed']['mean']:.1f} +/- {m['failed']['std']:.1f}, "
  f"syncs {m['syncs']['mean']:.0f} +/- {m['syncs']['std']:.0f}")
p(f"Campaign mean over successful tx (mean {m['mean_tokens']['mean']:.2f} tokens): measured {m['mean_latency_ms']['mean']:.1f} ms, ARM {m['mean_arm_ms_v2']['mean']:.0f} ms")
p("Crypto primitives (mean us; ARM est. us):")
for k, v in bench.items():
    p(f"   {k:24s} {v['mean_us']:9.1f}   ARM {v['arm_us']:10.0f}")
p("Scaling (median of %d): tokens | measured ms | measured C-eq ms | compute C-eq ms | BLE ms | ARM ms | bytes | frames | RAM" % REPS)
for d in scaling:
    p(f"   {d['tokens']:3d} | {d['measured_ms']:7.1f} | {d['measured_c_ms']:7.1f} | {d['compute_c_ms']:6.2f} | {d['ble_ms']:6.2f} | {d['arm_ms']:7.0f} | {d['payload_bytes']:6d} | {d['ble_frames']:3d} | {d['ram_bytes']}")
f = R["fit_measured_ms"]
p(f"Measured (C-eq) fit: {f['a']:.2f} + {f['b']:.3f} n ms, R^2 = {f['r2']:.4f}")
fa = R["fit_arm_ms"]
p(f"ARM fit: {fa['a']:.0f} + {fa['b']:.1f} n ms; first n above 1 s: {cross}; fit crossing n = {R['arm_1s_threshold_fit_n']}")
p(f"5-token phases (us): " + ", ".join(f"{k}={v:.0f}" for k, v in five_phase.items()))
p(f"Energy 5-token: {e_j:.3f} J -> {R['tx_per_charge']:.0f} tx per 500 mAh")
p("PUF: " + json.dumps({k: (v['success_rate'], v['max_errors'], v['stable_bits']) for k, v in R['puf_reliability'].items()}))
if V3:
    p(f"C-equivalent scalar-mult cost on host (us): {R['c_equiv_us']}")
if V4:
    p("")
    p("v4 MCU projection (published per-operation timings + BLE air + SE050 I/O + flash + BLE connection):")
    p("   tokens | " + " | ".join(f"{prof} ms" for prof in PROFILES))
    for d in scaling:
        p(f"   {d['tokens']:6d} | " + " | ".join(f"{d[f'mcu_{prof}_ms']:11.0f}" for prof in PROFILES))
    for prof, m in R["mcu"].items():
        p(f"{m['label']}: 5-token {m['five_token_ms']:.0f} ms; fit {m['fit_ms']['a']:.0f} + {m['fit_ms']['b']:.1f} n ms; "
          f"first n above 1 s: {m['first_n_above_1s']} (fit {m['fit_crossing_n']:.1f}); "
          f"campaign mean {m['campaign_mean_ms']['mean']:.0f} +/- {m['campaign_mean_ms']['std']:.0f} ms; "
          f"energy {m['energy_5tok_J']:.3f} J -> {m['tx_per_charge']:.0f} tx per 500 mAh")
    for prof, b in R["five_token_mcu_breakdown_ms"].items():
        p(f"   5-token breakdown {prof} (ms): " + ", ".join(f"{k}={v:.1f}" for k, v in b.items()))
    p("   Primitive costs (ms): " + json.dumps({k: {n: round(v, 2) for n, v in t.items()} for k, t in R["mcu_primitives_ms"].items()}))
    p(f"   BLE connection setup {R['ble_connect_ms']} ms; flash (5 tokens): {R['flash_ms_5tok']}; host keygen {R['host_keygen_us']:.1f} us")
open(f"{OUT}/summary.txt", "w").write("\n".join(L) + "\n")
print("\n".join(L))
