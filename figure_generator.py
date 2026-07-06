"""
Paper-quality figure generator for IoT-CBDC simulation results.
Produces publication-ready matplotlib figures matching IEEE style.
"""

from __future__ import annotations

import os
import statistics
from pathlib import Path
from typing import Any, Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

# IEEE-friendly defaults
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})

ARM_SCALE = 87


def save(fig, name: str, out_dir: str):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    fig.savefig(os.path.join(out_dir, f"{name}.png"))
    fig.savefig(os.path.join(out_dir, f"{name}.pdf"))
    plt.close(fig)


# ===================================================================
# Fig 1: Per-transaction latency across N transactions
# ===================================================================
def fig_transaction_latency(txs: list, out_dir: str) -> str:
    """Line chart: end-to-end latency for each successful transaction."""
    successful = [t for t in txs if t.status.value == "success"]
    if not successful:
        return ""

    indices = list(range(1, len(successful) + 1))
    measured_ms = [t.total_us / 1000 for t in successful]
    arm_ms = [t.total_us / 1000 * ARM_SCALE for t in successful]

    fig, ax1 = plt.subplots(figsize=(8, 4))
    ax1.plot(indices, measured_ms, "b-", linewidth=0.8, alpha=0.7, label="Measured (Apple Silicon)")
    ax1.set_xlabel("Transaction Index")
    ax1.set_ylabel("Measured Latency (ms)", color="b")
    ax1.tick_params(axis="y", labelcolor="b")

    ax2 = ax1.twinx()
    ax2.plot(indices, arm_ms, "r-", linewidth=0.8, alpha=0.7, label="Est. ARM Cortex-M4")
    ax2.set_ylabel("Estimated ARM Latency (ms)", color="r")
    ax2.tick_params(axis="y", labelcolor="r")

    avg_m = statistics.mean(measured_ms)
    avg_a = statistics.mean(arm_ms)
    ax1.axhline(avg_m, color="b", linestyle="--", linewidth=0.6, alpha=0.5)
    ax2.axhline(avg_a, color="r", linestyle="--", linewidth=0.6, alpha=0.5)

    ax1.set_title(f"End-to-End Transaction Latency ({len(successful)} Successful Transactions)")
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right")

    fig.tight_layout()
    save(fig, "fig1_transaction_latency", out_dir)
    return "fig1_transaction_latency"


# ===================================================================
# Fig 2: Phase breakdown (stacked bar)
# ===================================================================
def fig_phase_breakdown(txs: list, out_dir: str) -> str:
    """Stacked bar chart: time breakdown by protocol phase."""
    successful = [t for t in txs if t.status.value == "success"]
    if not successful:
        return ""

    phases = {
        "PUF Boot": [t.puf_boot_us for t in successful],
        "Schnorr Prove": [t.schnorr_prove_us for t in successful],
        "Schnorr Verify": [t.schnorr_verify_us for t in successful],
        "ECDH + HKDF": [t.ecdh_us + t.hkdf_us for t in successful],
        "Encrypt": [t.encrypt_us for t in successful],
        "Decrypt": [t.decrypt_us for t in successful],
        "CB Sig Verify": [t.cb_verify_us for t in successful],
        "Transfer Sign": [t.transfer_sign_us for t in successful],
        "Transfer Verify": [t.transfer_verify_us for t in successful],
        "Pedersen": [t.pedersen_commit_us + t.pedersen_verify_us for t in successful],
        "BLE Transfer": [t.ble_us for t in successful],
    }

    means = {k: statistics.mean(v) / 1000 for k, v in phases.items()}  # ms
    stds = {k: (statistics.stdev(v) / 1000 if len(v) > 1 else 0) for k, v in phases.items()}

    names = list(means.keys())
    vals = [means[n] for n in names]
    errs = [stds[n] for n in names]

    colors = plt.cm.Set3(np.linspace(0, 1, len(names)))

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(names, vals, xerr=errs, color=colors, edgecolor="gray", linewidth=0.5, capsize=3)
    ax.set_xlabel("Time (ms)")
    ax.set_title("Protocol Phase Breakdown (Measured, Mean ± σ)")
    ax.invert_yaxis()

    for bar, val in zip(bars, vals):
        ax.text(bar.get_width() + max(errs) * 0.3, bar.get_y() + bar.get_height() / 2,
                f"{val:.2f}", va="center", fontsize=8)

    fig.tight_layout()
    save(fig, "fig2_phase_breakdown", out_dir)
    return "fig2_phase_breakdown"


# ===================================================================
# Fig 3: Latency vs token count
# ===================================================================
def fig_latency_scaling(scaling_data: list, out_dir: str) -> str:
    """Line chart: latency scaling with token count."""
    if not scaling_data:
        return ""

    tokens = [d["tokens"] for d in scaling_data]
    measured = [d["measured_ms"] for d in scaling_data]
    arm = [d["arm_ms"] for d in scaling_data]

    fig, ax1 = plt.subplots(figsize=(7, 4))
    ax1.plot(tokens, measured, "bo-", label="Measured", linewidth=1.5, markersize=6)
    ax1.set_xlabel("Number of Tokens")
    ax1.set_ylabel("Measured Latency (ms)", color="b")
    ax1.tick_params(axis="y", labelcolor="b")

    ax2 = ax1.twinx()
    ax2.plot(tokens, arm, "rs-", label="Est. ARM Cortex-M4", linewidth=1.5, markersize=6)
    ax2.set_ylabel("Estimated ARM Latency (ms)", color="r")
    ax2.tick_params(axis="y", labelcolor="r")
    ax2.axhline(1000, color="gray", linestyle=":", linewidth=1, label="1-sec threshold")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left")

    ax1.set_title("Latency Scaling with Token Count")
    fig.tight_layout()
    save(fig, "fig3_latency_scaling", out_dir)
    return "fig3_latency_scaling"


# ===================================================================
# Fig 4: PUF reliability across BER
# ===================================================================
def fig_puf_reliability(puf_data: dict, out_dir: str) -> str:
    """Grouped bar: PUF bit errors and boot success vs BER."""
    if not puf_data:
        return ""

    bers = sorted(puf_data.keys())
    avg_errs = [puf_data[b]["avg_errors"] for b in bers]
    max_errs = [puf_data[b]["max_errors"] for b in bers]
    success = [puf_data[b]["success_rate"] for b in bers]

    fig, ax1 = plt.subplots(figsize=(7, 4))
    x = np.arange(len(bers))
    w = 0.3

    ax1.bar(x - w / 2, avg_errs, w, label="Avg Bit Errors", color="#4C72B0", edgecolor="gray")
    ax1.bar(x + w / 2, max_errs, w, label="Max Bit Errors", color="#DD8452", edgecolor="gray")
    ax1.axhline(50, color="red", linestyle="--", linewidth=1, label="BCH correction limit (t=50)")
    ax1.set_xlabel("Bit Error Rate (BER)")
    ax1.set_ylabel("Bit Errors")
    ax1.set_xticks(x)
    ax1.set_xticklabels([f"{b:.2f}" for b in bers])

    ax2 = ax1.twinx()
    ax2.plot(x, success, "g^-", label="Boot Success %", markersize=8, linewidth=1.5)
    ax2.set_ylabel("Boot Success Rate (%)", color="g")
    ax2.set_ylim(0, 110)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left")
    ax1.set_title("PUF Reliability vs Bit Error Rate (10 Devices per BER)")
    fig.tight_layout()
    save(fig, "fig4_puf_reliability", out_dir)
    return "fig4_puf_reliability"


# ===================================================================
# Fig 5: BLE payload scaling
# ===================================================================
def fig_ble_payload(scaling_data: list, out_dir: str) -> str:
    """Bar chart: BLE payload and frames vs token count."""
    if not scaling_data:
        return ""

    tokens = [d["tokens"] for d in scaling_data]
    payload = [d["payload_bytes"] for d in scaling_data]
    frames = [d["ble_frames"] for d in scaling_data]

    fig, ax1 = plt.subplots(figsize=(7, 4))
    x = np.arange(len(tokens))
    ax1.bar(x, payload, 0.5, color="#5975A4", edgecolor="gray", label="Payload (bytes)")
    ax1.set_xlabel("Number of Tokens")
    ax1.set_ylabel("Total BLE Payload (bytes)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(tokens)

    ax2 = ax1.twinx()
    ax2.plot(x, frames, "ro-", label="BLE Frames", markersize=7, linewidth=1.5)
    ax2.set_ylabel("BLE L2CAP Frames", color="r")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left")
    ax1.set_title("BLE Payload and Frame Count vs Token Count")
    fig.tight_layout()
    save(fig, "fig5_ble_payload", out_dir)
    return "fig5_ble_payload"


# ===================================================================
# Fig 6: RAM usage per transaction
# ===================================================================
def fig_ram_usage(txs: list, out_dir: str) -> str:
    """Line chart: RAM usage across transactions."""
    successful = [t for t in txs if t.status.value == "success"]
    if not successful:
        return ""

    indices = list(range(1, len(successful) + 1))
    ram_kb = [t.ram_bytes / 1024 for t in successful]

    fig, ax = plt.subplots(figsize=(8, 3.5))
    ax.plot(indices, ram_kb, "g-", linewidth=0.8, alpha=0.8)
    ax.fill_between(indices, ram_kb, alpha=0.15, color="green")
    ax.axhline(520, color="red", linestyle="--", linewidth=1, label="ESP32 RAM budget (520 KB)")
    avg = statistics.mean(ram_kb)
    ax.axhline(avg, color="green", linestyle=":", linewidth=1, label=f"Avg: {avg:.2f} KB")

    ax.set_xlabel("Transaction Index")
    ax.set_ylabel("Peak RAM Usage (KB)")
    ax.set_title("RAM Usage per Transaction")
    ax.legend()
    ax.set_ylim(0, max(ram_kb) * 2)
    fig.tight_layout()
    save(fig, "fig6_ram_usage", out_dir)
    return "fig6_ram_usage"


# ===================================================================
# Fig 7: Crypto operation benchmark
# ===================================================================
def fig_crypto_benchmark(bench: dict, out_dir: str) -> str:
    """Horizontal bar: crypto operation timing (measured + ARM)."""
    if not bench:
        return ""

    ops = list(bench.keys())
    measured = [bench[o]["mean_us"] for o in ops]
    arm = [bench[o]["arm_us"] for o in ops]
    stds = [bench[o]["std_us"] for o in ops]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), sharey=True)

    y = np.arange(len(ops))
    ax1.barh(y, measured, xerr=stds, color="#5975A4", edgecolor="gray", capsize=2)
    ax1.set_xlabel("Time (µs)")
    ax1.set_title("Measured (Apple Silicon)")
    ax1.set_yticks(y)
    ax1.set_yticklabels(ops)
    ax1.invert_yaxis()

    ax2.barh(y, arm, color="#DD8452", edgecolor="gray")
    ax2.set_xlabel("Time (µs)")
    ax2.set_title(f"Estimated ARM Cortex-M4 ({ARM_SCALE}×)")
    ax2.invert_yaxis()

    fig.suptitle("Cryptographic Operation Benchmark", y=1.02)
    fig.tight_layout()
    save(fig, "fig7_crypto_benchmark", out_dir)
    return "fig7_crypto_benchmark"


# ===================================================================
# Fig 8: Success/failure pie chart
# ===================================================================
def fig_success_failure(txs: list, out_dir: str) -> str:
    """Pie chart: transaction success vs failure modes."""
    if not txs:
        return ""

    from collections import Counter
    status_count = Counter()
    for t in txs:
        if t.status.value == "success":
            status_count["Success"] += 1
        elif t.status.value == "locked":
            status_count["ACK Lost (Locked)"] += 1
        else:
            reason = t.failure_reason
            if "N_MAX" in reason or "sync" in reason.lower():
                status_count["Sync Required (N_MAX)"] += 1
            elif "R_MAX" in reason:
                status_count["R_MAX Exceeded"] += 1
            elif "S_MAX" in reason:
                status_count["S_MAX Exceeded"] += 1
            elif "insufficient" in reason.lower():
                status_count["Insufficient Tokens"] += 1
            else:
                status_count[reason[:30]] += 1

    labels = list(status_count.keys())
    sizes = list(status_count.values())
    colors = ["#2ecc71"] + plt.cm.Reds(np.linspace(0.3, 0.8, len(labels) - 1)).tolist() if "Success" in labels else plt.cm.Set2(np.linspace(0, 1, len(labels)))

    fig, ax = plt.subplots(figsize=(7, 5))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct="%1.0f%%", startangle=90,
        colors=colors, textprops={"fontsize": 9}
    )
    ax.set_title(f"Transaction Outcomes (n={len(txs)})")
    fig.tight_layout()
    save(fig, "fig8_success_failure", out_dir)
    return "fig8_success_failure"


# ===================================================================
# Generate all figures
# ===================================================================
def generate_all_figures(result, out_dir: str) -> List[str]:
    """Generate all paper figures from simulation result. Returns list of figure names."""
    figures = []
    figures.append(fig_transaction_latency(result.transactions, out_dir))
    figures.append(fig_phase_breakdown(result.transactions, out_dir))
    figures.append(fig_latency_scaling(result.latency_scaling, out_dir))
    figures.append(fig_puf_reliability(result.puf_reliability, out_dir))
    figures.append(fig_ble_payload(result.latency_scaling, out_dir))
    figures.append(fig_ram_usage(result.transactions, out_dir))
    figures.append(fig_crypto_benchmark(result.crypto_bench, out_dir))
    figures.append(fig_success_failure(result.transactions, out_dir))
    return [f for f in figures if f]
