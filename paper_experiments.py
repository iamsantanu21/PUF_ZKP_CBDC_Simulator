"""
v2 paper experiment runner
==========================
Runs the protocol-conformant multi-seed experiment (B_max enforced at
loading, balanced denomination float, sync on limit failure) and
regenerates the paper's result figures:

  fig7_tx_outcomes      - outcome distribution, mean +/- sigma over seeds
  fig10_latency_scaling - measured latency + per-primitive ARM projection
  fig12_puf_reliability - PUF boot success vs BER (unchanged model)

Usage:  python3 paper_experiments.py [out_dir]
Run this on the SAME machine used for the measured timings (Apple
Silicon for the paper) so measured panels stay honestly labelled.
"""
import json
import statistics
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from iot_sim_engine import (SimulationConfig, run_simulation, run_multi_seed,
                            arm_projected_ms)

plt.rcParams.update({
    "font.family": "serif", "font.size": 10, "axes.labelsize": 11,
    "axes.titlesize": 12, "xtick.labelsize": 9, "ytick.labelsize": 9,
    "legend.fontsize": 9, "figure.dpi": 150, "savefig.dpi": 300,
    "savefig.bbox": "tight",
})

SEEDS = list(range(42, 52))


def save(fig, name, out):
    Path(out).mkdir(parents=True, exist_ok=True)
    fig.savefig(f"{out}/{name}.pdf")
    fig.savefig(f"{out}/{name}.png")
    plt.close(fig)


def classify(reason):
    r = reason.lower()
    if "ack lost" in r: return "ACK Lost"
    if "insufficient" in r: return "Insuf. Tokens"
    if "r_max" in r: return "$R_{max}$"
    if "s_max" in r: return "$S_{max}$"
    if "n_max" in r: return "$N_{max}$"
    return "Other"


def fig7(ms, out):
    cats = ["Success", "ACK Lost", "Insuf. Tokens", "$R_{max}$", "$S_{max}$"]
    per_seed = {c: [] for c in cats}
    for d in ms["per_seed"]:
        per_seed["Success"].append(d["success"])
        cnt = {c: 0 for c in cats}
        for reason, n in d["failure_breakdown"].items():
            c = classify(reason)
            if c in cnt: cnt[c] += n
        for c in cats[1:]:
            per_seed[c].append(cnt[c])
    means = [statistics.mean(per_seed[c]) for c in cats]
    stds = [statistics.stdev(per_seed[c]) for c in cats]
    colors = ["#5B9BD5", "#ED9B40", "#E870A0", "#B8A038", "#999999"]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    bars = ax.bar(cats, means, yerr=stds, capsize=4,
                  color=colors, edgecolor="gray", linewidth=0.6)
    for b, m in zip(bars, means):
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + max(stds) + 1,
                f"{m:.1f}", ha="center", fontweight="bold", fontsize=9)
    ax.set_ylabel("Transactions per 100 attempts")
    ax.set_title(f"Transaction Outcome Distribution "
                 f"(mean $\\pm\\sigma$, {len(SEEDS)} seeds $\\times$ 100 txns)")
    save(fig, "fig7_tx_outcomes", out)


def fig10(scaling, out):
    toks = [d["tokens"] for d in scaling]
    meas = [d["measured_ms"] for d in scaling]
    arm2 = [d["arm_ms_v2"] for d in scaling]
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7, 6), sharex=True)
    ax1.plot(toks, meas, "bo-", lw=1.5, ms=6, label="Measured")
    for x, y in zip(toks, meas):
        ax1.annotate(f"{y:.0f}", (x, y), textcoords="offset points",
                     xytext=(0, 8), fontsize=8, color="b")
    ax1.set_ylabel("Measured Latency (ms)", color="b")
    ax1.legend(loc="upper left"); ax1.set_title("Latency Scaling with Token Count")
    ax2.plot(toks, [v/1000 for v in arm2], "rs-", lw=1.5, ms=6,
             label="Est. ARM Cortex-M4 (per-primitive scaling + SE050 I/O)")
    for x, y in zip(toks, arm2):
        ax2.annotate(f"{y/1000:.2f}s", (x, y/1000), textcoords="offset points",
                     xytext=(0, 8), fontsize=8, color="r")
    ax2.axhline(1.0, color="gray", ls=":", lw=1, label="1-second IoT threshold")
    ax2.set_xlabel("Number of Tokens"); ax2.set_ylabel("Est. ARM Latency (s)", color="r")
    ax2.legend(loc="upper left")
    fig.tight_layout()
    save(fig, "fig10_latency_scaling", out)


def fig12(puf, out):
    bers = sorted(float(b) for b in puf.keys())
    key = lambda b: puf[b] if b in puf else puf[str(b)]
    avg = [key(b)["avg_errors"] for b in bers]
    mx = [key(b)["max_errors"] for b in bers]
    suc = [key(b)["success_rate"] for b in bers]
    x = np.arange(len(bers)); w = 0.3
    fig, ax1 = plt.subplots(figsize=(7, 4))
    ax1.bar(x - w/2, avg, w, label="Avg Bit Errors", color="#4C72B0", edgecolor="gray")
    ax1.bar(x + w/2, mx, w, label="Max Bit Errors", color="#DD8452", edgecolor="gray")
    ax1.axhline(50, color="red", ls="--", lw=1, label="BCH correction limit (t=50)")
    ax1.set_xlabel("Bit Error Rate (BER)"); ax1.set_ylabel("Bit Errors")
    ax1.set_xticks(x); ax1.set_xticklabels([f"{b:.2f}" for b in bers])
    ax2 = ax1.twinx()
    ax2.plot(x, suc, "g^-", label="Boot Success %", ms=8, lw=1.5)
    ax2.set_ylabel("Boot Success Rate (%)", color="g"); ax2.set_ylim(0, 110)
    l1, la1 = ax1.get_legend_handles_labels(); l2, la2 = ax2.get_legend_handles_labels()
    ax1.legend(l1 + l2, la1 + la2, loc="center left", fontsize=8)
    ax1.set_title("PUF Reliability vs Bit Error Rate (10 Devices per BER)")
    save(fig, "fig12_puf_reliability", out)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "paper_figures_v2"
    cfg = SimulationConfig()          # v2 defaults (protocol-conformant)
    ms = run_multi_seed(cfg, SEEDS)
    rep = run_simulation(SimulationConfig())   # representative seed-42 run
    succ = rep.successful
    stats = {
        "multi_seed": ms,
        "rep": {
            "mean_latency_ms": statistics.mean([t.total_us/1000 for t in succ]),
            "mean_arm_v2_ms": statistics.mean([arm_projected_ms(t) for t in succ]),
            "mean_tokens": statistics.mean([t.n_tokens for t in succ]),
        },
    }
    Path(out).mkdir(parents=True, exist_ok=True)
    json.dump(stats, open(f"{out}/stats.json", "w"), indent=1, default=str)
    fig7(ms, out)
    fig10(rep.latency_scaling, out)
    fig12({str(k): v for k, v in rep.puf_reliability.items()}, out)
    print("figures + stats.json written to", out)
