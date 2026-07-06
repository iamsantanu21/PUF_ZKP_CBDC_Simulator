"""
IoT-CBDC Dual-Offline Payment Simulator — Streamlit Dashboard
=============================================================
Simulates PUF-based CBDC protocol on resource-constrained IoT devices
(ESP32 @ 240 MHz / nRF52840 / NXP SE050). All timings are scaled to
ARM Cortex-M4 to mimic real IoT execution without physical hardware.

Run:  streamlit run dashboard.py
"""

from __future__ import annotations

import json
import os
import statistics
import time
from collections import Counter
from pathlib import Path

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ── Import simulation engine ────────────────────────────────────
from iot_sim_engine import (
    ARM_SCALE_FACTOR,
    MainWallet,
    SimulationConfig,
    SimulationResult,
    TxStatus,
    TokenState,
    run_simulation,
    run_crypto_benchmark,
)
from figure_generator import generate_all_figures

# ── Page config ─────────────────────────────────────────────────
st.set_page_config(
    page_title="IoT-CBDC Simulator",
    page_icon="₹",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS: large fonts & clean look ────────────────────────
st.markdown("""
<style>
    /* ── Reduce blank space everywhere ── */
    .block-container { padding-top: 1rem !important; padding-bottom: 0 !important; }
    [data-testid="stVerticalBlock"] > div { gap: 0.35rem !important; }
    [data-testid="stHorizontalBlock"] { gap: 0.5rem !important; }
    [data-testid="stMetric"] { padding: 0.3rem 0 !important; }
    [data-testid="stExpander"] { margin-bottom: 0.25rem !important; }
    hr { margin: 0.4rem 0 !important; }
    h1, h2, h3, h4, h5 { margin-top: 0.3rem !important; margin-bottom: 0.2rem !important; }
    .stTabs [data-baseweb="tab-panel"] { padding-top: 0.5rem !important; }
    [data-testid="stDataFrame"] { margin-bottom: 0.2rem !important; }
    .stMarkdown { margin-bottom: 0 !important; }
    [data-testid="stCodeBlock"] { margin-bottom: 0.2rem !important; }
    [data-testid="stCaption"] { margin-top: 0 !important; padding-top: 0 !important; }

    /* Metric labels & values */
    [data-testid="stMetricLabel"] { font-size: 1.15rem !important; }
    [data-testid="stMetricValue"] { font-size: 2.1rem !important; font-weight: 600 !important; }
    /* Dataframe cells */
    .stDataFrame td, .stDataFrame th { font-size: 1.05rem !important; }
    /* Headings */
    h1 { font-size: 2.2rem !important; }
    h2 { font-size: 1.8rem !important; }
    h3 { font-size: 1.5rem !important; }
    h5 { font-size: 1.25rem !important; }
    /* Sidebar & form labels */
    .stSelectbox label, .stSlider label, .stNumberInput label { font-size: 1.05rem !important; }
    /* Tab labels */
    button[data-baseweb="tab"] { font-size: 1.05rem !important; }
    /* General body text */
    .stMarkdown p, .stMarkdown li { font-size: 1.05rem !important; }
    /* Info / warning boxes */
    .stAlert p { font-size: 1.0rem !important; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar: Simulation Parameters ──────────────────────────────
st.sidebar.title("IoT-CBDC Simulator")
st.sidebar.markdown("---")

st.sidebar.subheader("Simulation Parameters")
n_devices = st.sidebar.slider("Number of IoT devices", 2, 20, 6, 1)
n_banks = st.sidebar.slider("Number of banks", 1, 4, 2)
n_transactions = st.sidebar.slider("Number of transactions", 1, 500, 10, 1)

# Hidden defaults (not exposed in sidebar)
ack_drop = 0.05
ber = 0.03
seed = 42

st.sidebar.markdown("---")
with st.sidebar.expander("IoT Compliance Policy", expanded=False):
    v_max = st.number_input("V_MAX (₹ per txn)", value=200)
    s_max = st.number_input("S_MAX (₹ offline spend)", value=500)
    r_max = st.number_input("R_MAX (₹ offline receive)", value=500)
    n_max_tx = st.number_input("N_MAX (txns before sync)", value=4)
    min_amount = st.number_input("Min transaction amount (₹)", 1, 100, 10)
    max_amount = st.number_input("Max transaction amount (₹)", 10, 200, 50)
    tokens_per_device = st.slider("Tokens per device", 10, 300, 150, 5)

run_btn = st.sidebar.button("▶  Run Simulation", width="stretch", type="primary")
export_figs_btn = st.sidebar.button("Export", width="stretch")

# ── Main Title ──────────────────────────────────────────────────
st.title("IoT-CBDC Dual-Offline Payment Simulator")


# ── Helper: run and cache ───────────────────────────────────────
@st.cache_resource(show_spinner=False)
def cached_simulation(
    n_dev, n_bank, n_tx, tok_per_dev, min_a, max_a, ack_d, b, s
):
    from iot_sim_engine import IoTPolicy
    config = SimulationConfig(
        n_devices=n_dev,
        n_banks=n_bank,
        devices_per_bank=n_dev // n_bank,
        tokens_per_device=tok_per_dev,
        n_transactions=n_tx,
        min_amount=min_a,
        max_amount=max_a,
        ack_drop_prob=ack_d,
        ber=b,
        seed=s,
    )
    return run_simulation(config)


# ── Run simulation ──────────────────────────────────────────────
if run_btn:
    cached_simulation.clear()
    with st.spinner("Running IoT-CBDC simulation on simulated ARM Cortex-M4..."):
        t0 = time.time()
        result = cached_simulation(
            n_devices, n_banks, n_transactions, tokens_per_device,
            min_amount, max_amount, ack_drop, ber, seed,
        )
        elapsed = time.time() - t0
    st.session_state["result"] = result
    st.session_state["elapsed"] = elapsed
    st.toast(f"Simulation complete in {elapsed:.1f}s", icon="✅")

if "result" not in st.session_state:
    st.info("Configure parameters and click **Run Simulation** to begin.")
    st.stop()

result: SimulationResult = st.session_state["result"]
elapsed = st.session_state.get("elapsed", 0)

# ── Export paper figures ────────────────────────────────────────
if export_figs_btn and "result" in st.session_state:
    out_dir = str(Path(__file__).parent / "paper_figures")
    with st.spinner("Generating publication-quality figures..."):
        figs = generate_all_figures(result, out_dir)
    st.success(f"Exported {len(figs)} figures to `{out_dir}/`")

# ===================================================================
# DASHBOARD TABS
# ===================================================================
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "Overview",
    "Wallet Explorer",
    "Latency",
    "PUF",
    "BLE & Resources",
    "Crypto",
    "Raw Data",
])

# ── Helper data ─────────────────────────────────────────────────
txs = result.transactions
successful = [t for t in txs if t.status == TxStatus.SUCCESS]
failed = [t for t in txs if t.status == TxStatus.FAILED]
locked = [t for t in txs if t.status == TxStatus.LOCKED]

# ===================================================================
# TAB 1: Overview
# ===================================================================
with tab1:
    st.subheader("Simulation Summary")

    # KPI row
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Transactions", len(txs))
    c2.metric("Success Rate", f"{result.success_rate():.1f}%")
    c3.metric("Successful", len(successful))
    c4.metric("Failed", len(failed))
    c5.metric("ACK Lost", len(locked))

    c6, c7, c8, c9 = st.columns(4)
    if successful:
        avg_arm = statistics.mean([t.total_us / 1000 * ARM_SCALE_FACTOR for t in successful])
        c6.metric("Avg IoT Latency", f"{avg_arm:.0f} ms")
        avg_tok = statistics.mean([t.n_tokens for t in successful])
        c7.metric("Avg Tokens/Tx", f"{avg_tok:.1f}")
        total_val = sum(t.amount for t in successful)
        c8.metric("Total Value (₹)", f"{total_val:,}")
    c9.metric("Syncs Triggered", len(result.syncs))

    st.markdown("---")

    # Failure breakdown
    col_l, col_r = st.columns(2)
    with col_l:
        st.subheader("Transaction Outcome Distribution")
        status_counts = Counter()
        for t in txs:
            if t.status == TxStatus.SUCCESS:
                status_counts["✅ Success"] += 1
            elif t.status == TxStatus.LOCKED:
                status_counts["⚠️ ACK Lost (Locked)"] += 1
            else:
                reason = t.failure_reason
                if "N_MAX" in reason or "sync" in reason.lower():
                    status_counts["⛔ Sync Required (N_MAX)"] += 1
                elif "R_MAX" in reason:
                    status_counts["⛔ R_MAX Exceeded"] += 1
                elif "S_MAX" in reason:
                    status_counts["⛔ S_MAX Exceeded"] += 1
                elif "insufficient" in reason.lower():
                    status_counts["⛔ Insufficient Tokens"] += 1
                else:
                    status_counts[f"⛔ {reason[:25]}"] += 1

        fig_pie = px.pie(
            names=list(status_counts.keys()),
            values=list(status_counts.values()),
            color_discrete_sequence=["#2ecc71", "#e74c3c", "#f39c12", "#9b59b6", "#3498db", "#1abc9c"],
        )
        fig_pie.update_layout(height=350)
        st.plotly_chart(fig_pie, width="stretch")

    with col_r:
        st.subheader("Inter-Bank vs Intra-Bank")
        bank_routes = {"Intra-Bank": {"total": 0, "success": 0, "value": 0},
                       "Inter-Bank": {"total": 0, "success": 0, "value": 0}}
        for t in txs:
            try:
                s_bank = result.devices[t.sender_id].bank_id
                r_bank = result.devices[t.receiver_id].bank_id
                route = "Intra-Bank" if s_bank == r_bank else "Inter-Bank"
            except (KeyError, AttributeError):
                route = "Intra-Bank"
            bank_routes[route]["total"] += 1
            if t.status == TxStatus.SUCCESS:
                bank_routes[route]["success"] += 1
                bank_routes[route]["value"] += t.amount

        bank_df = pd.DataFrame([
            {"Route": k, "Total": v["total"],
             "Success %": f"{v['success'] / v['total'] * 100:.1f}%" if v["total"] else "N/A",
             "Total Value (₹)": v["value"]}
            for k, v in bank_routes.items()
        ])
        st.dataframe(bank_df, width="stretch", hide_index=True)

    st.markdown("---")
    st.subheader("Per-Device Summary")
    dev_data = []
    for dev_id, dev in result.devices.items():
        locked_bal = sum(t.denomination for t in dev.pending.values() if t.state == TokenState.LOCKED)
        pending_bal = sum(t.denomination for t in dev.pending.values() if t.state != TokenState.LOCKED)
        needs_sync = dev.offline_tx_count > 0 or locked_bal > 0 or pending_bal > 0
        dev_data.append({
            "Device": dev_id,
            "Main Wallet": getattr(dev, 'wallet_id', '—'),
            "Bank": dev.bank_id,
            "Available (₹)": dev.balance(),
            "Locked (₹)": locked_bal,
            "Pending (₹)": pending_bal,
            "Tokens": dev.token_count(),
            "SE050 Used": f"{dev.se050_usage_bytes() / 1024:.1f} KB",
            "Offline Txns": dev.offline_tx_count,
            "Spend (₹)": dev.cumulative_spend,
            "Receive (₹)": dev.cumulative_receive,
            "Sync Needed": "⚠️ Required" if needs_sync else "✅ Not Required",
        })
    st.dataframe(pd.DataFrame(dev_data), width="stretch", hide_index=True)


# ===================================================================
# TAB 2: Wallet & Device Explorer
# ===================================================================
with tab2:
    st.subheader("Main Wallet & IoT Device Explorer")

    # ── Main Wallet Selector ─────────────────────────────────
    wallet_ids = list(getattr(result, 'wallets', {}).keys()) if hasattr(result, 'wallets') else []
    if not wallet_ids:
        st.warning("Wallet data not available. Please re-run the simulation.")
        st.stop()

    selected_wallet = st.selectbox(
        "Select Main Wallet",
        wallet_ids,
        format_func=lambda w: f"{w}  —  {result.wallets[w].bank_id}  ({len(result.wallets[w].device_ids)} IoT device{'s' if len(result.wallets[w].device_ids) != 1 else ''})",
    )
    mw = result.wallets[selected_wallet]

    # ── Main Wallet Summary ─────────────────────────────────
    st.markdown("---")
    st.subheader(f"{mw.wallet_id} — {mw.bank_id}")

    # Compute aggregated IoT Sub-Wallet stats
    mw_devs = [result.devices[d] for d in mw.device_ids if d in result.devices]
    iot_available = sum(d.balance() for d in mw_devs)
    iot_locked = sum(
        sum(t.denomination for t in d.pending.values() if t.state == TokenState.LOCKED)
        for d in mw_devs
    )
    iot_pending = sum(
        sum(t.denomination for t in d.pending.values() if t.state != TokenState.LOCKED)
        for d in mw_devs
    )
    iot_tokens = sum(d.token_count() for d in mw_devs)
    total_loaded = getattr(mw, 'total_loaded', 0)
    swept_back = getattr(mw, 'swept_back', 0)
    total_offline_txns = sum(d.offline_tx_count for d in mw_devs)
    devices_needing_sync = sum(
        1 for d in mw_devs
        if d.offline_tx_count > 0
        or sum(t.denomination for t in d.pending.values()) > 0
    )

    own_bal = getattr(mw, 'own_balance', 0)
    mw_known = getattr(mw, 'mw_known_iot_bal', 0)
    total_bal = own_bal + iot_available + iot_pending + iot_locked

    # ── Main Wallet KPIs ─────────────────────────────────────
    w1, w2, w3 = st.columns(3)
    w1.metric("Total Balance", f"₹{total_bal:,}",
              help="MW Own + IoT Spendable + IoT Pending/Locked (ground truth)")
    w2.metric("IoT Balance (Last Sync)", f"₹{mw_known:,}",
              help="What MW knows about IoT sub-wallets — updated only at sync")
    w3.metric("MW Own Balance", f"₹{own_bal:,}",
              help="Retained on Main Wallet, not loaded onto any IoT device")

    # ── Wallet Balance Distribution ──────────────────────────
    col_dist, col_tokens = st.columns(2)
    with col_dist:
        st.markdown("**IoT Sub-Wallet Spendable Distribution**")
        dist_labels = [d.device_id for d in mw_devs]
        dist_values = [d.balance() for d in mw_devs]
        fig_dist = px.pie(
            names=dist_labels, values=dist_values,
            color_discrete_sequence=["#2ecc71", "#e74c3c", "#f39c12", "#9b59b6", "#1abc9c", "#3498db"][:len(mw_devs)],
            hole=0.4,
        )
        fig_dist.update_layout(height=300, margin=dict(t=20, b=20))
        st.plotly_chart(fig_dist, width="stretch")

    with col_tokens:
        st.markdown("**Token Distribution Across IoT Devices**")
        tok_labels = [d.device_id for d in mw_devs]
        tok_values = [len(d.unspent) + len(d.pending) for d in mw_devs]
        fig_tok = px.bar(
            x=tok_labels, y=tok_values,
            labels={"x": "IoT Device", "y": "Tokens"},
            color=tok_labels,
            color_discrete_sequence=["#2ecc71", "#e74c3c", "#f39c12", "#9b59b6", "#1abc9c"],
        )
        fig_tok.update_layout(height=300, showlegend=False, margin=dict(t=20, b=20))
        st.plotly_chart(fig_tok, width="stretch")

    # ===================================================================
    # IoT Device Detail
    # ===================================================================
    st.markdown("---")
    st.subheader("IoT Device Detail")

    linked_dev_ids = mw.device_ids
    selected_dev = st.selectbox("Select IoT Device", linked_dev_ids, index=0, key="iot_dev_select")
    dev = result.devices[selected_dev]

    # ── Device KPIs ───────────────────────────────────────────
    locked_bal = sum(t.denomination for t in dev.pending.values() if t.state == TokenState.LOCKED)
    pending_bal = sum(t.denomination for t in dev.pending.values() if t.state != TokenState.LOCKED)
    needs_sync = dev.offline_tx_count > 0 or locked_bal > 0 or pending_bal > 0
    se_usage = dev.se050_usage_bytes()
    se_pct = se_usage / (50 * 1024) * 100

    b1, b2, b3, b4, b5, b6 = st.columns(6)
    b1.metric("Spendable (₹)", dev.balance())
    b2.metric("Locked (₹)", locked_bal)
    b3.metric("Pending (₹)", pending_bal)
    b4.metric("Spent Since Sync", f"₹{dev.cumulative_spend}")
    b5.metric("Offline Txns", f"{dev.offline_tx_count}/{dev.policy.n_max_tx}")
    b6.metric("Sync", "⚠️ Required" if needs_sync else "✅ Not Required")

    # ── PUF & Crypto Keys ────────────────────────────────────
    st.markdown("---")
    puf_col, key_col = st.columns(2)
    with puf_col:
        st.markdown("##### PUF Authentication")
        puf_enrollment = dev.puf._db.get(selected_dev)
        puf_data = [
            {"Property": "SRAM-PUF Size", "Value": f"{dev.puf.bit_length} bits"},
            {"Property": "BCH Correction (t)", "Value": str(dev.puf.correction_bits)},
            {"Property": "BER", "Value": str(dev.ber)},
            {"Property": "Last Boot Errors", "Value": f"{dev.puf_boot_distance} bits"},
            {"Property": "Boot Time (ARM)", "Value": f"{dev.last_puf_boot_us * ARM_SCALE_FACTOR / 1000:.1f} ms"},
            {"Property": "Fingerprint", "Value": puf_enrollment.fingerprint[:16].hex() + "…"},
            {"Property": "Helper Data", "Value": puf_enrollment.helper_data[:16].hex() + "…"},
            {"Property": "PUF Secret", "Value": puf_enrollment.key[:16].hex() + "…"},
        ]
        st.dataframe(pd.DataFrame(puf_data), width="stretch", hide_index=True)

    with key_col:
        st.markdown("##### Derived Crypto Keys (SE050)")
        key_data = [
            {"Key": "Ed25519 (Signing)", "Value": dev.ed_pk.hex()[:32] + "…" if dev.ed_pk else "N/A"},
            {"Key": "X25519 (ECDH)", "Value": dev.x_pk.hex()[:32] + "…" if dev.x_pk else "N/A"},
            {"Key": "CB Public Key", "Value": dev.cb_pk.hex()[:32] + "…" if dev.cb_pk else "N/A"},
        ]
        st.dataframe(pd.DataFrame(key_data), width="stretch", hide_index=True)

        st.markdown("##### Compliance Policy")
        policy_data = [
            {"Param": "V_MAX", "Value": f"₹{dev.policy.v_max}", "Desc": "Max per-txn"},
            {"Param": "S_MAX", "Value": f"₹{dev.policy.s_max_offline}", "Desc": "Max offline spend"},
            {"Param": "R_MAX", "Value": f"₹{dev.policy.r_max_offline}", "Desc": "Max offline receive"},
            {"Param": "B_MAX", "Value": f"₹{dev.policy.b_max}", "Desc": "Max loading balance"},
            {"Param": "N_MAX", "Value": str(dev.policy.n_max_tx), "Desc": "Txns before sync"},
        ]
        st.dataframe(pd.DataFrame(policy_data), width="stretch", hide_index=True)

    # ── SE050 Dual-Table Token Pool ──────────────────────────
    st.markdown("---")
    st.markdown(f"##### SE050 Token Pool — {len(dev.unspent)} unspent (₹{dev.balance()}) | {len(dev.pending)} pending")
    col_u, col_p = st.columns(2)
    with col_u:
        st.markdown(f"**Unspent** ({len(dev.unspent)} tokens)")
        if dev.unspent:
            u_rows = [{"TID": tid[:12] + "…", "₹": tok.denomination, "Bank": tok.issuer_bank}
                      for tid, tok in list(dev.unspent.items())[:20]]
            st.dataframe(pd.DataFrame(u_rows), width="stretch", hide_index=True)
            if len(dev.unspent) > 20:
                st.caption(f"… +{len(dev.unspent) - 20} more")
        else:
            st.info("Empty")

    with col_p:
        st.markdown(f"**Pending** ({len(dev.pending)} tokens)")
        if dev.pending:
            p_rows = [{"TID": tid[:12] + "…", "₹": tok.denomination, "State": tok.state.value}
                      for tid, tok in list(dev.pending.items())[:20]]
            st.dataframe(pd.DataFrame(p_rows), width="stretch", hide_index=True)
        else:
            st.info("Empty — cleared on sync")

    # ── Device Transaction Log ───────────────────────────────
    st.markdown("---")
    st.markdown("##### Transaction Log")
    dev_txs = [t for t in txs if t.sender_id == selected_dev or t.receiver_id == selected_dev]
    if dev_txs:
        for idx, t in enumerate(dev_txs):
            role = "Send" if t.sender_id == selected_dev else "Recv"
            cpty = t.receiver_id if role == "Send" else t.sender_id
            status_icon = "✅" if t.status == TxStatus.SUCCESS else ("⚠️" if t.status == TxStatus.LOCKED else "❌")
            arm_ms = round(t.total_us / 1000 * ARM_SCALE_FACTOR, 1)
            label = f"{status_icon}  TX {t.tx_id[:10]}  |  {role} → {cpty}  |  ₹{t.amount}  ({t.n_tokens} tokens)  |  {t.status.value}  |  {arm_ms} ms"

            with st.expander(label, expanded=False):
                pm = getattr(t, 'protocol_msgs', None) or {}
                m1 = pm.get("msg1_init", {})
                m2 = pm.get("msg2_auth_resp", {})
                m3 = pm.get("msg3_auth_proof", {})
                m4 = pm.get("msg4_payload", {})
                m5 = pm.get("msg5_ack", {})
                ped = pm.get("pedersen", {})
                ble_sum = pm.get("ble_summary", {})

                # ── Overview KPIs ──
                ov1, ov2, ov3, ov4 = st.columns(4)
                ov1.metric("Amount", f"₹{t.amount}")
                ov2.metric("Tokens", t.n_tokens)
                ov3.metric("Status", t.status.value)
                ov4.metric("Total Latency", f"{arm_ms} ms")

                if t.failure_reason:
                    st.error(f"**Failure:** {t.failure_reason}")

                st.markdown("---")

                # ═══════════════════════════════════════════════
                # MSG 1 — Sender → Receiver (Init + Commitment)
                # ═══════════════════════════════════════════════
                st.markdown("#### MSG 1 — Sender → Receiver  *(Init + Pedersen Commitment)*")
                st.code(f"""sender_ed_pk  : {m1.get('sender_ed_pk', 'N/A')}
sender_x_pk   : {m1.get('sender_x_pk', 'N/A')}
amount        : ₹{m1.get('amount', t.amount)}
commitment    : {m1.get('commitment', 'N/A')}
timestamp     : {m1.get('timestamp', 'N/A')}
device_id     : {m1.get('device_id', t.sender_id)}
BLE bytes     : {m1.get('ble_bytes', '—')}""", language="yaml")

                st.markdown("---")

                # ═══════════════════════════════════════════════
                # MSG 2 — Receiver → Sender (Schnorr Auth)
                # ═══════════════════════════════════════════════
                st.markdown("#### MSG 2 — Receiver → Sender  *(Schnorr Auth Response)*")
                st.code(f"""receiver_ed_pk : {m2.get('receiver_ed_pk', 'N/A')}
receiver_x_pk  : {m2.get('receiver_x_pk', 'N/A')}
schnorr_proof  : {m2.get('schnorr_proof', 'N/A')}
timestamp      : {m2.get('timestamp', 'N/A')}
BLE bytes      : {m2.get('ble_bytes', '—')}""", language="yaml")
                sp_r_ms = round(t.schnorr_prove_us / 2 / 1000 * ARM_SCALE_FACTOR, 2) if t.schnorr_prove_us else 0
                sv_r_ms = round(t.schnorr_verify_us / 2 / 1000 * ARM_SCALE_FACTOR, 2) if t.schnorr_verify_us else 0
                st.caption(f"Schnorr Prove: {sp_r_ms} ms  ·  Sender verifies → Schnorr Verify: {sv_r_ms} ms")

                st.markdown("---")

                # ═══════════════════════════════════════════════
                # MSG 3 — Sender → Receiver (Sender Auth Proof)
                # ═══════════════════════════════════════════════
                st.markdown("#### MSG 3 — Sender → Receiver  *(Schnorr Auth Proof)*")
                st.code(f"""sender_proof : {m3.get('sender_proof', 'N/A')}
timestamp    : {m3.get('timestamp', 'N/A')}
BLE bytes    : {m3.get('ble_bytes', '—')}""", language="yaml")
                sp_s_ms = round(t.schnorr_prove_us / 2 / 1000 * ARM_SCALE_FACTOR, 2) if t.schnorr_prove_us else 0
                sv_s_ms = round(t.schnorr_verify_us / 2 / 1000 * ARM_SCALE_FACTOR, 2) if t.schnorr_verify_us else 0
                st.caption(f"Schnorr Prove: {sp_s_ms} ms  ·  Receiver verifies → Schnorr Verify: {sv_s_ms} ms")

                st.markdown("---")

                # ═══════════════════════════════════════════════
                # MSG 4 — Sender → Receiver (Encrypted Payload)
                # ═══════════════════════════════════════════════
                st.markdown("#### MSG 4 — Sender → Receiver  *(Encrypted Token Payload)*")

                ecdh_ms = round(t.ecdh_us / 1000 * ARM_SCALE_FACTOR, 2)
                hkdf_ms = round(t.hkdf_us / 1000 * ARM_SCALE_FACTOR, 2)
                enc_ms = round(t.encrypt_us / 1000 * ARM_SCALE_FACTOR, 2)

                st.markdown("**Key Exchange (X25519 ECDH + HKDF)**")
                st.code(f"""shared_secret : {m4.get('shared_secret', 'N/A')}
session_key   : {m4.get('session_key', 'N/A')}
ECDH          : {ecdh_ms} ms  |  HKDF: {hkdf_ms} ms""", language="yaml")

                st.markdown("**AES-256-GCM Encrypted Envelope**")
                ct_hex = m4.get('ciphertext', '')
                ct_preview = ct_hex[:64] + "…" if len(ct_hex) > 64 else ct_hex
                st.code(f"""nonce      : {m4.get('nonce', 'N/A')}
ciphertext : {ct_preview}
             ({m4.get('ciphertext_len', '?')} bytes)
tag        : {m4.get('tag', 'N/A')}
Encrypt    : {enc_ms} ms""", language="yaml")

                st.markdown("**Plaintext Payload (inside AES envelope)**")
                tok_wire = m4.get('tokens', [])
                tok_sel_ms = round(t.token_select_us / 1000 * ARM_SCALE_FACTOR, 2)
                tsign_ms = round(t.transfer_sign_us / 1000 * ARM_SCALE_FACTOR, 2)
                st.code(f"""tx_id     : {t.tx_id}
seq_no    : {m4.get('seq_no', '—')}
amount    : ₹{t.amount}
blinding  : {m4.get('blinding', 'N/A')}
tokens    : {t.n_tokens} tokens (selected in {tok_sel_ms} ms, signed in {tsign_ms} ms)""", language="yaml")

                if tok_wire:
                    st.markdown(f"**Token Details** ({len(tok_wire)} tokens)")
                    for i, tw in enumerate(tok_wire[:10]):
                        cb_preview = tw.get('cb_sig', '')[:32] + "…" if len(tw.get('cb_sig', '')) > 32 else tw.get('cb_sig', '')
                        xf_preview = tw.get('xfer_sig', '')[:32] + "…" if len(tw.get('xfer_sig', '')) > 32 else tw.get('xfer_sig', '')
                        st.code(f"""Token {i+1}:
  tid          : {tw.get('tid', '—')}
  denomination : ₹{tw.get('denomination', '—')}
  issuer       : {tw.get('issuer', '—')}
  cb_sig       : {cb_preview}
  xfer_sig     : {xf_preview}""", language="yaml")
                    if len(tok_wire) > 10:
                        st.caption(f"… +{len(tok_wire) - 10} more tokens")

                st.markdown("**Receiver Decryption & Verification**")
                dec_ms = round(t.decrypt_us / 1000 * ARM_SCALE_FACTOR, 2)
                cb_ms = round(t.cb_verify_us / 1000 * ARM_SCALE_FACTOR, 2)
                tverify_ms = round(t.transfer_verify_us / 1000 * ARM_SCALE_FACTOR, 2)
                ped_v_ms = round(t.pedersen_verify_us / 1000 * ARM_SCALE_FACTOR, 2)
                st.code(f"""AES-256-GCM Decrypt       : {dec_ms} ms
CB Sig Verify ({t.n_tokens} tokens) : {cb_ms} ms
Transfer Verify ({t.n_tokens} tok)  : {tverify_ms} ms
Pedersen Verify           : {ped_v_ms} ms
  commitment : {ped.get('commitment', 'N/A')}
  blinding   : {ped.get('blinding', 'N/A')}
  amount     : ₹{ped.get('amount', t.amount)}""", language="yaml")

                st.markdown("---")

                # ═══════════════════════════════════════════════
                # MSG 5 — Receiver → Sender (ACK)
                # ═══════════════════════════════════════════════
                st.markdown("#### MSG 5 — Receiver → Sender  *(ACK)*")
                ack_delivered = m5.get('status', 'unknown')
                ble_ms = round(t.ble_us / 1000 * ARM_SCALE_FACTOR, 2)
                st.code(f"""tx_id     : {m5.get('tx_id', t.tx_id)}
status    : {ack_delivered}
BLE bytes : {m5.get('ble_bytes', '—')}""", language="yaml")

                st.markdown("---")

                # ═══════════════════════════════════════════════
                # BLE Summary + Latency Breakdown
                # ═══════════════════════════════════════════════
                st.markdown("**BLE Transport Summary**")
                st.code(f"""Total BLE payload : {ble_sum.get('total_bytes', '—')} bytes
BLE frames        : {ble_sum.get('total_frames', '—')}
BLE latency       : {ble_ms} ms
RAM estimate      : {t.ram_bytes} bytes""", language="yaml")


    else:
        st.info(f"No transactions for {selected_dev}")

    # ── Sync History ─────────────────────────────────────────
    st.markdown("---")
    st.markdown("##### Sync History")
    if dev.sync_log:
        for idx, s in enumerate(dev.sync_log):
            arm_ms = round(s.duration_us / 1000 * ARM_SCALE_FACTOR, 1)
            swept_tag = f"  |  Swept {s.tokens_swept} tokens (₹{s.amount_swept})" if s.tokens_swept else ""
            label = (
                f"✅  SYNC #{idx + 1}  |  {s.device_id}  |  "
                f"Uploaded {s.tokens_uploaded} tx  |  Confirmed {s.tokens_received} tokens  |  "
                f"{arm_ms} ms{swept_tag}"
            )

            with st.expander(label, expanded=False):
                # ── Overview KPIs ──
                k1, k2, k3, k4 = st.columns(4)
                k1.metric("TX Logs Uploaded", s.tokens_uploaded)
                k2.metric("Tokens Confirmed", s.tokens_received)
                k3.metric("Tokens Swept", s.tokens_swept)
                k4.metric("Duration", f"{arm_ms} ms")

                st.markdown("---")

                # ── Sync Protocol Steps ──
                st.markdown("#### Sync Protocol Steps")
                st.code(f"""1. Upload tx_log to bank
   → {s.tokens_uploaded} transaction records uploaded
   → Bank ACKs receipt

2. Clear local tx_log
   → Device tx_log cleared after bank confirmation

3. Move pending → unspent
   → {s.tokens_received} pending tokens confirmed as unspent
   → LOCKED tokens resolved by bank (discard or restore)

4. Reset compliance counters
   → offline_tx_count : 0
   → cumulative_spend : ₹0
   → cumulative_receive: ₹0

5. Balance sweep (excess → main wallet)
   → Balance before sweep : ₹{s.balance_before_sweep}
   → Tokens swept back    : {s.tokens_swept}
   → Amount swept         : ₹{s.amount_swept}
   → Balance after sweep  : ₹{s.balance_after_sweep}
   → Policy b_max         : ₹{dev.policy.b_max}""", language="yaml")

                st.markdown("---")

                # ── Balance Impact ──
                st.markdown("#### Balance Impact")
                b1, b2, b3 = st.columns(3)
                b1.metric("Before Sweep", f"₹{s.balance_before_sweep}")
                b2.metric("After Sweep", f"₹{s.balance_after_sweep}")
                delta = s.balance_before_sweep - s.balance_after_sweep
                b3.metric("Returned to MW", f"₹{delta}")

                if s.tokens_swept > 0:
                    st.caption(
                        f"Device exceeded b_max (₹{dev.policy.b_max}). "
                        f"{s.tokens_swept} smallest tokens (₹{s.amount_swept}) swept back to main wallet."
                    )

    else:
        st.info(f"No sync events for {selected_dev}")


# ===================================================================
# TAB 3: Latency Analysis (IoT-only framing)
# ===================================================================
with tab3:
    if not successful:
        st.warning("No successful transactions to analyze.")
    else:
        st.subheader("Per-Transaction IoT Latency (ARM Cortex-M4 @ 240 MHz)")
        indices = list(range(1, len(successful) + 1))
        arm_ms = [t.total_us / 1000 * ARM_SCALE_FACTOR for t in successful]

        fig_lat = go.Figure()
        fig_lat.add_trace(
            go.Scatter(x=indices, y=arm_ms, name="IoT Latency (ARM est.)",
                       line=dict(color="#e74c3c", width=1.5),
                       fill="tozeroy", fillcolor="rgba(231,76,60,0.1)"),
        )
        if len(arm_ms) > 1:
            avg = statistics.mean(arm_ms)
            fig_lat.add_hline(y=avg, line_dash="dash", line_color="blue",
                              annotation_text=f"Avg: {avg:.0f} ms")
        fig_lat.add_hline(y=1000, line_dash="dot", line_color="gray",
                          annotation_text="1-sec UX threshold")
        fig_lat.update_yaxes(title_text="IoT Latency (ms)")
        fig_lat.update_xaxes(title_text="Transaction Index")
        fig_lat.update_layout(height=400, title="End-to-End Transaction Latency on IoT Device")
        st.plotly_chart(fig_lat, width="stretch")

        # Phase breakdown
        st.subheader("Protocol Phase Breakdown (ARM Cortex-M4)")
        phase_data = {
            "PUF Boot": [t.puf_boot_us / 1000 * ARM_SCALE_FACTOR for t in successful],
            "Schnorr Prove": [t.schnorr_prove_us / 1000 * ARM_SCALE_FACTOR for t in successful],
            "Schnorr Verify": [t.schnorr_verify_us / 1000 * ARM_SCALE_FACTOR for t in successful],
            "ECDH + HKDF": [(t.ecdh_us + t.hkdf_us) / 1000 * ARM_SCALE_FACTOR for t in successful],
            "Encrypt": [t.encrypt_us / 1000 * ARM_SCALE_FACTOR for t in successful],
            "Decrypt": [t.decrypt_us / 1000 * ARM_SCALE_FACTOR for t in successful],
            "CB Sig Verify": [t.cb_verify_us / 1000 * ARM_SCALE_FACTOR for t in successful],
            "Transfer Sign": [t.transfer_sign_us / 1000 * ARM_SCALE_FACTOR for t in successful],
            "Transfer Verify": [t.transfer_verify_us / 1000 * ARM_SCALE_FACTOR for t in successful],
            "Pedersen": [(t.pedersen_commit_us + t.pedersen_verify_us) / 1000 * ARM_SCALE_FACTOR for t in successful],
            "BLE Transfer": [t.ble_us / 1000 * ARM_SCALE_FACTOR for t in successful],
        }

        phase_summary = []
        for name, vals in phase_data.items():
            m = statistics.mean(vals)
            s = statistics.stdev(vals) if len(vals) > 1 else 0
            phase_summary.append({
                "Phase": name,
                "IoT Mean (ms)": round(m, 2),
                "Std Dev (ms)": round(s, 2),
                "% of Total": round(m / statistics.mean(arm_ms) * 100, 1) if arm_ms else 0,
            })

        phase_df = pd.DataFrame(phase_summary)

        col_chart, col_table = st.columns([2, 1])
        with col_chart:
            fig_phase = px.bar(
                phase_df, x="IoT Mean (ms)", y="Phase", orientation="h",
                error_x="Std Dev (ms)",
                color="Phase",
                color_discrete_sequence=px.colors.qualitative.Set3,
            )
            fig_phase.update_layout(height=450, showlegend=False,
                                    title="Mean Phase Duration on IoT Device (ms)")
            st.plotly_chart(fig_phase, width="stretch")

        with col_table:
            st.dataframe(phase_df, width="stretch", hide_index=True)

        # Latency scaling
        st.subheader("Latency Scaling with Token Count")
        if result.latency_scaling:
            scale_df = pd.DataFrame(result.latency_scaling)
            fig_scale = go.Figure()
            fig_scale.add_trace(
                go.Scatter(x=scale_df["tokens"], y=scale_df["arm_ms"],
                           name="IoT Latency", mode="lines+markers",
                           line=dict(color="#e74c3c", width=2)),
            )
            fig_scale.add_hline(y=1000, line_dash="dash", line_color="gray",
                                annotation_text="1-sec UX threshold")
            fig_scale.update_xaxes(title_text="Number of Tokens")
            fig_scale.update_yaxes(title_text="IoT Latency (ms)")
            fig_scale.update_layout(height=400, title="Latency vs Token Count (ARM Cortex-M4)")
            st.plotly_chart(fig_scale, width="stretch")

            st.dataframe(
                scale_df[["tokens", "arm_ms", "payload_bytes", "ble_frames", "ram_bytes"]].rename(
                    columns={"arm_ms": "IoT Latency (ms)", "payload_bytes": "BLE Payload (B)",
                             "ble_frames": "BLE Frames", "ram_bytes": "RAM (B)"}
                ),
                width="stretch", hide_index=True,
            )


# ===================================================================
# TAB 4: PUF Reliability
# ===================================================================
with tab4:
    st.subheader("PUF Boot Reliability Across Bit Error Rates")

    if result.puf_reliability:
        puf_df = pd.DataFrame([
            {
                "BER": f"{b:.2f}",
                "Boot Success (%)": d["success_rate"],
                "Avg Bit Errors": round(d["avg_errors"], 1),
                "Max Bit Errors": d["max_errors"],
                "Stable Bits": d["stable_bits"],
            }
            for b, d in sorted(result.puf_reliability.items())
        ])
        st.dataframe(puf_df, width="stretch", hide_index=True)

        bers = sorted(result.puf_reliability.keys())
        avg_e = [result.puf_reliability[b]["avg_errors"] for b in bers]
        max_e = [result.puf_reliability[b]["max_errors"] for b in bers]

        fig_puf = go.Figure()
        fig_puf.add_trace(go.Bar(
            x=[f"{b:.2f}" for b in bers], y=avg_e, name="Avg Errors",
            marker_color="#4C72B0"))
        fig_puf.add_trace(go.Bar(
            x=[f"{b:.2f}" for b in bers], y=max_e, name="Max Errors",
            marker_color="#DD8452"))
        fig_puf.add_hline(y=170, line_dash="dash", line_color="red",
                          annotation_text="BCH correction limit (t=170)")
        fig_puf.update_layout(
            barmode="group", height=400,
            title="PUF Bit Errors vs BER (10 Devices per BER)",
            xaxis_title="Bit Error Rate",
            yaxis_title="Bit Errors",
        )
        st.plotly_chart(fig_puf, width="stretch")

        st.info(
            "BCH ECC with **t=170** can correct up to 170 bit errors in a 2048-bit PUF response. "
            f"Max observed = **{max(max_e)}** errors across all tested BERs."
        )


# ===================================================================
# TAB 5: BLE & Resources
# ===================================================================
with tab5:
    st.subheader("BLE 5.0 Payload Scaling")

    if result.latency_scaling:
        ble_df = pd.DataFrame([
            {
                "Tokens": d["tokens"],
                "Payload (B)": d["payload_bytes"],
                "BLE Frames": d["ble_frames"],
                "RAM (B)": d["ram_bytes"],
            }
            for d in result.latency_scaling
        ])
        st.dataframe(ble_df, width="stretch", hide_index=True)

        fig_ble = make_subplots(specs=[[{"secondary_y": True}]])
        fig_ble.add_trace(
            go.Bar(x=ble_df["Tokens"], y=ble_df["Payload (B)"],
                   name="Payload (bytes)", marker_color="#5975A4"),
            secondary_y=False,
        )
        fig_ble.add_trace(
            go.Scatter(x=ble_df["Tokens"], y=ble_df["BLE Frames"],
                       name="BLE L2CAP Frames", mode="lines+markers",
                       line=dict(color="red", width=2)),
            secondary_y=True,
        )
        fig_ble.update_xaxes(title_text="Number of Tokens")
        fig_ble.update_yaxes(title_text="Payload (bytes)", secondary_y=False)
        fig_ble.update_yaxes(title_text="BLE Frames", secondary_y=True)
        fig_ble.update_layout(height=350, title="BLE Payload & Frames per Transaction")
        st.plotly_chart(fig_ble, width="stretch")

    st.markdown("---")
    st.subheader("RAM & SE050 Usage")

    if result.resource_stress:
        stress_df = pd.DataFrame(result.resource_stress)
        st.dataframe(stress_df, width="stretch", hide_index=True)

    if successful:
        ram_data = [t.ram_bytes for t in successful]
        fig_ram = go.Figure()
        fig_ram.add_trace(go.Scatter(
            x=list(range(1, len(ram_data) + 1)),
            y=[r / 1024 for r in ram_data],
            fill="tozeroy", fillcolor="rgba(46,204,113,0.15)",
            line=dict(color="green", width=1),
            name="Peak RAM",
        ))
        fig_ram.add_hline(y=520, line_dash="dash", line_color="red",
                          annotation_text="ESP32 RAM Budget (520 KB)")
        fig_ram.update_layout(
            height=300, title="Peak RAM per Transaction",
            xaxis_title="Tx Index", yaxis_title="RAM (KB)",
        )
        st.plotly_chart(fig_ram, width="stretch")

        se_data = []
        for dev_id, dev_obj in result.devices.items():
            se_data.append({
                "Device": dev_id,
                "Tokens": dev_obj.token_count(),
                "SE050 (KB)": round(dev_obj.se050_usage_bytes() / 1024, 1),
                "Usage %": round(dev_obj.se050_usage_bytes() / (50 * 1024) * 100, 1),
            })
        se_df = pd.DataFrame(se_data)
        st.dataframe(se_df, width="stretch", hide_index=True)

        fig_se_bar = px.bar(se_df, x="Device", y="Usage %", color="Usage %",
                            color_continuous_scale="RdYlGn_r",
                            title="SE050 Storage Utilization per Device")
        fig_se_bar.add_hline(y=100, line_dash="dash", line_color="red")
        fig_se_bar.update_layout(height=300)
        st.plotly_chart(fig_se_bar, width="stretch")


# ===================================================================
# TAB 6: Crypto Benchmark
# ===================================================================
with tab6:
    st.subheader("Cryptographic Operation Benchmark (ARM Cortex-M4 @ 240 MHz)")

    if result.crypto_bench:
        bench_data = []
        for op, vals in result.crypto_bench.items():
            bench_data.append({
                "Operation": op,
                "IoT Time (µs)": round(vals["arm_us"], 0),
                "IoT Time (ms)": round(vals["arm_us"] / 1000, 2),
            })
        bench_df = pd.DataFrame(bench_data)
        st.dataframe(bench_df, width="stretch", hide_index=True)

        fig_bench = px.bar(
            bench_df, y="Operation", x="IoT Time (µs)",
            orientation="h",
            color="IoT Time (µs)",
            color_continuous_scale="OrRd",
            title="Crypto Operation Time on IoT Device (ARM Cortex-M4)"
        )
        fig_bench.update_layout(height=500, showlegend=False)
        st.plotly_chart(fig_bench, width="stretch")


# ===================================================================
# TAB 7: Raw Data
# ===================================================================
with tab7:
    st.subheader("All Transaction Records")
    tx_records = []
    for t in txs:
        arm_total = t.total_us / 1000 * ARM_SCALE_FACTOR
        tx_records.append({
            "TX ID": t.tx_id[:8],
            "Sender": t.sender_id,
            "Receiver": t.receiver_id,
            "Amount (₹)": t.amount,
            "Tokens": t.n_tokens,
            "Status": t.status.value,
            "Failure": t.failure_reason,
            "IoT Latency (ms)": round(arm_total, 1),
            "RAM (B)": t.ram_bytes,
        })
    tx_df = pd.DataFrame(tx_records)
    st.dataframe(tx_df, width="stretch", hide_index=True)

    # Download JSON
    export_data = {
        "config": {
            "n_devices": result.config.n_devices,
            "n_banks": result.config.n_banks,
            "n_transactions": result.config.n_transactions,
            "tokens_per_device": result.config.tokens_per_device,
            "ber": result.config.ber,
            "ack_drop_prob": result.config.ack_drop_prob,
            "seed": result.config.seed,
        },
        "target_platform": {
            "mcu": "ESP32 (ARM Cortex-M4 @ 240 MHz)",
            "ram": "520 KB SRAM",
            "flash": "4 MB",
            "secure_element": "NXP SE050 (50 KB)",
            "puf": "2048-bit SRAM-PUF with BCH(t=170)",
            "ble": "BLE 5.0 (2 Mbps, MTU 251)",
        },
        "summary": {
            "total": len(txs),
            "successful": len(successful),
            "failed": len(failed),
            "locked": len(locked),
            "success_rate": result.success_rate(),
            "avg_iot_latency_ms": round(
                statistics.mean([t.total_us / 1000 * ARM_SCALE_FACTOR for t in successful]), 1
            ) if successful else 0,
        },
        "failure_breakdown": result.failure_breakdown(),
        "syncs": len(result.syncs),
    }
    st.download_button(
        label="⬇ Download Results (JSON)",
        data=json.dumps(export_data, indent=2),
        file_name="iot_cbdc_simulation_results.json",
        mime="application/json",
    )

# ── Footer ──────────────────────────────────────────────────────
st.markdown("---")
st.caption(
    f"Simulation completed in {elapsed:.1f}s | "
    f"{len(txs)} transactions | {n_devices} IoT devices | {n_banks} banks | "
    f"Target: ARM Cortex-M4 @ 240 MHz (scale factor: {ARM_SCALE_FACTOR}×)"
)
