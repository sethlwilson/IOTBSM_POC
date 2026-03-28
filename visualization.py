"""
visualization.py
IOTBSM Simulation Visualization

Generates publication-quality plots of:
  1. IA (Information Availability) and SM (Security Measure) over cycles
  2. Inter-organizational trust evolution (logistic growth)
  3. Breach detection and TPM application timeline
  4. LLM assessment activity
  5. Cross-org fact sharing heatmap
"""

import matplotlib  # pyright: ignore[reportMissingImports]
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # pyright: ignore[reportMissingImports]
import matplotlib.gridspec as gridspec  # pyright: ignore[reportMissingImports]
import matplotlib.patches as mpatches  # pyright: ignore[reportMissingImports]
import numpy as np  # pyright: ignore[reportMissingImports]
from typing import List, Dict
from simulation import CycleMetrics


# ---------------------------------------------------------------------------
# Color palette (defense/intel aesthetic)
# ---------------------------------------------------------------------------
COLORS = {
    "ia":        "#2ecc71",   # green — information availability
    "sm":        "#e74c3c",   # red — security measure (breaches)
    "Agency_A":  "#3498db",   # blue
    "Agency_B":  "#9b59b6",   # purple
    "Agency_C":  "#f39c12",   # amber
    "neutral":   "#95a5a6",
    "breach":    "#c0392b",
    "tpm":       "#e67e22",
    "llm":       "#1abc9c",
    "bg":        "#1a1a2e",
    "panel":     "#16213e",
    "text":      "#eaeaea",
    "grid":      "#2d3561",
}

plt.rcParams.update({
    "figure.facecolor":  COLORS["bg"],
    "axes.facecolor":    COLORS["panel"],
    "axes.edgecolor":    COLORS["grid"],
    "axes.labelcolor":   COLORS["text"],
    "text.color":        COLORS["text"],
    "xtick.color":       COLORS["text"],
    "ytick.color":       COLORS["text"],
    "grid.color":        COLORS["grid"],
    "grid.linewidth":    0.5,
    "font.family":       "monospace",
    "legend.facecolor":  COLORS["panel"],
    "legend.edgecolor":  COLORS["grid"],
})


# ---------------------------------------------------------------------------
# Main Dashboard
# ---------------------------------------------------------------------------
def generate_dashboard(metrics: List[CycleMetrics],
                       io_trust_history: Dict[str, List[float]],
                       output_path: str = "iotbsm_dashboard.png"):
    """
    Generate the full IOTBSM simulation dashboard.
    
    Layout:
      Row 1: IA/SM over time (main metric) | Inter-org trust evolution
      Row 2: Breach & TPM timeline         | LLM activity & cross-org sharing
      Row 3: Summary statistics panel
    """
    fig = plt.figure(figsize=(18, 14), facecolor=COLORS["bg"])
    fig.suptitle(
        "IOTBSM — Classified Threat Intelligence Sharing Simulation\n"
        "Inter-Organizational Trust-Based Security Model (Hexmoor, Wilson & Bhattaram, 2006)",
        fontsize=13, color=COLORS["text"], fontweight="bold", y=0.98
    )

    gs = gridspec.GridSpec(3, 2, figure=fig,
                           hspace=0.42, wspace=0.32,
                           top=0.93, bottom=0.07,
                           left=0.07, right=0.96)

    ax1 = fig.add_subplot(gs[0, 0])  # IA/SM
    ax2 = fig.add_subplot(gs[0, 1])  # Inter-org trust
    ax3 = fig.add_subplot(gs[1, 0])  # Breaches & TPM
    ax4 = fig.add_subplot(gs[1, 1])  # LLM + cross-org
    ax5 = fig.add_subplot(gs[2, :])  # Summary stats

    cycles = [m.cycle for m in metrics]

    _plot_ia_sm(ax1, cycles, metrics)
    _plot_io_trust(ax2, cycles, io_trust_history)
    _plot_breaches_tpm(ax3, cycles, metrics)
    _plot_llm_crossorg(ax4, cycles, metrics)
    _plot_summary_table(ax5, metrics, io_trust_history)

    plt.savefig(output_path, dpi=150, bbox_inches="tight",
                facecolor=COLORS["bg"])
    plt.close()
    print(f"  Dashboard saved → {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Plot 1: Information Availability & Security Measure
# ---------------------------------------------------------------------------
def _plot_ia_sm(ax, cycles, metrics: List[CycleMetrics]):
    """Primary IOTBSM metrics: %IA and %SM over cycles."""
    pct_ia = [m.pct_ia for m in metrics]
    pct_sm = [m.pct_sm for m in metrics]

    ax.plot(cycles, pct_ia, color=COLORS["ia"], linewidth=2.5,
            label="% Information Availability (IA)", marker="o", markersize=3)
    ax.plot(cycles, pct_sm, color=COLORS["sm"], linewidth=2.5,
            label="% Security Measure / Breaches (SM)", marker="s", markersize=3)

    # Shade the area between IA and SM
    ax.fill_between(cycles, pct_ia, pct_sm,
                    where=[ia > sm for ia, sm in zip(pct_ia, pct_sm)],
                    alpha=0.12, color=COLORS["ia"], label="IA > SM (secure)")
    ax.fill_between(cycles, pct_ia, pct_sm,
                    where=[sm >= ia for ia, sm in zip(pct_ia, pct_sm)],
                    alpha=0.12, color=COLORS["sm"], label="SM ≥ IA (risk)")

    # Target lines
    ax.axhline(100, color=COLORS["ia"], linestyle="--", alpha=0.3,
               linewidth=1, label="Ideal IA = 100%")
    ax.axhline(0, color=COLORS["sm"], linestyle="--", alpha=0.3,
               linewidth=1, label="Ideal SM = 0%")

    ax.set_title("Information Availability (IA) vs Security Measure (SM)",
                 color=COLORS["text"], fontsize=10, pad=8)
    ax.set_xlabel("Simulation Cycle", fontsize=9)
    ax.set_ylabel("Percentage (%)", fontsize=9)
    ax.set_ylim(-5, 115)
    ax.legend(fontsize=7, loc="center right")
    ax.grid(True, alpha=0.4)

    # Annotate IA saturation if achieved
    for i, m in enumerate(metrics):
        if m.pct_ia >= 95 and m.pct_sm <= 5:
            ax.annotate(f"Near-Ideal\nCycle {m.cycle}",
                        xy=(m.cycle, m.pct_ia),
                        xytext=(m.cycle + 1.5, m.pct_ia - 15),
                        color=COLORS["ia"], fontsize=7,
                        arrowprops=dict(arrowstyle="->",
                                        color=COLORS["ia"], lw=1))
            break


# ---------------------------------------------------------------------------
# Plot 2: Inter-organizational Trust Evolution (Logistic Growth)
# ---------------------------------------------------------------------------
def _plot_io_trust(ax, cycles, io_trust_history: Dict[str, List[float]]):
    """Show logistic growth of inter-organizational trust (Equation 5)."""
    agency_colors = {
        "Agency_A": COLORS["Agency_A"],
        "Agency_B": COLORS["Agency_B"],
        "Agency_C": COLORS["Agency_C"],
    }

    line_styles = ["-", "--", ":", "-."]
    ls_idx = 0

    for pair, trust_vals in sorted(io_trust_history.items()):
        if len(trust_vals) < len(cycles):
            trust_vals = trust_vals + [trust_vals[-1]] * (len(cycles) - len(trust_vals))

        # Color by the source agency
        source_agency = pair.split("->")[0]
        color = agency_colors.get(source_agency, COLORS["neutral"])
        ls = line_styles[ls_idx % len(line_styles)]
        ls_idx += 1

        ax.plot(cycles[:len(trust_vals)], trust_vals,
                color=color, linewidth=1.8,
                linestyle=ls, label=pair, alpha=0.85)

    ax.axhline(0.5, color=COLORS["neutral"], linestyle=":",
               alpha=0.4, linewidth=1, label="Trust threshold (0.5)")

    ax.set_title("Inter-Organizational Trust Evolution\n(Logistic Growth, Eq. 5 & 6)",
                 color=COLORS["text"], fontsize=10, pad=8)
    ax.set_xlabel("Simulation Cycle", fontsize=9)
    ax.set_ylabel("Trust Value τ(o_m, o_n)", fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=7, loc="lower right")
    ax.grid(True, alpha=0.4)


# ---------------------------------------------------------------------------
# Plot 3: Breach Detection & TPM Applications
# ---------------------------------------------------------------------------
def _plot_breaches_tpm(ax, cycles, metrics: List[CycleMetrics]):
    """Timeline of security breaches detected and TPM applications."""
    breaches = [m.breaches_detected for m in metrics]
    tpm_apps = [m.tpm_applications for m in metrics]
    unintended = [m.unintended_receivers for m in metrics]

    ax2 = ax.twinx()

    bars = ax.bar(cycles, breaches, color=COLORS["breach"],
                  alpha=0.7, label="Breaches Detected", width=0.6)
    ax.bar(cycles, tpm_apps, color=COLORS["tpm"],
           alpha=0.6, label="TPM Applications", width=0.4)

    ax2.plot(cycles, unintended, color="#ff6b6b", linewidth=1.5,
             linestyle="--", marker="x", markersize=4,
             label="Unintended Receivers", alpha=0.8)

    ax.set_title("Security Breaches & Trust Policy Model Applications",
                 color=COLORS["text"], fontsize=10, pad=8)
    ax.set_xlabel("Simulation Cycle", fontsize=9)
    ax.set_ylabel("Count (Breaches / TPM)", fontsize=9)
    ax2.set_ylabel("Unintended Receivers", fontsize=9,
                   color="#ff6b6b")
    ax2.tick_params(axis='y', labelcolor="#ff6b6b")

    lines1, labels1 = ax.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax.legend(lines1 + lines2, labels1 + labels2,
              fontsize=7, loc="upper right")
    ax.grid(True, alpha=0.3, axis='y')


# ---------------------------------------------------------------------------
# Plot 4: LLM Activity & Cross-Org Sharing
# ---------------------------------------------------------------------------
def _plot_llm_crossorg(ax, cycles, metrics: List[CycleMetrics]):
    """LLM assessments, recommendations, and cross-org fact sharing."""
    assessments = [m.llm_assessments for m in metrics]
    recommended = [m.llm_share_recommended for m in metrics]
    crossed = [m.facts_crossed_boundary for m in metrics]

    width = 0.3
    x = np.array(cycles)

    ax.bar(x - width, assessments, width=width,
           color=COLORS["llm"], alpha=0.7, label="LLM Assessments")
    ax.bar(x, recommended, width=width,
           color="#27ae60", alpha=0.7, label="LLM: Share Recommended")
    ax.bar(x + width, crossed, width=width,
           color=COLORS["Agency_A"], alpha=0.7, label="Facts Crossed Org Boundary")

    # Acceptance rate line
    acceptance = [r / a * 100 if a > 0 else 0
                  for a, r in zip(assessments, recommended)]
    ax2 = ax.twinx()
    ax2.plot(cycles, acceptance, color="#f1c40f", linewidth=1.5,
             linestyle="-.", marker="^", markersize=4,
             label="LLM Accept Rate (%)", alpha=0.85)
    ax2.set_ylabel("LLM Accept Rate (%)", fontsize=9, color="#f1c40f")
    ax2.tick_params(axis='y', labelcolor="#f1c40f")
    ax2.set_ylim(0, 110)

    ax.set_title("LLM Semantic Assessment Activity & Cross-Org Sharing",
                 color=COLORS["text"], fontsize=10, pad=8)
    ax.set_xlabel("Simulation Cycle", fontsize=9)
    ax.set_ylabel("Count", fontsize=9)

    lines1, labels1 = ax.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax.legend(lines1 + lines2, labels1 + labels2,
              fontsize=7, loc="upper left")
    ax.grid(True, alpha=0.3, axis='y')


# ---------------------------------------------------------------------------
# Plot 5: Summary Statistics Panel
# ---------------------------------------------------------------------------
def _plot_summary_table(ax, metrics: List[CycleMetrics],
                        io_trust_history: Dict[str, List[float]]):
    """Text summary panel with key statistics."""
    ax.axis('off')

    final = metrics[-1]
    total_breaches = sum(m.breaches_detected for m in metrics)
    total_crossed = sum(m.facts_crossed_boundary for m in metrics)
    total_llm = sum(m.llm_assessments for m in metrics)
    total_recommended = sum(m.llm_share_recommended for m in metrics)
    avg_ia = np.mean([m.pct_ia for m in metrics])
    avg_sm = np.mean([m.pct_sm for m in metrics])
    peak_ia = max(m.pct_ia for m in metrics)
    min_sm = min(m.pct_sm for m in metrics)

    # Final IOT values
    iot_summary = []
    for pair, vals in sorted(io_trust_history.items()):
        if vals:
            iot_summary.append(f"{pair}: {vals[-1]:.3f}")

    col1 = [
        ["Metric", "Value"],
        ["Final % IA",          f"{final.pct_ia:.1f}%"],
        ["Final % SM",          f"{final.pct_sm:.1f}%"],
        ["Average % IA",        f"{avg_ia:.1f}%"],
        ["Average % SM",        f"{avg_sm:.1f}%"],
        ["Peak % IA",           f"{peak_ia:.1f}%"],
        ["Min % SM",            f"{min_sm:.1f}%"],
    ]

    col2 = [
        ["Security Events", "Count"],
        ["Total Breaches",       str(total_breaches)],
        ["TPM Applications",     str(sum(m.tpm_applications for m in metrics))],
        ["Facts Crossed Orgs",   str(total_crossed)],
        ["LLM Assessments",      str(total_llm)],
        ["LLM Share Recs",       str(total_recommended)],
        ["LLM Accept Rate",      f"{total_recommended/max(total_llm,1)*100:.1f}%"],
    ]

    col3 = [["Inter-Org Trust (Final)", "τ"]] + \
           [[p.split(":")[0], p.split(":")[1].strip()]
            for p in iot_summary]

    def draw_table(ax, data, x_offset, width=0.28):
        y_positions = np.linspace(0.92, 0.05, len(data))
        for i, (label, val) in enumerate(data):
            y = y_positions[i]
            is_header = i == 0
            weight = "bold" if is_header else "normal"
            color_l = COLORS["llm"] if is_header else COLORS["text"]
            color_v = COLORS["ia"] if (not is_header and "IA" in label) else \
                      COLORS["sm"] if (not is_header and "SM" in label or
                                       "Breach" in label) else \
                      COLORS["llm"] if (not is_header and "LLM" in label) else \
                      COLORS["text"]
            ax.text(x_offset, y, label, transform=ax.transAxes,
                    fontsize=9, color=color_l, fontweight=weight,
                    ha="left", va="center", family="monospace")
            ax.text(x_offset + width, y, val, transform=ax.transAxes,
                    fontsize=9, color=color_v, fontweight=weight,
                    ha="right", va="center", family="monospace")

    draw_table(ax, col1, 0.02)
    draw_table(ax, col2, 0.38)
    draw_table(ax, col3, 0.70)

    # Dividers
    for x in [0.36, 0.68]:
        line = plt.Line2D([x, x], [0.0, 1.0],
                          color=COLORS["grid"], linewidth=1,
                          transform=ax.transAxes)
        ax.add_line(line)

    ax.set_title(
        "Simulation Summary — IOTBSM POC | "
        "Based on Hexmoor, Wilson & Bhattaram (2006) KER 21(2):127-161",
        color=COLORS["neutral"], fontsize=8, pad=6)
