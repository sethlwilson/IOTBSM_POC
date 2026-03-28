"""
main.py
IOTBSM Proof of Concept — Entry Point

Classified Threat Intelligence Sharing Simulation
Based on the Inter-Organizational Trust-Based Security Model (IOTBSM)

Citation:
  Hexmoor, H., Wilson, S., & Bhattaram, S. (2006).
  A theoretical inter-organizational trust-based security model.
  The Knowledge Engineering Review, 21(2), 127-161.
  https://doi.org/10.1017/S0269888906000932

Usage:
  python main.py [--cycles N] [--tpm {1,2,3}] [--seed N] [--beta N]
"""

import argparse
import sys
import os

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simulation import IOTBSMSimulation
from visualization import generate_dashboard
from trust_policy import TPMType


def parse_args():
    parser = argparse.ArgumentParser(
        description="IOTBSM Classified Threat Intel Sharing Simulation"
    )
    parser.add_argument("--cycles", type=int, default=30,
                        help="Number of simulation cycles (default: 30)")
    parser.add_argument("--tpm", type=int, default=1, choices=[1, 2, 3],
                        help="Trust Policy Model: 1=Proportional, "
                             "2=Uniform, 3=Initiator-Direct (default: 1)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    parser.add_argument("--beta", type=int, default=5,
                        help="BS regulatory process rate β (default: 5)")
    parser.add_argument("--delta", type=float, default=0.1,
                        help="Trust decrement factor δ (default: 0.1)")
    parser.add_argument("--alpha", type=float, default=0.6,
                        help="IOT weight α in Eq. 7 (default: 0.6)")
    parser.add_argument("--output", type=str,
                        default="./iotbsm_dashboard.png",
                        help="Output path for dashboard image")
    return parser.parse_args()


def main():
    args = parse_args()

    tpm_map = {
        1: TPMType.TPM1,
        2: TPMType.TPM2,
        3: TPMType.TPM3,
    }
    tpm_type = tpm_map[args.tpm]

    print("\n" + "="*60)
    print("  IOTBSM — Inter-Organizational Trust-Based Security Model")
    print("  Proof of Concept: Classified Threat Intelligence Sharing")
    print("="*60)
    print(f"  Parameters:")
    print(f"    Cycles:  {args.cycles}")
    print(f"    TPM:     {tpm_type.value}")
    print(f"    β (BS regulatory rate): {args.beta}")
    print(f"    δ (trust decrement):     {args.delta}")
    print(f"    α (IOT weight):          {args.alpha}")
    print(f"    Seed:    {args.seed}")

    # Run simulation
    sim = IOTBSMSimulation(
        num_cycles=args.cycles,
        bs_regulatory_rate=args.beta,
        tpm_type=tpm_type,
        decrement_factor=args.delta,
        alpha=args.alpha,
        seed=args.seed,
    )

    metrics = sim.run()
    io_trust_history = sim.get_io_trust_history()

    # Generate dashboard
    print("\n  Generating visualization dashboard...")
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    output_path = generate_dashboard(
        metrics, io_trust_history, output_path=args.output)

    # Print event log summary
    breaches = [e for e in sim.event_log if e["event"] == "BREACH_DETECTED"]
    shares = [e for e in sim.event_log if e["event"] == "INTER_ORG_SHARE"]

    print(f"\n  Event Log Summary:")
    print(f"    Inter-org shares:    {len(shares)}")
    print(f"    Breach events:       {len(breaches)}")
    if breaches:
        print(f"\n  Sample breach events:")
        for b in breaches[:3]:
            print(f"    Cycle {b['cycle']:2d}: Fact {b['fact_id']} → "
                  f"Unintended: {b['unintended_receiver']} | "
                  f"TPM: {b['tpm']}")

    print(f"\n  Dashboard: {output_path}")
    print("  Done.\n")

    return metrics, sim


if __name__ == "__main__":
    main()
