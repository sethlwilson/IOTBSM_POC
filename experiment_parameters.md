# IOTBSM POC Experiment Input Parameters

Use this experiment set to cover policy effect, sensitivity, and stability with a manageable run count.

## 1) Baseline (3 runs, one per TPM)

- `python main.py --cycles 30 --tpm 1 --seed 42 --beta 5 --delta 0.10 --alpha 0.60 --output ./out/baseline_tpm1.png`
- `python main.py --cycles 30 --tpm 2 --seed 42 --beta 5 --delta 0.10 --alpha 0.60 --output ./out/baseline_tpm2.png`
- `python main.py --cycles 30 --tpm 3 --seed 42 --beta 5 --delta 0.10 --alpha 0.60 --output ./out/baseline_tpm3.png`

## 2) Delta Sensitivity (trust decrement) (9 runs)

For each `tpm in {1,2,3}`, run:
- `--delta 0.05`
- `--delta 0.10`
- `--delta 0.20`

With fixed:
- `--cycles 30 --seed 42 --beta 5 --alpha 0.60`

## 3) Beta Sensitivity (BS regulatory frequency) (9 runs)

For each `tpm in {1,2,3}`, run:
- `--beta 3` (more frequent regulation)
- `--beta 5` (default)
- `--beta 8` (less frequent regulation)

With fixed:
- `--cycles 30 --seed 42 --delta 0.10 --alpha 0.60`

## 4) Alpha Sensitivity (IOT weighting) (9 runs)

For each `tpm in {1,2,3}`, run:
- `--alpha 0.40`
- `--alpha 0.60`
- `--alpha 0.80`

With fixed:
- `--cycles 30 --seed 42 --beta 5 --delta 0.10`

## 5) Stochastic Robustness (15 runs)

Pick one setting from each TPM (typically baseline), then run with seeds:
- `--seed 1,2,3,4,5`

Total:
- `3 TPMs x 5 seeds = 15 runs`

## Minimal Full Campaign

- Baseline: 3
- Sensitivity: 27
- Robustness: 15

Total: `45 runs`

This gives enough coverage to compare IA/SM trends, breach behavior, and trust dynamics across policy model and parameter stress.
