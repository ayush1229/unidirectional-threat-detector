"""
calibrate_external_thresholds.py — External Benchmark Threshold Optimization Tool.

Sweeps detection thresholds across external/real evaluation predictions to determine
the optimal operational thresholds subject to target False Positive Rate constraints:
  - Strict Operational Gate : Benign FPR <= 1.0%
  - High-Confidence Gate    : Benign FPR <= 0.1%
  - Unconstrained Peak F1   : Maximum F1 operating point

Evaluates on predictions exported by agent2_detection_product evaluation suite.
"""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc

ROOT = Path(__file__).resolve().parent.parent


def evaluate_threshold_operating_point(scores, targets, is_benign, threshold):
    preds = (scores >= threshold).astype(int)
    tp = int(((preds == 1) & (targets == 1)).sum())
    fp = int(((preds == 1) & (targets == 0)).sum())
    fn = int(((preds == 0) & (targets == 1)).sum())
    tn = int(((preds == 0) & (targets == 0)).sum())
    
    benign_total = int(is_benign.sum())
    benign_fp = int(((preds == 1) & is_benign).sum())
    benign_fpr = benign_fp / max(benign_total, 1)

    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * tp / max(2 * tp + fp + fn, 1)
    specificity = tn / max(tn + fp, 1)
    balanced_acc = 0.5 * (recall + specificity)
    
    denom = np.sqrt(float((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    mcc = float((tp * tn - fp * fn) / denom) if denom > 0 else 0.0

    return {
        "threshold": float(threshold),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "benign_fp": benign_fp, "benign_total": benign_total,
        "benign_fpr": round(float(benign_fpr), 6),
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "f1": round(float(f1), 6),
        "specificity": round(float(specificity), 6),
        "balanced_accuracy": round(float(balanced_acc), 6),
        "mcc": round(float(mcc), 6)
    }


def sweep_thresholds(scores, targets, is_benign, n_steps=500):
    unique_scores = np.unique(scores)
    if len(unique_scores) > n_steps:
        percentiles = np.linspace(0, 100, n_steps)
        thresholds = np.unique(np.percentile(unique_scores, percentiles))
    else:
        thresholds = unique_scores
    
    thresholds = sorted(set(thresholds.tolist()) | {0.0, 0.5, 0.9, 0.95, 0.99, 1.0})
    rows = []
    for tau in thresholds:
        rows.append(evaluate_threshold_operating_point(scores, targets, is_benign, tau))
    df = pd.DataFrame(rows)
    return df


def find_optimal_gates(sweep_df: pd.DataFrame):
    best_f1_idx = sweep_df["f1"].idxmax()
    best_f1 = sweep_df.iloc[best_f1_idx].to_dict()

    under_1pct = sweep_df[sweep_df["benign_fpr"] <= 0.01]
    if not under_1pct.empty:
        best_1pct_idx = under_1pct["f1"].idxmax()
        gate_1pct = under_1pct.loc[best_1pct_idx].to_dict()
    else:
        gate_1pct = None

    under_01pct = sweep_df[sweep_df["benign_fpr"] <= 0.001]
    if not under_01pct.empty:
        best_01pct_idx = under_01pct["f1"].idxmax()
        gate_01pct = under_01pct.loc[best_01pct_idx].to_dict()
    else:
        gate_01pct = None

    return {
        "unconstrained_peak_f1": best_f1,
        "gate_benign_fpr_under_1pct": gate_1pct,
        "gate_benign_fpr_under_01pct": gate_01pct
    }


def calibrate_predictions(predictions_path: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Reading predictions from {predictions_path}...", flush=True)

    if str(predictions_path).endswith(".gz"):
        with gzip.open(predictions_path, "rt", encoding="utf-8") as f:
            df = pd.read_csv(f)
    else:
        df = pd.read_csv(predictions_path)

    print(f"Loaded {len(df):,} prediction rows. Columns: {list(df.columns)}", flush=True)

    label_col = "label" if "label" in df.columns else "Label"
    is_benign = df[label_col].astype(str).str.upper().str.contains("BENIGN").to_numpy()
    is_ddos = df[label_col].astype(str).str.upper().str.contains("DDOS").to_numpy()
    is_scan = df[label_col].astype(str).str.upper().str.contains("PORT").to_numpy()
    is_any_attack = ~is_benign

    summary = {
        "total_rows_evaluated": len(df),
        "benign_rows": int(is_benign.sum()),
        "attack_rows": int(is_any_attack.sum()),
        "heads": {}
    }

    # Analyze DDoS Head if present
    ddos_col = next((c for c in df.columns if "ddos" in c.lower() and ("prob" in c.lower() or "score" in c.lower() or "pred" in c.lower())), None)
    if not ddos_col:
        ddos_col = next((c for c in df.columns if "ddos" in c.lower()), None)

    if ddos_col:
        print(f"\nCalibrating DDoS head on column '{ddos_col}'...", flush=True)
        scores = df[ddos_col].to_numpy(dtype=float)
        sweep = sweep_thresholds(scores, is_ddos.astype(int), is_benign)
        sweep.to_csv(output_dir / "ddos_threshold_sweep.csv", index=False)
        gates = find_optimal_gates(sweep)
        summary["heads"]["DDoS"] = {
            "score_column": ddos_col,
            "roc_auc": round(float(roc_auc_score(is_ddos, scores)), 6) if len(set(is_ddos)) > 1 else 1.0,
            "gates": gates
        }
        print(f"  Peak F1: {gates['unconstrained_peak_f1']['f1']:.4f} @ tau={gates['unconstrained_peak_f1']['threshold']:.4f} (Benign FPR={gates['unconstrained_peak_f1']['benign_fpr']*100:.2f}%)")
        if gates['gate_benign_fpr_under_1pct']:
            g1 = gates['gate_benign_fpr_under_1pct']
            print(f"  FPR <= 1% Gate: F1={g1['f1']:.4f}, Recall={g1['recall']*100:.2f}%, Precision={g1['precision']*100:.2f}% @ tau={g1['threshold']:.4f}")

    # Analyze PortScan Head if present
    scan_col = next((c for c in df.columns if ("port" in c.lower() or "scan" in c.lower()) and ("prob" in c.lower() or "score" in c.lower() or "pred" in c.lower())), None)
    if not scan_col:
        scan_col = next((c for c in df.columns if "port" in c.lower() or "scan" in c.lower()), None)

    if scan_col:
        print(f"\nCalibrating PortScan head on column '{scan_col}'...", flush=True)
        scores = df[scan_col].to_numpy(dtype=float)
        sweep = sweep_thresholds(scores, is_scan.astype(int), is_benign)
        sweep.to_csv(output_dir / "portscan_threshold_sweep.csv", index=False)
        gates = find_optimal_gates(sweep)
        summary["heads"]["PORT_SCAN"] = {
            "score_column": scan_col,
            "roc_auc": round(float(roc_auc_score(is_scan, scores)), 6) if len(set(is_scan)) > 1 else 1.0,
            "gates": gates
        }
        print(f"  Peak F1: {gates['unconstrained_peak_f1']['f1']:.4f} @ tau={gates['unconstrained_peak_f1']['threshold']:.4f} (Benign FPR={gates['unconstrained_peak_f1']['benign_fpr']*100:.2f}%)")
        if gates['gate_benign_fpr_under_1pct']:
            g1 = gates['gate_benign_fpr_under_1pct']
            print(f"  FPR <= 1% Gate: F1={g1['f1']:.4f}, Recall={g1['recall']*100:.2f}%, Precision={g1['precision']*100:.2f}% @ tau={g1['threshold']:.4f}")

    out_summary = output_dir / "external_calibration_summary.json"
    out_summary.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"\nExternal calibration complete! Summary saved to {out_summary}", flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path,
                        default=ROOT / "artifacts/pipeline/2.0.0-synthetic-pcap-final/cicids/predictions.csv.gz")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "artifacts/experiments/external_calibration")
    args = parser.parse_args()
    calibrate_predictions(args.predictions, args.output)


if __name__ == "__main__":
    main()
