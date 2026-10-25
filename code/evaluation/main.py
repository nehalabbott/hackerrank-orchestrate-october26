"""Score predictions against labelled answers (e.g. the public sample_output.csv).

    python code/evaluation/main.py --predictions sample_predictions.csv \
        --gold dataset/sample_output.csv

Metrics:
* status accuracy   - deletion_status matches;
* step precision / recall / F1 - steps matched on (phase, operation, state,
  system_id, resource_id, evidence_id);
* field accuracy    - per-field agreement over position-aligned steps;
* sequence accuracy - cases whose full steps_json equals the gold exactly;
* order consistency - over every pair of steps present in both prediction and
  gold for a case, the share whose relative order agrees (ordering quality
  independent of missing steps);
* status confusion  - gold status -> predicted status counts.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def load(path: Path) -> dict[str, tuple[str, list[dict]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {row["case_id"]: (row["deletion_status"], json.loads(row["steps_json"]))
                for row in csv.DictReader(handle)}


def key(step: dict) -> tuple:
    return tuple(step[f] for f in FIELDS)


def score(predicted: dict, gold: dict) -> dict:
    status_ok = tp = fp = fn = exact = 0
    pairs_agree = pairs_total = 0
    confusion: Counter = Counter()
    field_hits: Counter = Counter()
    aligned = 0
    failures = []
    for case_id, (gold_status, gold_steps) in sorted(gold.items()):
        pred_status, pred_steps = predicted.get(case_id, ("MISSING", []))
        status_ok += pred_status == gold_status
        confusion[(gold_status, pred_status)] += 1
        gold_pos = {key(s): i for i, s in enumerate(gold_steps)}
        shared = [gold_pos[key(s)] for s in pred_steps if key(s) in gold_pos]
        for i in range(len(shared)):
            for j in range(i + 1, len(shared)):
                pairs_total += 1
                pairs_agree += shared[i] < shared[j]
        g, p = Counter(map(key, gold_steps)), Counter(map(key, pred_steps))
        hit = sum((g & p).values())
        tp, fp, fn = tp + hit, fp + sum(p.values()) - hit, fn + sum(g.values()) - hit
        for gs, ps in zip(gold_steps, pred_steps):
            aligned += 1
            for f in FIELDS:
                field_hits[f] += gs[f] == ps[f]
        aligned_extra = abs(len(gold_steps) - len(pred_steps))
        aligned += aligned_extra
        same = pred_status == gold_status and [key(s) for s in pred_steps] == [key(s) for s in gold_steps]
        exact += same
        if not same:
            failures.append((case_id, gold_status, pred_status,
                             sorted(set(g) - set(p)), sorted(set(p) - set(g))))
    n = len(gold)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "cases": n,
        "status_accuracy": status_ok / n if n else 0.0,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "field_accuracy": {f: field_hits[f] / aligned if aligned else 0.0 for f in FIELDS},
        "sequence_accuracy": exact / n if n else 0.0,
        "order_consistency": pairs_agree / pairs_total if pairs_total else 1.0,
        "matched_steps": tp, "predicted_steps": tp + fp, "gold_steps": tp + fn,
        "status_confusion": dict(confusion),
        "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", type=Path, default=root / "sample_predictions.csv")
    parser.add_argument("--gold", type=Path, default=root / "dataset" / "sample_output.csv")
    parser.add_argument("--failures", action="store_true", help="print per-case differences")
    args = parser.parse_args(argv)
    result = score(load(args.predictions), load(args.gold))
    print(f"cases: {result['cases']}")
    print(f"status accuracy:   {result['status_accuracy']:.3f}")
    print(f"step precision:    {result['step_precision']:.3f}")
    print(f"step recall:       {result['step_recall']:.3f}")
    print(f"step F1:           {result['step_f1']:.3f}")
    print("field accuracy:    " + ", ".join(f"{k}={v:.3f}" for k, v in result["field_accuracy"].items()))
    print(f"sequence accuracy: {result['sequence_accuracy']:.3f}")
    print(f"order consistency: {result['order_consistency']:.3f}")
    print(f"steps: matched={result['matched_steps']} predicted={result['predicted_steps']} "
          f"gold={result['gold_steps']}")
    print("status confusion (gold -> predicted): " + ", ".join(
        f"{g}->{p}={c}" for (g, p), c in sorted(result["status_confusion"].items())))
    if args.failures:
        for case_id, gs, ps, missing, extra in result["failures"]:
            print(f"\n{case_id}: gold={gs} predicted={ps}")
            for s in missing:
                print("   missing", s)
            for s in extra:
                print("   extra  ", s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
