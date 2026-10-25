"""Ghost Data Still Exists - deletion audit agent.

Usage:
    python code/main.py                      # audit dataset/deletion_requests.csv -> output.csv
    python code/main.py --sample             # audit the sample requests -> sample_predictions.csv
    python code/main.py --output path.csv    # choose the output path
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from data_loader import DEFAULT_DATASET_DIR, REPO_ROOT, load_dataset  # noqa: E402
from engine import DeletionEngine  # noqa: E402
from identity import _natural_key  # noqa: E402
from planner import serialize_steps, validate_steps  # noqa: E402


def run(dataset_dir: Path, table: str, output: Path, verbose: bool = False) -> list:
    dataset = load_dataset(dataset_dir)
    if dataset.issues:
        print(f"warning: {len(dataset.issues)} dataset issues", file=sys.stderr)
    engine = DeletionEngine(dataset)
    for problem in engine.index.issues + engine.index.unsupported:
        print(f"evidence: {problem}", file=sys.stderr)

    results = []
    for request in sorted(dataset[table].rows, key=lambda r: _natural_key(r["case_id"])):
        result = engine.decide(request)
        validate_steps(result.deletion_status, result.steps)
        results.append(result)
        if verbose:
            print(result.case_id, result.deletion_status, len(result.steps), result.user_id)
            for note in result.notes:
                print("   ", note)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for result in results:
            writer.writerow([result.case_id, result.deletion_status, serialize_steps(result.steps)])
    print(f"wrote {len(results)} rows to {output}")
    weak = [r for r in results if r.deletion_status == "COMPLETE" and r.unverified]
    if weak:
        print(f"note: {len(weak)} COMPLETE cases rest partly or wholly on missing evidence "
              f"(no contrary evidence, but not every final state is proven):", file=sys.stderr)
        for r in weak:
            print(f"  {r.case_id}: {'; '.join(r.unverified)}", file=sys.stderr)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--sample", action="store_true", help="audit sample requests instead")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    table = "sample_requests" if args.sample else "requests"
    default = REPO_ROOT / ("sample_predictions.csv" if args.sample else "output.csv")
    run(args.dataset, table, args.output or default, args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
