"""Command line interface.

  python run.py demo        generate fresh sample logs, analyze them, open the dashboard
  python run.py serve       open the dashboard on whatever is already in the database
  python run.py ingest F... analyze your own log files
  python run.py evaluate    measure detection against the simulator's ground truth
  python run.py bench       measure events per second on this machine
  python run.py samples     rewrite the files in samples/
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from . import config, simulator
from .evaluate import score
from .parsers import _syslog
from .pipeline import Pipeline
from .storage import Storage


def _fresh(db: Optional[Path] = None) -> Pipeline:
    storage = Storage(db or config.DB_PATH)
    storage.reset()
    return Pipeline(storage)


def _load_demo(pipeline: Pipeline, seed: int = 7) -> dict:
    lines, truth = simulator.generate(seed=seed)
    started = time.perf_counter()
    for start in range(0, len(lines), 2000):
        pipeline.ingest_lines((src, line) for _, src, line in lines[start:start + 2000])
    seconds = time.perf_counter() - started
    return {"truth": truth, "seconds": seconds, "lines": len(lines)}


def cmd_demo(args) -> int:
    from .web.app import create_app, start_live_feed
    pipeline = _fresh()
    info = _load_demo(pipeline)
    print("Analyzed %d log lines in %.1fs and raised %d alerts." % (
        info["lines"], info["seconds"], pipeline.stats["alerts"]))
    app = create_app(pipeline)
    if not args.no_live:
        start_live_feed(pipeline)
    print("\n  Dashboard: http://%s:%d   (Ctrl+C to stop)\n" % (config.HOST, config.PORT))
    app.run(host=config.HOST, port=config.PORT, debug=False, use_reloader=False)
    return 0


def cmd_serve(args) -> int:
    from .web.app import create_app
    pipeline = Pipeline(Storage(config.DB_PATH))
    print("\n  Dashboard: http://%s:%d   (Ctrl+C to stop)\n" % (config.HOST, config.PORT))
    create_app(pipeline).run(host=config.HOST, port=config.PORT, debug=False,
                             use_reloader=False)
    return 0


def cmd_ingest(args) -> int:
    pipeline = _fresh() if args.reset else Pipeline(Storage(config.DB_PATH))
    if args.year:
        _syslog.set_reference_year(args.year)
    ids = pipeline.ingest_files([Path(p) for p in args.files])
    print(json.dumps(dict(pipeline.stats, new_alerts=len(ids)), indent=2))
    return 0


def cmd_evaluate(args) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = _fresh(Path(tmp) / "eval.db")
        info = _load_demo(pipeline, seed=args.seed)
        result = score(info["truth"], pipeline.storage.alerts(limit=10000))
    print("\nScenario                     Rule      Entity            Detected  Fired at")
    print("-" * 76)
    for row in result["rows"]:
        print("%-28s %-9s %-17s %-9s %s" % (
            row["scenario"][:28], row["rule_id"], row["entity"],
            "yes" if row["detected"] else "MISSED",
            "+%ss into scenario" % row["delay"] if row["detected"] else "-"))
    print("-" * 76)
    print("Expected detections : %d" % result["expected"])
    print("Detected            : %d   (recall %s)" % (result["detected"], result["recall"]))
    print("Unexpected alerts   : %d   (precision %s)" % (
        result["unexpected_alerts"], result["precision"]))
    print("Log lines analyzed  : %d, including %d benign look-alikes built to sit just"
          " under the thresholds" % (info["lines"], len(simulator.LOOKALIKES)))
    print("\nNote: this data is synthetic and written by the same project, so these"
          "\nnumbers prove the pipeline works as designed. They are NOT a claim about"
          "\ndetection rates against real-world attackers.\n")
    for item in result["unexpected"]:
        print("  unexpected:", item)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0 if result["missed"] == 0 and result["unexpected_alerts"] == 0 else 1


def cmd_bench(args) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = _fresh(Path(tmp) / "bench.db")
        info = _load_demo(pipeline)
    rate = info["lines"] / info["seconds"]
    print("%d lines in %.2fs = %d events/second (parse + enrich + %d rules + SQLite),"
          " single process, on this machine." % (
              info["lines"], info["seconds"], rate, len(pipeline.rules) + 1))
    return 0


def cmd_samples(args) -> int:
    lines, truth = simulator.generate(seed=args.seed)
    paths = simulator.write_samples(config.SAMPLES_DIR, lines, truth)
    print("Wrote %d lines across %d files to %s" % (len(lines), len(paths), config.SAMPLES_DIR))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")
    demo = sub.add_parser("demo", help="sample data + dashboard")
    demo.add_argument("--no-live", action="store_true", help="do not stream live events")
    demo.set_defaults(func=cmd_demo)
    sub.add_parser("serve", help="dashboard only").set_defaults(func=cmd_serve)
    ingest = sub.add_parser("ingest", help="analyze log files")
    ingest.add_argument("files", nargs="+")
    ingest.add_argument("--reset", action="store_true", help="clear the database first")
    ingest.add_argument("--year", type=int, help="year to assume for syslog timestamps")
    ingest.set_defaults(func=cmd_ingest)
    evaluate = sub.add_parser("evaluate", help="score detections against ground truth")
    evaluate.add_argument("--seed", type=int, default=7)
    evaluate.add_argument("--json", help="also write the result to this file")
    evaluate.set_defaults(func=cmd_evaluate)
    sub.add_parser("bench", help="throughput on this machine").set_defaults(func=cmd_bench)
    samples = sub.add_parser("samples", help="rewrite samples/")
    samples.add_argument("--seed", type=int, default=7)
    samples.set_defaults(func=cmd_samples)
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
