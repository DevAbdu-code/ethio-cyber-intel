"""Repeatable CPU microbenchmark for correlation over synthetic local reports.

This measures candidate generation only (no SQLite writes or network calls).
Generated records are synthetic performance fixtures, never research data.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.ethio_cyber_intel.correlation import correlate_articles


def synthetic_corpus(size: int) -> list[dict]:
    languages = ("en", "am", "om")
    return [{
        "id": index,
        "title": f"Security update vendor group {index % 13} CVE-2026-{10000 + index}",
        "summary": f"Researchers investigated malware family: SampleGroup{index % 7} affecting product: Secure Suite {index % 9}.",
        "content": f"The report describes access controls and service impact in district {index % 11}. Administrators review vendor advisory and patch deployment details.",
        "language": languages[index % len(languages)],
        "published_at": f"2026-11-{(index % 25) + 1:02d}T12:00:00Z",
    } for index in range(size)]


def run(sizes: list[int], repeats: int = 3) -> list[dict]:
    output = []
    for size in sizes:
        articles = synthetic_corpus(size)
        observations = []
        candidate_counts = []
        for _ in range(repeats):
            started = perf_counter()
            candidates = correlate_articles(articles)
            observations.append(perf_counter() - started)
            candidate_counts.append(len(candidates))
        output.append({"articles": size, "pairs": size * (size - 1) // 2,
                       "repeats": repeats, "seconds_each": [round(x, 6) for x in observations],
                       "median_seconds": round(sorted(observations)[len(observations) // 2], 6),
                       "candidate_counts": candidate_counts, "synthetic_fixture": True})
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[40, 100, 300])
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1 or any(size < 2 for size in args.sizes):
        parser.error("repeats must be positive and sizes must be at least 2")
    print(json.dumps(run(args.sizes, args.repeats), indent=2))


if __name__ == "__main__":
    main()
