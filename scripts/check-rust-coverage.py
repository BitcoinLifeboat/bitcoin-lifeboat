#!/usr/bin/env python3
"""Enforce per-crate Rust source line coverage from cargo-llvm-cov JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def usage() -> None:
    print(
        "usage: scripts/check-rust-coverage.py <llvm-cov.json> [threshold]",
        file=sys.stderr,
    )


def relative_to_repo(filename: str, repo_root: Path) -> Path | None:
    path = Path(filename)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(repo_root)
        except ValueError:
            return None
    return path


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        usage()
        return 2

    coverage_path = Path(argv[1])
    threshold = float(argv[2]) if len(argv) == 3 else 80.0
    repo_root = Path(__file__).resolve().parents[1]
    crates_root = repo_root / "crates"

    with coverage_path.open("r", encoding="utf-8") as handle:
        coverage = json.load(handle)

    crate_totals: dict[str, dict[str, int]] = {}
    for crate_dir in sorted(crates_root.iterdir()):
        if (crate_dir / "Cargo.toml").is_file():
            crate_totals[crate_dir.name] = {"count": 0, "covered": 0}

    for data in coverage.get("data", []):
        for file_entry in data.get("files", []):
            relative = relative_to_repo(file_entry.get("filename", ""), repo_root)
            if relative is None:
                continue

            parts = relative.parts
            if len(parts) < 4 or parts[0] != "crates" or parts[2] != "src":
                continue

            crate_name = parts[1]
            if crate_name not in crate_totals or relative.suffix != ".rs":
                continue

            lines = file_entry.get("summary", {}).get("lines", {})
            crate_totals[crate_name]["count"] += int(lines.get("count", 0))
            crate_totals[crate_name]["covered"] += int(lines.get("covered", 0))

    failures: list[str] = []
    for crate_name, totals in crate_totals.items():
        line_count = totals["count"]
        covered = totals["covered"]
        if line_count == 0:
            print(f"crates/{crate_name}: n/a (no coverable source lines)")
            continue

        percent = (covered / line_count * 100.0) if line_count else 0.0
        print(f"crates/{crate_name}: {percent:.2f}% lines ({covered}/{line_count})")
        if percent + 1e-9 < threshold:
            failures.append(
                f"crates/{crate_name}: {percent:.2f}% line coverage is below {threshold:.2f}%"
            )

    if failures:
        print("\nCoverage check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"\nAll core crates meet the {threshold:.2f}% line coverage threshold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
