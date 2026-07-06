#!/usr/bin/env python3
"""Run the bundled CAIRN Security Agent Audit sample."""

from __future__ import annotations

import argparse
import sys
from importlib import resources
from pathlib import Path

import cairn_pilot_from_raw_logs


def bundled_sample_path() -> Path:
    sample = resources.files("cairn_security_agent_audit").joinpath("samples/pentest_trace_sample.jsonl")
    with resources.as_file(sample) as path:
        return Path(path)


def synth_team_traces(out_dir: Path) -> list[Path]:
    """Deterministic synthetic 5-dev fleet day (clearly labeled synthetic).

    Engine-agnostic row shape: any agent that logs tool events as JSONL works
    the same way with cairn-shadow team-report."""
    import json
    import random

    rnd = random.Random(42)
    devs = {"alice": 0.55, "bob": 0.42, "chen": 0.33, "dana": 0.22, "eli": 0.12}
    repos = ["/repo/api", "/repo/web", "/repo/infra"]
    read_pool = [f"src/pkg_{i // 20}/module_{i:03d}.py" for i in range(300)] + ["package-lock.json", "README.md"]
    cmd_pool = ([f"pytest tests/test_module_{i:03d}.py" for i in range(80)]
                + [f"grep -rn TODO src/pkg_{i}" for i in range(15)]
                + ["git status", "git diff HEAD~1", "npm test", "ls -R src/"])
    out_dir.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []
    ts = 1_782_000_000.0
    for dev, rep in devs.items():
        rows = []
        cwd = rnd.choice(repos)
        # stable output per unit of work: repeats are identical unless the
        # world changed (a file edit, a test flip) — that's the honest signal
        outputs: dict[str, str] = {}
        seen: list[tuple[str, dict]] = []

        def fresh_output(tool: str, key: str) -> str:
            if tool == "Read":
                return f"# {key}\n" + "def handler(req):\n    return respond(req)\n" * rnd.randint(60, 380)
            return f"$ {key}\n" + "line of tool output text here\n" * rnd.randint(20, 200)

        for i in range(260):
            ts += rnd.randint(4, 70)
            if seen and rnd.random() < rep:
                tool, tool_input = rnd.choice(seen)          # deliberate re-read
            elif rnd.random() < 0.55:
                path = rnd.choice(read_pool)
                tool, tool_input = "Read", {"file_path": f"{cwd}/{path}"}
                seen.append((tool, tool_input))
            else:
                c = rnd.choice(cmd_pool)
                tool, tool_input = "Bash", {"command": c}
                seen.append((tool, tool_input))
            key = str(sorted(tool_input.items()))
            if key not in outputs:
                outputs[key] = fresh_output(tool, key)
            elif "pytest" in key and rnd.random() < 0.30:    # test result flipped
                outputs[key] = f"{rnd.randint(1, 9)} passed, {rnd.randint(0, 2)} failed in {rnd.random() * 3:.2f}s"
            elif tool == "Read" and rnd.random() < 0.10:     # file was edited between reads
                outputs[key] = outputs[key] + f"\n# edited at {i}\ndef new_branch():\n    pass\n"
            rows.append({
                "source": "synthetic_team_demo", "schema": "cairn_shadow_v0", "ts": ts,
                "session_id": f"{dev}-day", "user_id": dev, "tool_name": tool,
                "tool_input": tool_input, "output": outputs[key], "cwd": cwd,
            })
        p = out_dir / f"{dev}.jsonl"
        with p.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, sort_keys=True) + "\n")
        files.append(p)
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the bundled CAIRN Security Agent Audit demo.")
    parser.add_argument("--out", default="report", help="Report output directory.")
    parser.add_argument("--price-input-per-m", type=float, default=3.0)
    parser.add_argument("--json-only", action="store_true", help="Print full audit JSON to stdout and skip files.")
    parser.add_argument("--html", action="store_true", help="Also write report.html.")
    parser.add_argument(
        "--team",
        action="store_true",
        help="Demo the fleet view: synthetic 5-dev day, per-dev usage and dollars, opens report.html.",
    )
    parser.add_argument("--no-open", action="store_true", help="With --team: do not open the browser.")
    args = parser.parse_args()

    if args.team:
        import cairn_shadow

        out_dir = Path(args.out if args.out != "report" else "team_demo")
        traces = synth_team_traces(out_dir / "traces")
        print(f"synthetic fleet: {len(traces)} devs -> {out_dir / 'traces'} (labeled synthetic; ratios illustrative)\n")
        raise SystemExit(
            cairn_shadow.cmd_team_report(
                [str(p) for p in traces], model="claude-sonnet-4.5",
                price=0.0, cached=None, out=str(out_dir), open_browser=not args.no_open,
            )
        )

    sample = bundled_sample_path()
    argv = [
        "cairn-audit",
        "--input",
        str(sample),
        "--price-input-per-m",
        str(args.price_input_per_m),
    ]
    if args.json_only:
        argv.append("--json-only")
    else:
        argv.extend(["--out", args.out])
        if args.html:
            argv.append("--html")

    sys.argv = argv
    cairn_pilot_from_raw_logs.main()

    if not args.json_only:
        out = Path(args.out)
        print("\nCAIRN sample audit complete.\n")
        print("Written:")
        print(f"  {out / 'summary.json'}")
        print(f"  {out / 'summary.md'}")
        if args.html:
            print(f"  {out / 'report.html'}")
        print(f"  {out / 'normalization_summary.json'}")


if __name__ == "__main__":
    main()
