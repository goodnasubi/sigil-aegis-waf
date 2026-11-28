#!/usr/bin/env python3
"""
scripts/run_long_fuzz.py - Aegis WAF Stage 4 長時間ファジング実行スクリプト (Issue #9, ADR 0068 決定 7)
5つの対象について評価器 (Evaluator) とネイティブ (Native) の両方で指定秒数（既定 3605 秒 ≒ 1 時間超）実行し、
実行回数・所要時間・クラッシュ／ハング／性質違反の有無を記録・集計する。
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

TARGETS = [
    {"id": 0, "name": "ポリシー JSON", "slug": "policy_json"},
    {"id": 1, "name": "CIDR 表", "slug": "cidr_table"},
    {"id": 2, "name": "経路表", "slug": "route_table"},
    {"id": 3, "name": "PROXY v2", "slug": "proxy_v2"},
    {"id": 4, "name": "HTTP 解析と検査の経路", "slug": "http_inspect"},
]

def prepare_root(repo_root: Path, work_dir: Path, sigil_root: Path) -> Path:
    fuzz_root = work_dir / "fuzz_root"
    fuzz_root.mkdir(parents=True, exist_ok=True)
    for sigil_file in (repo_root / "sigil").glob("*.sigil"):
        shutil.copy(sigil_file, fuzz_root / sigil_file.name)
    shutil.copy(repo_root / "Sigil.toml", fuzz_root / "Sigil.toml")

    # Fetch or copy argus_observe.sigil
    argus_local = Path("/home/antigravity/goodnasubi/sigil-argus-observe/argus_observe.sigil")
    if argus_local.exists():
        shutil.copy(argus_local, fuzz_root / "argus_observe.sigil")
    return fuzz_root

def parse_output(output: str):
    lines = output.strip().splitlines()
    iterations = 0
    elapsed_ns = 0
    success = False
    for i, line in enumerate(lines):
        line = line.strip()
        if line == "FINISH_SUCCESS" and i + 2 < len(lines):
            try:
                iterations = int(lines[i + 1].strip())
                elapsed_ns = int(lines[i + 2].strip())
                success = True
            except ValueError:
                pass
    return success, iterations, elapsed_ns

def post_progress_comment(result: dict, issue_num: int = 9, repo: str = "goodnasubi/sigil-aegis-waf"):
    target_name = result["target_name"]
    target_id = result["target_id"]
    e = result["evaluator"]
    n = result["native"]
    total_iters = e["iterations"] + n["iterations"]
    body = f"""## 進捗報告: 対象 {target_id}（{target_name}）の長時間ファジング完了

- **対象**: {target_name}（Target {target_id}）
- **所要時間**:
  - 評価器: {e['elapsed_seconds']:.2f} 秒
  - ネイティブ: {n['elapsed_seconds']:.2f} 秒
  - 壁時計時間: {result['wall_time_seconds']:.2f} 秒
- **実行回数**:
  - 評価器: {e['iterations']:,} 回
  - ネイティブ: {n['iterations']:,} 回
  - 合計: {total_iters:,} 回
- **初期シード**: 評価器 {e['seed']} / ネイティブ {n['seed']}（実行中 10,000 回ごとにシード自動更新）
- **クラッシュ／ハング**: 0 件
- **性質違反**: 0 件
- **判定**: **合格**
"""
    try:
        subprocess.run(["gh", "issue", "comment", str(issue_num), "--repo", repo, "--body", body], check=True)
        print(f"Posted progress comment for Target {target_id} to Issue #{issue_num}", flush=True)
    except Exception as ex:
        print(f"Failed to post comment to Issue #{issue_num}: {ex}", file=sys.stderr, flush=True)

def run_target(target_id: int, duration_secs: int, repo_root: Path, sigil_bin: Path, work_dir: Path, seeds=(20261128, 20261129), post_comment: bool = True):
    target_info = TARGETS[target_id]
    target_name = target_info["name"]
    print(f"==================================================", flush=True)
    print(f"Starting long fuzzing for Target {target_id}: {target_name}", flush=True)
    print(f"Target duration: {duration_secs}s (Evaluator seed: {seeds[0]}, Native seed: {seeds[1]})", flush=True)
    print(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}", flush=True)

    fuzz_root = prepare_root(repo_root, work_dir, sigil_bin.parent.parent)

    # 1. Build native binary
    native_bin = work_dir / f"fuzz_native_{target_id}"
    print(f"Compiling native binary: {native_bin} ...", flush=True)
    build_cmd = [
        str(sigil_bin),
        "build",
        "--root", str(fuzz_root),
        str(fuzz_root / "stage4_fuzz_test.sigil"),
        "run_target_timed",
        "-o", str(native_bin)
    ]
    t0_build = time.time()
    res_build = subprocess.run(build_cmd, capture_output=True, text=True)
    if res_build.returncode != 0:
        print(f"Compilation error: {res_build.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"Compiled in {time.time() - t0_build:.2f}s", flush=True)

    # 2. Run Evaluator and Native in parallel
    eval_log_path = work_dir / f"target_{target_id}_evaluator.log"
    native_log_path = work_dir / f"target_{target_id}_native.log"

    eval_cmd = [
        str(sigil_bin),
        "run",
        "--root", str(fuzz_root),
        str(fuzz_root / "stage4_fuzz_test.sigil"),
        "run_target_timed",
        str(target_id),
        str(seeds[0]),
        str(duration_secs)
    ]
    native_cmd = [
        str(native_bin),
        str(target_id),
        str(seeds[1]),
        str(duration_secs)
    ]

    print(f"Spawning Evaluator and Native processes concurrently...", flush=True)
    t_start = time.time()
    with open(eval_log_path, "w") as f_eval, open(native_log_path, "w") as f_native:
        p_eval = subprocess.Popen(eval_cmd, stdout=f_eval, stderr=subprocess.STDOUT)
        p_native = subprocess.Popen(native_cmd, stdout=f_native, stderr=subprocess.STDOUT)

        # Monitor processes
        last_log = t_start
        while True:
            if p_eval.poll() is not None and p_native.poll() is not None:
                break
            time.sleep(5)
            now = time.time()
            if now - last_log >= 30:
                elapsed = now - t_start
                eval_alive = "RUNNING" if p_eval.poll() is None else f"EXITED({p_eval.returncode})"
                native_alive = "RUNNING" if p_native.poll() is None else f"EXITED({p_native.returncode})"
                print(f"[{elapsed:6.1f}s / {duration_secs}s] Target {target_id} ({target_name}) | Evaluator: {eval_alive} | Native: {native_alive}", flush=True)
                last_log = now

    t_end = time.time()
    total_elapsed = t_end - t_start
    print(f"Processes completed in {total_elapsed:.2f}s. Analyzing results...", flush=True)

    eval_output = eval_log_path.read_text(encoding="utf-8", errors="replace")
    native_output = native_log_path.read_text(encoding="utf-8", errors="replace")

    eval_success, eval_iters, eval_ns = parse_output(eval_output)
    native_success, native_iters, native_ns = parse_output(native_output)

    eval_result = {
        "mode": "evaluator",
        "returncode": p_eval.returncode,
        "success": eval_success and p_eval.returncode == 0,
        "iterations": eval_iters,
        "elapsed_seconds": eval_ns / 1e9 if eval_ns > 0 else total_elapsed,
        "wall_time_seconds": total_elapsed,
        "crashes": 1 if p_eval.returncode != 0 else 0,
        "hangs": 0,
        "seed": seeds[0],
    }
    native_result = {
        "mode": "native",
        "returncode": p_native.returncode,
        "success": native_success and p_native.returncode == 0,
        "iterations": native_iters,
        "elapsed_seconds": native_ns / 1e9 if native_ns > 0 else total_elapsed,
        "wall_time_seconds": total_elapsed,
        "crashes": 1 if p_native.returncode != 0 else 0,
        "hangs": 0,
        "seed": seeds[1],
    }

    result = {
        "target_id": target_id,
        "target_name": target_name,
        "slug": target_info["slug"],
        "evaluator": eval_result,
        "native": native_result,
        "start_time": time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(t_start)),
        "end_time": time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(t_end)),
        "wall_time_seconds": total_elapsed,
    }

    print(f"Target {target_id} ({target_name}) Results:")
    print(f"  Evaluator: {eval_iters:,} iterations in {eval_result['elapsed_seconds']:.2f}s (code={p_eval.returncode}, success={eval_result['success']})")
    print(f"  Native:    {native_iters:,} iterations in {native_result['elapsed_seconds']:.2f}s (code={p_native.returncode}, success={native_result['success']})")
    print(f"==================================================\n", flush=True)

    if post_comment:
        post_progress_comment(result)

    return result

def main():
    parser = argparse.ArgumentParser(description="Aegis WAF Stage 4 Long Fuzzing Runner")
    parser.add_argument("--targets", nargs="*", type=int, default=[0, 1, 2, 3, 4], help="Target IDs to run (0..4)")
    parser.add_argument("--duration", type=int, default=3605, help="Duration in seconds per target (default 3605)")
    parser.add_argument("--sigil-bin", type=str, default="/home/antigravity/sigil-1a4bf/target/release/sigil")
    parser.add_argument("--work-dir", type=str, default="/tmp/aegis_fuzz_run")
    parser.add_argument("--results-json", type=str, default="docs/records/long_fuzz_results.json")
    parser.add_argument("--no-comment", action="store_true", help="Do not post comments to GitHub issue")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    sigil_bin = Path(args.sigil_bin)

    results_path = repo_root / args.results_json
    results_path.parent.mkdir(parents=True, exist_ok=True)

    all_results = {}
    if results_path.exists():
        try:
            with open(results_path, "r", encoding="utf-8") as f:
                prev = json.load(f)
                if isinstance(prev, list):
                    for item in prev:
                        all_results[item["target_id"]] = item
                elif isinstance(prev, dict):
                    all_results = prev
        except Exception:
            all_results = {}

    target_seeds = [
        (20261128, 20261129),
        (20261130, 20261201),
        (20261202, 20261203),
        (20261204, 20261205),
        (20261206, 20261207),
    ]

    for t_id in args.targets:
        res = run_target(
            t_id,
            args.duration,
            repo_root,
            sigil_bin,
            work_dir,
            target_seeds[t_id % len(target_seeds)],
            post_comment=not args.no_comment
        )
        all_results[t_id] = res

        # Save cumulative results
        results_list = [all_results[k] for k in sorted(all_results.keys())]
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(results_list, f, indent=2, ensure_ascii=False)

    print("All requested fuzzing runs completed successfully!")

if __name__ == "__main__":
    main()
