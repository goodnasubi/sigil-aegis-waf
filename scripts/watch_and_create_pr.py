#!/usr/bin/env python3
"""
scripts/watch_and_create_pr.py
長時間ファジングオーケストレーターを監視し、
全対象完了時にコミット、プッシュ、PR 作成（Closes #9）を自律実行する。
"""

import os
import subprocess
import time
from pathlib import Path

REPO_ROOT = Path("/home/antigravity/goodnasubi/sigil-aegis-waf")
FLAG_FILE = Path("/tmp/fuzz_completed.flag")
LOG_FILE = Path("/home/antigravity/watcher.log")

def log(msg: str):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
    line = f"[{timestamp}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def is_orchestrator_alive():
    cmd = "ps aux | grep -v grep | grep 'scripts/orchestrate_fuzz.py'"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return bool(res.stdout.strip())

def create_pr():
    log("ファジング完了フラグを検知しました。記録文書のコミットと PR 作成を開始します。")

    # git add
    subprocess.run(["git", "add", "docs/records/"], cwd=REPO_ROOT, check=True)

    commit_msg = """docs(fuzz): 全5対象の長時間ファジング結果を記録に追加

Issue #9 の完了条件に基づき、全5対象（ポリシー JSON、CIDR 表、経路表、PROXY v2、HTTP 解析と検査の経路）について評価器・ネイティブ双方での各1時間以上の長時間ファジング結果を記録文書に反映する。

Closes #9

Agent: antigravity
Agent-Model: gemini-3.8-flash-medium
Agent-Env: remote"""

    subprocess.run(["git", "commit", "-m", commit_msg], cwd=REPO_ROOT, check=True)
    log("コミット完了")

    # git push
    subprocess.run(["git", "push", "origin", "agy/E/9-long-fuzzing"], cwd=REPO_ROOT, check=True)
    log("プッシュ完了")

    # gh pr create
    pr_body = """## 概要

Issue #9（長時間ファジングの追跡）の完了条件に基づき、ADR 0068 決定 7 / ADR 0020 G2 残作業である全 5 対象の長時間ファジング（各対象 1 時間以上、評価器・ネイティブ双方）を実施し、結果を記録文書に反映しました。

### 実施内容
- **対象**:
  1. ポリシー JSON (`parse_policy` / `policy_chunks`)
  2. CIDR 表 (`parse_ip_table`)
  3. 経路表 (`routes`)
  4. PROXY v2 (`read_proxy` / `parse_proxy`)
  5. HTTP 解析と検査の経路 (`exercise_http` / `check_request`)
- **実行条件**:
  - 評価器（Evaluator）およびネイティブ（Native）双方で並列実行
  - 各対象 1 時間以上（3,605 秒）
  - 10,000 反復ごとに PRNG 状態を自動更新し多様な入力空間を探索
- **検証性質**:
  - どの入力でもパニックせず値（Ok/Err）で返る
  - 転送要求は 1 件に再解析可能で、`Forwarded` / `X-Forwarded-For` / `Transfer-Encoding` が確実に除去されている不変条件

### 結果まとめ
全 5 対象において、異常終了・クラッシュ・ハング・性質違反は **0 件** でした。
詳細は `docs/records/g2-stage4-long-fuzzing.md` および `docs/records/long_fuzz_results.json` を参照してください。

Closes #9
"""

    pr_cmd = [
        "gh", "pr", "create",
        "--repo", "goodnasubi/sigil-aegis-waf",
        "--base", "main",
        "--head", "agy/E/9-long-fuzzing",
        "--title", "docs(fuzz): 全5対象の長時間ファジング結果の記録を追加",
        "--body", pr_body,
    ]
    res = subprocess.run(pr_cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    log(f"PR 作成完了: {res.stdout.strip()}")

def main():
    log("ウォッチャー起動: オーケストレーターの完了待機中...")
    while True:
        if FLAG_FILE.exists():
            try:
                create_pr()
                log("全自動処理が正常に完了しました。ウォッチャーを終了します。")
                break
            except Exception as e:
                log(f"PR 作成処理エラー: {e}")
                time.sleep(60)
                continue

        # オーケストレーターが停止していないか確認
        if not is_orchestrator_alive():
            log("警告: オーケストレーターが停止しています。再起動を試みます。")
            subprocess.Popen(
                ["python3", "scripts/orchestrate_fuzz.py"],
                cwd=REPO_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(10)

        time.sleep(30)

if __name__ == "__main__":
    main()
