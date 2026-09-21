#!/usr/bin/env python3
"""weekly_report.py -- the weekly routine's whole body (HANDOFF §8).

The routine is NOT registered.  This script is the thing a scheduler would call
once it is; running it by hand does exactly what the scheduled run would do.

What it does (all of it accumulation, none of it change):

  1. **aggregate** every project's ``.verified-fix/`` and the harness'
     ``runs.jsonl`` for the last N days
  2. **accumulate** new escapes into the attack corpus -- a patch that got past
     every gate in a real run is copied into ``attack-corpus/patches/`` and
     appended to ``index.json`` with ``expect: attack`` and a ``first`` verdict
     of SLIP.  This is declarative: it records what happened, it does not decide
     anything
  3. **regression-test** the gates with ``run_corpus.py`` (optional, because it
     is the expensive part) and report REGRESSION / FALSE-POSITIVE rows
  4. **extract false-positive patterns** -- which gate rejects correct fixes,
     and on what shape of patch
  5. write ``reports/weekly_YYYY-MM-DD.md``

What it deliberately does NOT do:

  **it never edits SKILL.md, DESIGN.md, or any gate.**  Everything it concludes
  goes into a 「提案（適用は人間）」 section of the report and stops there.

  Reason, from SKILL 原則3: a routine that reads its own results and then tunes
  the gates has built the exact loop the whole design exists to prevent -- an
  agent with a path to loosening the mechanism that stops it.  蓄積は自動、
  変更は人間.

With no data for the period it prints one line, ``今週の実行なし``, and exits 0.
An empty week is a normal week, not an error.

usage:
  weekly_report.py [--projects P[,P...]] [--scan ROOT] [--corpus DIR]
                   [--runs FILE] [--out DIR] [--days N]
                   [--regression off|fast|strict] [--jobs N] [--dry-run]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import shutil
import subprocess
import sys
import time

HOME = pathlib.Path.home()
SKILL = pathlib.Path(__file__).resolve().parents[2]      # .../skills/verified-fix
DEFAULT_CORPUS = SKILL / "harness/attack-corpus"
DEFAULT_REPORTS = SKILL / "reports"
DEFAULT_RUNS = HOME / "vf1/runs.jsonl"
SRC = pathlib.Path(__file__).resolve().parent

ESCALATORS = {"check6", "check7"}


# --------------------------------------------------------------------------- #
# 1. collect
# --------------------------------------------------------------------------- #

def find_projects(scan_roots, explicit):
    """Every directory that holds a ``.verified-fix/``."""
    out = []
    for p in explicit:
        d = pathlib.Path(p).expanduser()
        if (d / ".verified-fix").is_dir():
            out.append(d)
        elif d.name == ".verified-fix" and d.is_dir():
            out.append(d.parent)
    for root in scan_roots:
        r = pathlib.Path(root).expanduser()
        if not r.is_dir():
            continue
        for d in sorted(r.glob("*/.verified-fix")):
            out.append(d.parent)
        for d in sorted(r.glob("*/*/.verified-fix")):
            out.append(d.parent)
    seen, uniq = set(), []
    for d in out:
        if str(d) not in seen:
            seen.add(str(d))
            uniq.append(d)
    return uniq


def _read_json(p: pathlib.Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def collect_project(d: pathlib.Path, since: float) -> dict:
    vf = d / ".verified-fix"
    rec = {"project": str(d), "rounds": [], "hardening": None,
           "escapes": [], "n_files": 0, "latest_mtime": None}
    files = [p for p in vf.rglob("*") if p.is_file()]
    rec["n_files"] = len(files)
    if files:
        rec["latest_mtime"] = max(p.stat().st_mtime for p in files)
    rec["hardening"] = _read_json(vf / "hardening.json")
    for p in sorted(vf.glob("round_*.json")) + sorted(vf.glob("rounds/*.json")):
        if p.stat().st_mtime < since:
            continue
        j = _read_json(p)
        if j:
            j["_file"] = str(p)
            rec["rounds"].append(j)
    # an escape is a patch the pipeline accepted that a human later marked bad,
    # or a patch a hardening run recorded as having passed every gate.
    for p in sorted(vf.glob("escapes/*.patch")):
        rec["escapes"].append({"patch": str(p), "name": p.stem,
                               "mtime": p.stat().st_mtime})
    h = rec["hardening"] or {}
    for a in (h.get("attacks") or []):
        if a.get("slipped") and a.get("patch"):
            rec["escapes"].append({"patch": a["patch"],
                                   "name": a.get("name") or
                                   pathlib.Path(a["patch"]).stem,
                                   "mtime": None, "from": "hardening.json"})
    return rec


def recent_runs(runs_file: pathlib.Path, since: float) -> list:
    if not runs_file.exists():
        return []
    out = []
    for line in runs_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        ts = j.get("ts")
        try:
            t = _dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S").timestamp()
        except Exception:
            t = None
        if t is None or t >= since:
            j["_ts"] = t
            out.append(j)
    return out


# --------------------------------------------------------------------------- #
# 2. accumulate new escapes into the corpus  (declarative; no judgement)
# --------------------------------------------------------------------------- #

def accumulate(escapes, corpus: pathlib.Path, dry: bool) -> list:
    idx_path = corpus / "index.json"
    idx = _read_json(idx_path) or {"entries": []}
    known = {e["name"] for e in idx["entries"]}
    added = []
    for esc in escapes:
        name = esc["name"]
        if name in known:
            continue
        src = pathlib.Path(esc["patch"])
        if not src.exists():
            continue
        rel = "patches/%s.patch" % name
        entry = {
            "name": name,
            "patch": rel,
            "origin": "weekly-%s" % _dt.date.today().isoformat(),
            "intent": "escape observed in a real run; added by the weekly "
                      "routine, not yet triaged by a human",
            "expect": "attack",
            "harm": {"escape": None, "how": "UNVERIFIED -- a human must "
                                            "confirm the harm before this row "
                                            "is used as evidence"},
            "first": {"seen": "weekly-%s" % _dt.date.today().isoformat(),
                      "verdict": "SLIP", "killed_by": None},
        }
        if not dry:
            (corpus / "patches").mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, corpus / rel)
            idx["entries"].append(entry)
        added.append(entry)
        known.add(name)
    if added and not dry:
        idx_path.write_text(json.dumps(idx, indent=1, ensure_ascii=False),
                            encoding="utf-8")
    return added


# --------------------------------------------------------------------------- #
# 3. regression check -- the gates' own CI
# --------------------------------------------------------------------------- #

def regression(mode: str, corpus: pathlib.Path, jobs: int, py: str) -> dict:
    if mode == "off":
        return {"ran": False, "reason": "--regression off"}
    out = HOME / ("vf1/weekly_corpus_%s.json" % _dt.date.today().isoformat())
    gate_args = "--profile fast" if mode == "fast" else "--profile strict"
    cmd = [py, str(SRC / "run_corpus.py"), "--corpus", str(corpus),
           "--jobs", str(jobs), "--out", str(out), "--gate-args", gate_args]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=6 * 3600)
    except Exception as exc:                                    # noqa: BLE001
        return {"ran": False, "error": str(exc)[:300], "cmd": " ".join(cmd)}
    rep = _read_json(out) or {}
    return {"ran": True, "mode": mode, "wall_s": round(time.time() - t0, 1),
            "rc": r.returncode, "report": str(out),
            "defence_rate": rep.get("defence_rate"),
            "n_attacks": rep.get("n_attacks"),
            "n_attacks_killed": rep.get("n_attacks_killed"),
            "slips": rep.get("slips"), "regressions": rep.get("regressions"),
            "false_positives": rep.get("false_positives"),
            "rows": rep.get("rows") or [],
            "tail": (r.stdout or "")[-1500:]}


# --------------------------------------------------------------------------- #
# 4. false-positive patterns
# --------------------------------------------------------------------------- #

def fp_patterns(rows) -> dict:
    """Which gate rejects correct fixes, and what those patches have in common."""
    by_gate, esc_only = {}, []
    for r in rows:
        if r.get("expect") != "control":
            continue
        gates = r.get("gates") or {}
        red = [g for g, v in gates.items() if v is False]
        if not red:
            continue
        hard = [g for g in red if g.split("@")[0] not in ESCALATORS]
        if not hard:
            esc_only.append({"name": r["name"], "gates": red})
            continue
        for g in hard:
            by_gate.setdefault(g.split("@")[0], []).append(r["name"])
    return {"hard_reject_by_gate": {k: sorted(v) for k, v in sorted(by_gate.items())},
            "escalated_only": esc_only}


# --------------------------------------------------------------------------- #
# 5. report
# --------------------------------------------------------------------------- #

def write_report(path: pathlib.Path, ctx: dict) -> None:
    d = ctx
    L = []
    L.append("# verified-fix 週次レポート %s" % d["date"])
    L.append("")
    L.append("> 自動生成（`harness/src/weekly_report.py`）。**このレポートは"
             "スキルもゲートも変更しない。** 提案は §5 にあり、適用は人間が行う。")
    L.append("")
    L.append("対象期間: 直近 %d 日（%s 以降）" % (d["days"], d["since_str"]))
    L.append("")

    L.append("## 1. 実行の集約")
    L.append("")
    if not d["projects"] and not d["runs"]:
        L.append("今週の実行なし")
    else:
        L.append("| プロジェクト | `.verified-fix/` のファイル数 | 最終更新 | "
                 "今週のラウンド | 記録された escape |")
        L.append("|---|---|---|---|---|")
        for p in d["projects"]:
            mt = ("-" if not p["latest_mtime"] else
                  _dt.datetime.fromtimestamp(p["latest_mtime"]).strftime("%Y-%m-%d %H:%M"))
            L.append("| `%s` | %d | %s | %d | %d |"
                     % (p["project"], p["n_files"], mt, len(p["rounds"]),
                        len(p["escapes"])))
        if not d["projects"]:
            L.append("| （`.verified-fix/` を持つプロジェクトなし） | - | - | - | - |")
        L.append("")
        L.append("### ハーネス実行（`runs.jsonl`）")
        L.append("")
        if d["runs"]:
            L.append("| ts | label | 防御率 | 正当修正の hard reject | "
                     "平均コスト/パッチ |")
            L.append("|---|---|---|---|---|")
            for r in d["runs"]:
                ac = r.get("attack_corpus") or {}
                lf = r.get("legit_fixes") or {}
                gc = r.get("gate_cost") or {}
                mean = round(sum(v.get("mean_s", 0) for v in gc.values()), 1) if gc else "-"
                L.append("| %s | %s | %s | %s | %s |"
                         % (r.get("ts"), r.get("label"),
                            ac.get("defence_rate", "-"),
                            lf.get("false_positive_rate_reject", "-"), mean))
        else:
            L.append("今週の実行なし")
    L.append("")

    L.append("## 2. 攻撃コーパスへの追加（新規突破）")
    L.append("")
    if d["added"]:
        for e in d["added"]:
            L.append("- **%s** — `%s`（harm 未検証。人間が確認するまで証拠に"
                     "使わないこと）" % (e["name"], e["patch"]))
    else:
        L.append("新規の突破なし。")
    L.append("")

    L.append("## 3. 回帰検査（ゲートの CI）")
    L.append("")
    rg = d["regression"]
    if not rg.get("ran"):
        L.append("未実行（%s）" % (rg.get("reason") or rg.get("error") or "-"))
    else:
        L.append("- モード: `%s` / 所要 %s 秒" % (rg.get("mode"), rg.get("wall_s")))
        L.append("- 防御: %s/%s（%s）" % (rg.get("n_attacks_killed"),
                                          rg.get("n_attacks"),
                                          rg.get("defence_rate")))
        L.append("- **REGRESSION**: %s" % (rg.get("regressions") or "なし"))
        L.append("- **SLIP**: %s" % (rg.get("slips") or "なし"))
        L.append("- **正当修正の誤却下**: %s" % (rg.get("false_positives") or "なし"))
    L.append("")

    L.append("## 4. 偽陽性パターン")
    L.append("")
    fp = d["fp"]
    if fp.get("hard_reject_by_gate"):
        L.append("| ゲート | 誤って却下した正当修正 |")
        L.append("|---|---|")
        for g, names in fp["hard_reject_by_gate"].items():
            L.append("| `%s` | %s |" % (g, ", ".join(names)))
    else:
        L.append("hard reject された正当修正なし。")
    if fp.get("escalated_only"):
        L.append("")
        L.append("エスカレートのみ（却下ではない）: %s"
                 % ", ".join(x["name"] for x in fp["escalated_only"]))
    L.append("")

    L.append("## 5. 提案（**適用は人間**）")
    L.append("")
    if d["proposals"]:
        for p in d["proposals"]:
            L.append("- %s" % p)
    else:
        L.append("提案なし。")
    L.append("")
    L.append("> このセクションは提案で終わる。原則3「AI にゲートを最適化させない」"
             "——結果を見てゲートを自動調整すると、AI が自分を止める機構を緩める"
             "経路ができる。**蓄積は自動、変更は人間。**")
    L.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def build_proposals(d: dict) -> list:
    out = []
    fp = d["fp"].get("hard_reject_by_gate") or {}
    for g, names in fp.items():
        out.append("`%s` が正当修正 %d 件（%s）を却下している。"
                   "**ゲートを緩める前に、まずオラクル T が弱くないかを見ること** "
                   "— v8 で L1/L3 はゲートではなく T の穴だった（`_is_allowed` の "
                   "参照意味論 R と等価な性質が無かった）。" % (g, len(names),
                                                              ", ".join(names)))
    if d["regression"].get("regressions"):
        out.append("**REGRESSION あり**: %s。直近のゲート変更を疑い、"
                   "変更前後で `run_corpus.py` を回して差分を取ること。"
                   % d["regression"]["regressions"])
    if d["added"]:
        out.append("新規 escape %d 件をコーパスに追加した。"
                   "**harm の検証（truth グリッド or 個別 witness）は人間の作業**。"
                   "検証前の行を防御率の分母に入れないこと。" % len(d["added"]))
    if not d["projects"] and not d["runs"]:
        out.append("実行データが無い。ルーティンは正常終了しているが、"
                   "**この状態が続くならスキルが実務で使われていない**という所見。")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects", default="")
    ap.add_argument("--scan", default=str(HOME / "projects") + "," + str(HOME / "vf1"))
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ap.add_argument("--runs", default=str(DEFAULT_RUNS))
    ap.add_argument("--out", default=str(DEFAULT_REPORTS))
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--regression", default="off", choices=["off", "fast", "strict"])
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--py", default=str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python"))
    ap.add_argument("--dry-run", action="store_true",
                    help="do not write the corpus; still writes the report")
    a = ap.parse_args()

    since = time.time() - a.days * 86400
    corpus = pathlib.Path(a.corpus)

    projects = [collect_project(d, since) for d in find_projects(
        [x for x in a.scan.split(",") if x.strip()],
        [x for x in a.projects.split(",") if x.strip()])]
    runs = recent_runs(pathlib.Path(a.runs), since)

    if not projects and not runs:
        print("今週の実行なし")
        # a report is still written so the absence itself is on the record
        ctx = {"date": _dt.date.today().isoformat(), "days": a.days,
               "since_str": _dt.datetime.fromtimestamp(since).strftime("%Y-%m-%d"),
               "projects": [], "runs": [], "added": [],
               "regression": {"ran": False, "reason": "no data"},
               "fp": {}, "proposals": []}
        ctx["proposals"] = build_proposals(ctx)
        write_report(pathlib.Path(a.out) /
                     ("weekly_%s.md" % ctx["date"]), ctx)
        return 0

    escapes = [e for p in projects for e in p["escapes"]]
    added = accumulate(escapes, corpus, a.dry_run)
    rg = regression(a.regression, corpus, a.jobs, a.py)
    fp = fp_patterns(rg.get("rows") or [])

    ctx = {"date": _dt.date.today().isoformat(), "days": a.days,
           "since_str": _dt.datetime.fromtimestamp(since).strftime("%Y-%m-%d"),
           "projects": projects, "runs": runs, "added": added,
           "regression": rg, "fp": fp, "proposals": []}
    ctx["proposals"] = build_proposals(ctx)

    out = pathlib.Path(a.out) / ("weekly_%s.md" % ctx["date"])
    write_report(out, ctx)
    print(json.dumps({"projects": len(projects), "runs": len(runs),
                      "corpus_added": [e["name"] for e in added],
                      "regression_ran": rg.get("ran"),
                      "report": str(out)}, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
