# -*- coding: utf-8 -*-
"""検査13（Python 版）— 修正が型エラーを持ち込んでいないか。

判断27（本人決裁 2026-09-10 夜）。JS 側 v104 の `typegate.mjs` と同じ**差分方式**:

    pre イメージで mypy を回し、post イメージでも回し、
    **post にだけ現れたエラー**で落とす。

なぜ差分方式か（実測・v108）: この木は**もとから 238 件のエラーを持っている**
（28ファイル・ほぼ `tests/` 配下。`ccd/` 自体は 60ファイルで 0 件）。
絶対数で判定すると、正当な修正が他人のエラーで落ちる。

⚠ **行番号を鍵にしない。**1行足しただけで下の全エラーが「新規」になる。
鍵は `(ファイル, エラーコード, 本文)`。JS 版と同じ。

⚠ **mypy の終了コードは見ない**（エラーがあれば非0を返すのが正常）。§0-h。

使い方（run_gates3.py から2回呼ぶ）:
    typegate.py --repo R --mode pre  --save /tmp/pre.json
    typegate.py --repo R --mode post --pre  /tmp/pre.json      # ← 判定を stdout に
"""
import argparse, json, os, re, subprocess, sys, time

# `path:line: severity: message  [code]`
LINE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+):(?:\d+:)?\s*(?P<sev>error|note):\s*(?P<msg>.*?)(?:\s+\[(?P<code>[a-z-]+)\])?$")


def run_mypy(py, repo, targets, timeout):
    t0 = time.time()
    cmd = [py, "-m", "mypy", "--no-error-summary", "--no-color-output"] + list(targets)
    try:
        r = subprocess.run(cmd, cwd=repo, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ran": False, "why": "mypy timed out after %ss" % timeout,
                "errors": [], "secs": round(time.time() - t0, 2)}
    out = (r.stdout or "") + (r.stderr or "")
    errors = []
    for ln in out.splitlines():
        m = LINE.match(ln.strip())
        if not m or m.group("sev") != "error":
            continue
        errors.append({"file": m.group("file"), "code": m.group("code") or "",
                       "msg": m.group("msg").strip()})
    # mypy exits non-zero whenever it found errors -- that is not a failure of
    # the gate.  It IS a failure if it could not run at all (no output, no
    # errors parsed, and a non-zero status).
    ran = bool(errors) or r.returncode == 0 or "Success" in out
    return {"ran": ran, "why": None if ran else (out.strip()[-400:] or "mypy produced no output"),
            "errors": errors, "secs": round(time.time() - t0, 2),
            "exit": r.returncode}


def key(e):
    return (e["file"], e["code"], e["msg"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--mode", choices=("pre", "post"), required=True)
    ap.add_argument("--py", default=sys.executable)
    ap.add_argument("--save", default="")
    ap.add_argument("--pre", default="")
    ap.add_argument("--targets", default=".",
                    help="comma-separated mypy targets; the SAME value must be "
                         "used for pre and post or the diff is meaningless")
    ap.add_argument("--budget-s", type=int, default=300)
    a = ap.parse_args()

    targets = [t for t in a.targets.split(",") if t.strip()]
    got = run_mypy(a.py, a.repo, targets, a.budget_s)

    if a.mode == "pre":
        payload = {"errors": got["errors"], "ran": got["ran"], "why": got["why"],
                   "secs": got["secs"], "targets": targets}
        if a.save:
            with open(a.save, "w", encoding="utf-8") as f:
                json.dump(payload, f)
        print(json.dumps({"gate": "check13_typecheck", "mode": "pre",
                          "n_errors": len(got["errors"]), "ran": got["ran"],
                          "secs": got["secs"]}, ensure_ascii=False))
        return 0

    base = {"errors": [], "ran": False, "why": "no pre result given", "secs": 0}
    if a.pre and os.path.exists(a.pre):
        with open(a.pre, encoding="utf-8") as f:
            base = json.load(f)

    out = {"gate": "check13_typecheck", "targets": targets,
           "secs": round(got["secs"] + base.get("secs", 0), 2)}

    # Either side failing to run means nothing was compared.  Say so; do not
    # call it a pass and do not call it a rejection (D22 / 判断17).
    if not base.get("ran") or not got["ran"]:
        out.update({"pass": False, "gate_could_not_run": True,
                    "reason": "mypy did not run on one of the two images",
                    "pre_ran": base.get("ran"), "post_ran": got["ran"],
                    "why_pre": base.get("why"), "why_post": got["why"],
                    "n_introduced": None, "n_pre_existing": len(base.get("errors") or [])})
        print(json.dumps(out, ensure_ascii=False))
        return 0

    pre_keys = {}
    for e in base["errors"]:
        pre_keys[key(e)] = pre_keys.get(key(e), 0) + 1
    introduced = []
    seen = {}
    for e in got["errors"]:
        k = key(e)
        seen[k] = seen.get(k, 0) + 1
        if seen[k] > pre_keys.get(k, 0):
            introduced.append(e)

    out.update({
        "pass": len(introduced) == 0,
        "n_introduced": len(introduced),
        "n_pre_existing": len(base["errors"]),
        "n_post_total": len(got["errors"]),
        "introduced": introduced[:20],
        "engine": "mypy",
    })
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
