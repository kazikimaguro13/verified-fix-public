# -*- coding: utf-8 -*-
"""v38: パイプライン結果を「受理したか」の1行にまとめる。

    python3 show_verdicts.py <サフィックス> <変種...>

★D22: 「却下した」(killed_by_all)・「走れなかった」(errored_gates)・
  「適用外」(inapplicable_gates) を
  同じ列に出さない。どちらもパッチは受理されないが、混ぜて読むと撃墜を捏造する。
  エスカレート (検査6/7) は却下ではないので、さらに別の列にする。
"""
import io
import json
import sys

suf = sys.argv[1] if len(sys.argv) > 1 else "v38"
names = sys.argv[2:]
if not names:
    print("usage: show_verdicts.py <suffix> <variant...>")
    sys.exit(2)

rows = []
for v in names:
    p = "/tmp/pipe_%s_%s.json" % (v, suf)
    try:
        d = json.load(io.open(p, encoding="utf-8"))
    except Exception as e:
        rows.append((v, "読めない", str(e)[:60], "", "", ""))
        try:
            tail = io.open(p.replace(".json", ".err"), encoding="utf-8",
                           errors="replace").read()[-400:]
            print("%s stderr tail:\n%s" % (v, tail))
        except Exception:
            pass
        continue
    killed = d.get("killed_by_all") or []
    errored = d.get("errored_gates") or []
    inapp = d.get("inapplicable_gates") or []
    esc = d.get("escalated") or []
    # ★受理の定義: hard 却下がゼロ かつ 走れなかったゲートがゼロ。
    #   `all_gates_passed` を使ってはいけない — あれは escalate 専用ゲート
    #   （検査6・検査7）が鳴っただけでも false になる。エスカレートは
    #   「人間に返す」であって却下ではない（§0-h・D22）。
    # ★v70: 受理は run_gates が `accepted` で1か所に決める。ここは再導出しない。
    #   宣言による適用外は塞がない／結果による適用外は塞ぐ。
    #   古い走行に `accepted` が無いときだけ、旧い定義で落とす。
    acc = d.get("accepted")
    by_out = d.get("inapplicable_by_outcome") or []
    if killed:
        verdict = "却下"
    elif errored:
        verdict = "ERROR"
    elif (by_out if acc is not None else inapp):
        verdict = "適用外"
    elif esc:
        verdict = "受理*"      # * = エスカレートあり（人間が読む）
    else:
        verdict = "受理"
    cost = sum(v2 for v2 in (d.get("cost_s") or {}).values()
               if isinstance(v2, (int, float)))
    rows.append((v, verdict, ",".join(killed), ",".join(errored),
                 ",".join(esc), "%.1f" % cost))

w = max([len(r[0]) for r in rows] + [7])
print("%-*s | %-6s | %-22s | %-16s | %-14s | %s"
      % (w, "変種", "判定", "却下したゲート", "走れなかった", "エスカレート", "秒"))
print("-" * (w + 84))
for r in rows:
    print("%-*s | %-6s | %-22s | %-16s | %-14s | %s"
          % (w, r[0], r[1], r[2] or "-", r[3] or "-", r[4] or "-", r[5]))

print("")
print("受理* = hard 却下ゼロだがエスカレートあり（人間が読む）。エスカレートは却下ではない。")
print("")
print("=== 却下・ERROR の理由 ===")
for v in names:
    p = "/tmp/pipe_%s_%s.json" % (v, suf)
    try:
        d = json.load(io.open(p, encoding="utf-8"))
    except Exception:
        continue
    bad = ((d.get("killed_by_all") or []) + (d.get("errored_gates") or [])
           + (d.get("inapplicable_gates") or []))
    if not bad:
        continue
    print("--- %s ---" % v)
    for g in bad:
        det = d.get(g.split("@")[0]) or d.get(g) or {}
        if not isinstance(det, dict):
            print("   %s: %s" % (g, det))
            continue
        why = det.get("reason") or det.get("fail_reason") or det.get("detail") or ""
        flag = ""
        if det.get("gate_could_not_run"):
            flag = "[走れなかった] "
        elif det.get("inapplicable"):
            flag = "[適用外] "
        print("   %s: %s%s" % (g, flag, str(why)[:300]))
        for k in ("n_survived", "survived", "survivors", "mutants", "killed",
                  "no_coverage", "n_divergent", "n_unexplained", "n_failed",
                  "structural_error", "genuine_behavioural_failure",
                  "sample_message"):
            if k in det:
                print("       %s = %s" % (k, json.dumps(det[k], ensure_ascii=False)[:220]))
