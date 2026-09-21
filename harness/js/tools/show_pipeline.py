# -*- coding: utf-8 -*-
"""v29: パイプライン結果を並べる。sys.argv[1] = サフィックス"""
import io
import json
import sys

suf = sys.argv[1] if len(sys.argv) > 1 else "v29s"
names = sys.argv[2:] or ["N10_codepoint_class", "S1_control", "N11_two_char"]

for v in names:
    p = "/tmp/pipe_%s_%s.json" % (v, suf)
    try:
        d = json.load(io.open(p, encoding="utf-8"))
    except Exception as e:
        print("%s: 読めない (%s)" % (v, e))
        try:
            print("  stderr:", io.open(p.replace(".json", ".err"),
                                       encoding="utf-8", errors="replace").read()[-500:])
        except Exception:
            pass
        continue
    print("=" * 76)
    print("%s  [%s]" % (v, d.get("profile")))
    print("  gates :", json.dumps(d.get("gates"), ensure_ascii=False))
    print("  killed:", d.get("killed_by_all"), " escalated:", d.get("escalated"))
    print("  cost  :", json.dumps(d.get("cost_s"), ensure_ascii=False))
    for s in d.get("skipped_gates", []):
        print("  skip  : %s -- %s" % (s.get("gate"), (s.get("why") or "")[:70]))
    # 落ちたゲートの理由を出す
    for g, ok in (d.get("gates") or {}).items():
        if ok is False:
            det = d.get(g) or {}
            if isinstance(det, dict):
                for k in ("fail_reason", "n_divergent", "n_divergent_total",
                          "inapplicable", "skipped", "n_survived", "survived",
                          "n_unexplained"):
                    if k in det:
                        print("   %s.%s = %s" % (g, k, json.dumps(det[k], ensure_ascii=False)[:200]))
