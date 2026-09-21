# -*- coding: utf-8 -*-
"""v32: 検査8 の結果を、生成器の内訳つきで並べる。"""
import io
import json
import sys


def esc(s):
    return "".join(c if 0x20 <= ord(c) < 0x7f else "\\u%04x" % ord(c) for c in str(s))


for v in (sys.argv[1:] or ["S1_control", "N9_derived_prefix",
                          "N10_codepoint_class", "N11_two_char"]):
    try:
        d = json.load(io.open("/tmp/mr_%s.json" % v, encoding="utf-8"))
    except Exception as e:
        print("%s: 読めない (%s)" % (v, e)); continue
    print("=" * 76)
    print("%-22s pass=%s" % (v, d.get("pass")))
    print("  符号位置の掃引 : 乖離 %-4s / %s 点" % (d.get("n_divergent_total"),
                                                    d.get("cp_tried_total")))
    print("  多文字の候補   : 違反 %-4s (逆向き %s) / 試行 %s"
          % (d.get("n_candidate_violations"), d.get("n_candidate_other_direction"),
             d.get("n_candidates_tried")))
    print("  生成器         : %s" % d.get("generator_note"))
    if d.get("regex_candidates"):
        print("    正規表現から : %s" % ", ".join(esc(c) for c in d["regex_candidates"]))
    if d.get("regex_unsupported"):
        for u in d["regex_unsupported"]:
            print("    ★作れず     : /%s/ -- %s" % (esc(u["pattern"]), u["why"]))
    if d.get("harvested"):
        print("    スパイ回収   : %s" % ", ".join(esc(c) for c in d["harvested"][:10]))
    for h in (d.get("candidate_violations") or [])[:4]:
        print("    ★違反       : template=%-10s candidate=%s"
              % (h["template"], esc(h["candidate"])))
    print("  時間           : 単調 %ss / 実時刻 %ss"
          % (d.get("elapsed_s"), d.get("elapsed_s_wall")))
