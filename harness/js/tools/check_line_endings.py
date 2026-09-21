# -*- coding: utf-8 -*-
"""CRLF を保つべきファイルに単独 LF が紛れていないかを、バイトで検算する。

  python3 harness/js/tools/check_line_endings.py          # 検査だけ（非ゼロ終了で失敗）
  python3 harness/js/tools/check_line_endings.py --fix    # 単独 LF を CRLF へ直す

★なぜ道具にしたか: 2026-08-26 に Cowork が **同じミスを2回** した。
どちらも「挿入する文字列の片方だけに改行変換を掛け忘れた」もので、
1回目は 14行、2回目は 1行。**どちらもコミット後の検算で見つかった＝直前まで気づいていない。**
§0-c の規律（件数を出す）を、改行にも当てる。
"""
import io, sys, pathlib

# CRLF を保つファイル（実測して決めた。増えたらここに足す）
CRLF_FILES = ["HANDOFF.md", "DESIGN.md", "harness/js/gates/run_gates.mjs", "harness/js/gates/diffgate.mjs"]

def main():
    fix = "--fix" in sys.argv
    root = pathlib.Path(__file__).resolve().parents[3]
    bad = 0
    for rel in CRLF_FILES:
        p = root / rel
        if not p.exists():
            print("%-40s 見つからない" % rel); bad += 1; continue
        b = p.read_bytes()
        crlf = b.count(b"\r\n"); lone = b.count(b"\n") - crlf
        if lone and fix:
            b2 = b.replace(b"\r\n", b"\x00").replace(b"\n", b"\r\n").replace(b"\x00", b"\r\n")
            assert b2.count(b"\n") == b.count(b"\n"), "行数が変わった"
            p.write_bytes(b2)
            print("%-40s CRLF=%-6d 単独LF=%-4d → 直した" % (rel, crlf, lone))
        else:
            print("%-40s CRLF=%-6d 単独LF=%d%s" % (rel, crlf, lone, "  ★" if lone else ""))
            bad += 1 if lone else 0
    if bad and not fix:
        print("\n★単独 LF がある。`--fix` で直すこと。"); return 1
    return 0

sys.exit(main())
