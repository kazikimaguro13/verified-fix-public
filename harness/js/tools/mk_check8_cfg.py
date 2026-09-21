# -*- coding: utf-8 -*-
"""v29: 検査8（mrgate）単体実行用の cfg を作る。

パイプラインの cfg は spec を「パス」で持つが、mrgate.mjs は spygate と同じく
spec を「インラインの объект」で受ける。ここで読み込んで畳む。
sys.argv[1] = 変種名, [2] = max_cp(16進可), [3] = precond_max_cp
"""
import io
import json
import sys

import pathlib as _pathlib
import sys as _sys

# ★v134 (judgement 61): the machine paths below are resolved in ONE
# place now -- harness/src/vf_paths.py.  They used to be literals here.
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[2] / "src"))
from vf_paths import CLIENT_VF  # noqa: E402

ORCH = CLIENT_VF + "/orch2/"
OUT = CLIENT_VF + "/lit2/"

name = sys.argv[1]
max_cp = int(sys.argv[2], 0)
precond = int(sys.argv[3], 0) if len(sys.argv) > 3 else min(0x800, max_cp)

src = json.loads(io.open(ORCH + name + ".cfg.json", encoding="utf-8").read())
spec = json.loads(io.open(src["anchor_spec"], encoding="utf-8").read())

cfg = {
    "repo": src["repo"],
    "anchor_file": src["anchor_file"],
    "anchor_func": src["anchor_func"],
    "spec": spec,
    "spec_source": src["anchor_spec"],
    "pre_images": src["pre_images"],
    "post_images": src["post_images"],
    "max_cp": max_cp,
    "precond_max_cp": precond,
}
dst = OUT + name + ".mr.cfg.json"
io.open(dst, "w", encoding="utf-8").write(json.dumps(cfg, indent=1) + "\n")
print("WROTE", dst)
print("  post =", cfg["post_images"][cfg["anchor_file"]])
print("  max_cp = %s (%d) / precond = %s" % (hex(max_cp), max_cp, hex(precond)))
print("  templates =", [t["id"] for t in spec["templates"]],
      "| projection =", spec["projection"],
      "| structural =", spec.get("structural", []))
