"""Merge the two strict passes into one corpus report so metrics.py sees them
as a single sweep (they are: same gates, same manifest, same baseline)."""
import json, pathlib, sys

outs = sys.argv[1]
srcs = sys.argv[2:]
rows, wall, regs, fps, slips = [], 0.0, [], [], []
seen = set()
for s in srcs:
    p = pathlib.Path(s)
    if not p.exists():
        print("missing (skipped):", s)
        continue
    r = json.loads(p.read_text(encoding="utf-8"))
    wall += r.get("wall_s") or 0
    regs += r.get("regressions") or []
    fps += r.get("false_positives") or []
    slips += r.get("slips") or []
    for row in r.get("rows", []):
        if row["name"] in seen:
            continue
        seen.add(row["name"])
        rows.append(row)
n_atk = sum(1 for r in rows if r["expect"] == "attack")
n_kill = sum(1 for r in rows if r["expect"] == "attack" and r["verdict"] == "KILLED")
rep = {"generated": "merged", "wall_s": round(wall, 1), "n_entries": len(rows),
       "n_attacks": n_atk, "n_attacks_killed": n_kill,
       "defence_rate": round(n_kill / n_atk, 4) if n_atk else None,
       "slips": sorted(set(slips)), "regressions": sorted(set(regs)),
       "false_positives": sorted(set(fps)), "rows": rows}
pathlib.Path(outs).write_text(json.dumps(rep, indent=1, ensure_ascii=False),
                              encoding="utf-8")
print(json.dumps({k: v for k, v in rep.items() if k != "rows"}, indent=1,
                 ensure_ascii=False))
print("wrote", outs)
