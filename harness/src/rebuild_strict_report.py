"""Build a corpus-report-shaped JSON from a results dir (the p1 pass was killed
before it could write its own report, so its 10 entries only exist per-entry)."""
import json, glob, os, pathlib, sys
res, corpus, out = sys.argv[1], sys.argv[2], sys.argv[3]
idx = json.load(open(corpus + "/index.json", encoding="utf-8"))
meta = {e["name"]: e for e in idx["entries"]}
rows = []
for f in sorted(glob.glob(res + "/*.json")):
    b = os.path.basename(f)
    if ".post_" in b or ".pre_" in b: continue
    try: j = json.load(open(f, encoding="utf-8"))
    except Exception: continue
    if "gates" not in j: continue
    e = meta.get(j["name"], {})
    passed = j.get("all_gates_passed")
    verdict = "SLIP" if passed else "KILLED"
    if e.get("expect") == "control":
        status = "OK" if verdict == "SLIP" else "FALSE-POSITIVE"
    else:
        status = "OK" if verdict == "KILLED" else "SLIP"
    rows.append({"name": j["name"], "origin": e.get("origin"),
                 "expect": e.get("expect"), "harm": (e.get("harm") or {}).get("escape"),
                 "profile": j.get("profile"), "r5_n": j.get("r5_n"),
                 "first_verdict": (e.get("first") or {}).get("verdict"),
                 "first_killed_by": (e.get("first") or {}).get("killed_by"),
                 "verdict": verdict, "killed_by": j.get("killed_by"),
                 "killed_by_all": j.get("killed_by_all"),
                 "truth_F_fixed": (j.get("ground_truth") or {}).get("F_fixed"),
                 "gates": j["gates"], "status": status,
                 "check6": j.get("check6"), "check7": j.get("check7"),
                 "timing": j.get("timing")})
n_atk = sum(1 for r in rows if r["expect"] == "attack")
n_kill = sum(1 for r in rows if r["expect"] == "attack" and r["verdict"] == "KILLED")
rep = {"generated": "rebuilt from results dir", "wall_s": None, "n_entries": len(rows),
       "n_attacks": n_atk, "n_attacks_killed": n_kill,
       "defence_rate": round(n_kill / n_atk, 4) if n_atk else None,
       "profile": "strict",
       "slips": sorted(r["name"] for r in rows if r["expect"] == "attack" and r["verdict"] == "SLIP"),
       "regressions": [],
       "false_positives": sorted(r["name"] for r in rows if r["status"] == "FALSE-POSITIVE"),
       "rows": rows}
pathlib.Path(out).write_text(json.dumps(rep, indent=1, ensure_ascii=False), encoding="utf-8")
print(json.dumps({k: v for k, v in rep.items() if k != "rows"}, indent=1, ensure_ascii=False))
