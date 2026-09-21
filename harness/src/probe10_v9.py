import json, os, pathlib, re, shutil, subprocess, sys
HOME = pathlib.Path.home()
REPO = HOME/"vf1/testbed"; PY=str(HOME/"projects/Cowork-CC-dispatch/.venv/bin/python")
SRC=HOME/"vf1/src"; WORK=HOME/"vf1/v9tmp/probe10"
DIFF=re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.M)
pdir = pathlib.Path(sys.argv[1])
for patch in sorted(pdir.glob("*.patch")):
    name=patch.stem; text=patch.read_text()
    changed=sorted({m.group(2) for m in DIFF.finditer(text)})
    d=WORK/name
    if d.exists(): shutil.rmtree(d)
    for half in ("pre","post"):
        for rel in changed:
            p=d/half/rel; p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(subprocess.run(["git","show","HEAD:"+rel],cwd=str(REPO),capture_output=True,text=True).stdout)
    r=subprocess.run(["patch","-p1","-s","-i",str(patch)],cwd=str(d/"post"),capture_output=True,text=True)
    if r.returncode!=0:
        print(name,"PATCH FAILED",r.stdout,r.stderr); continue
    cfg=d/"cfg.json"
    cfg.write_text(json.dumps({"repo":str(REPO),"changed":changed,
        "pre_images":{r0:str(d/"pre"/r0) for r0 in changed},
        "post_images":{r0:str(d/"post"/r0) for r0 in changed},
        "anchor_file":"ccd/guard_pathmatch.py","anchor_func":"_is_allowed"}))
    q=subprocess.run([PY,os.environ.get("SG_GATE") or str(SRC/"structgate.py"),str(cfg),"--py",PY],capture_output=True,text=True)
    try: v=json.loads(q.stdout[q.stdout.index("{"):])
    except Exception: v={"pass":None,"error":(q.stdout+q.stderr)[-300:]}
    print(name.ljust(24), "check10 pass=", v.get("pass"), "ndiv=", v.get("n_divergent_variants"), "variants=", sorted(v.get("divergent") or {}), "inapp=", v.get("n_inapplicable"))
