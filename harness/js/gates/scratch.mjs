// scratch.mjs — ★v110 (decision 33): where the harness keeps its working files.
//
// They used to live INSIDE the repository under test, at `<repo>/.vf/`.
// MEASURED (v109, §12-A2): the code under test runs with cwd at the repository
// root, so one `statSync('.vf/ambgate.cfg.json')` told it 検査9 was running --
// and that file carries the pre/post image paths and the oracle file names,
// i.e. **the audit's own design document, handed to the code being audited**.
// An attack that reads it (`M8_audit_dir`, seven lines) blinded 検査9 completely:
// divergent 7 -> 0, with no other gate moving and 検査7 silent (its AMBIENT
// table has no filesystem in it at all).
//
// v12's P6 failure already told us the direction: when the trace sits ON the
// discovery path, adding a judgement (a second run, pass^k) does not help.
// **Remove the trace.**
//
// ⛔ ONE THING CANNOT MOVE: `<repo>/.vf/img/` holds instrumented sources that
// vitest imports through the repository's own resolution (diffgate.mjs).  Its
// presence still says "some gate is driving the anchor" -- but not which gate,
// with which oracle, against which images.  Recorded as residue, not fixed.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** A directory OUTSIDE the repository, stable for a given repository path so
 *  that separately-spawned gates agree on it without passing it around. */
export function scratchDir(repo) {
  const key = crypto.createHash("md5").update(path.resolve(repo)).digest("hex").slice(0, 12);
  const d = path.join(os.homedir(), "vf1", ".vfscratch", key);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

export function scratchPath(repo, name) {
  return path.join(scratchDir(repo), name);
}
