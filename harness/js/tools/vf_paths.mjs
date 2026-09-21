// vf_paths.mjs -- the ONE place the JS side of this harness learns where things
// are.  Introduced by judgement 61 (option A, v134).
//
// WHY: MEASURED (v131 staging audit, §4): five machine paths were written out
// as string literals in 109 places across 47 files.  They are five facts, not
// 109, and a public copy of this repository cannot carry any of them.
//
// WHAT IT IS NOT: this is not a gate and it is not a pass condition.  Nothing
// here is read by run_gates.mjs; it is read by the *drivers* around it.
//
// ⛔ THE DEFAULTS REPRODUCE THE OLD LITERALS ON THE MACHINE THEY WERE WRITTEN
//   ON, and that is checked, not hoped for: reports/v134_raw/paths_resolved.txt
//   prints every value from all three languages and compares it against the
//   literal it replaced.
//
// Every value takes an environment variable first (except VF_SKILL_DIR, which
// prefers its own location -- a checkout knows where it is better than an
// exported variable does), then falls back to a default derived from $HOME.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const env = (k) => {
  const v = process.env[k];
  return v && v.length ? v : null;
};

// ---- VF_HOME -------------------------------------------------------------
// The scratch root every experiment writes into.  Was: /home/<user>/vf1
export const VF_HOME = env("VF_HOME") || path.join(os.homedir(), "vf1");

// ---- VF_SKILL_DIR --------------------------------------------------------
// The checkout of this skill.  Derived from THIS FILE's own location, which is
// <skill>/harness/js/tools/vf_paths.mjs -- three levels up is the skill root.
// The env variable is the FALLBACK, for the case where the derivation lands
// somewhere that is not a checkout (a copied-out single file, a bundle).
// Was: /mnt/c/Users/<user>/.claude/skills/verified-fix
const HERE = path.dirname(fileURLToPath(import.meta.url));
const DERIVED_SKILL = path.resolve(HERE, "..", "..", "..");
const looksLikeSkill = (d) => {
  try {
    return fs.existsSync(path.join(d, "SKILL.md")) && fs.existsSync(path.join(d, "harness"));
  } catch {
    return false;
  }
};
export const VF_SKILL_DIR = looksLikeSkill(DERIVED_SKILL)
  ? DERIVED_SKILL
  : (env("VF_SKILL_DIR") || DERIVED_SKILL);

// ---- the client clone (read only -- never pushed to) ----------------------
// Was: /home/<user>/vf1/client/portal  (apps/portal-web is the repo inside it)
// ★v135 (judgement 63): the name carried the client's initials into the public
//   copy.  Environment spelling is VF_CLIENT_PORTAL; the bare CLIENT_PORTAL is
//   still read, because vf_env.sh EXPORTS that spelling to its children.
export const CLIENT_PORTAL =
  env("VF_CLIENT_PORTAL") || env("CLIENT_PORTAL") || path.join(VF_HOME, "client", "portal");

// ---- the variant / cfg store ---------------------------------------------
// Was: /home/<user>/vf1/client/vf     (lit2, orch2, ctrl, lit, lit4, orch58 ...)
export const CLIENT_VF =
  env("VF_CLIENT_VF") || env("CLIENT_VF") || path.join(VF_HOME, "client", "vf");

// ---- the RUNNING copy of the gates ---------------------------------------
// Was: /home/<user>/vf1/jsharness/gates
// VF_GATES is honoured first because gate_power.mjs and run_check5.mjs already
// read it and that spelling must keep working.
export const JS_GATES_DIR =
  env("VF_GATES") || env("JS_GATES_DIR") || path.join(VF_HOME, "jsharness", "gates");

// ---- Node 22 -------------------------------------------------------------
// Was: /home/<user>/.nvm/versions/node/v22.23.2/bin
// Resolution: VF_NODE_BIN, else the FIRST $HOME/.nvm/versions/node/v22*/bin
// that exists (ascending name order), else "" -- and "" means "use PATH".
// Callers write: NODE_BIN_DIR ? path.join(NODE_BIN_DIR, "node") : "node".
function findNodeBin() {
  const e = env("VF_NODE_BIN");
  if (e) return e;
  const base = path.join(os.homedir(), ".nvm", "versions", "node");
  let names = [];
  try {
    names = fs.readdirSync(base).filter((n) => n.startsWith("v22")).sort();
  } catch {
    return "";
  }
  for (const n of names) {
    const bin = path.join(base, n, "bin");
    try {
      if (fs.statSync(bin).isDirectory()) return bin;
    } catch {
      /* keep looking */
    }
  }
  return "";
}
export const NODE_BIN_DIR = findNodeBin();

// Printed by reports/v134_raw/paths_resolved.txt.  Order is fixed and shared
// with vf_env.sh and vf_paths.py so the three outputs compare line by line.
export const VF_PATHS_ORDER = [
  "VF_HOME",
  "VF_SKILL_DIR",
  "CLIENT_PORTAL",
  "CLIENT_VF",
  "JS_GATES_DIR",
  "NODE_BIN_DIR",
];
export const VF_PATHS = {
  VF_HOME,
  VF_SKILL_DIR,
  CLIENT_PORTAL,
  CLIENT_VF,
  JS_GATES_DIR,
  NODE_BIN_DIR,
};
