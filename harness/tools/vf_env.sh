# vf_env.sh -- the ONE place the shell side of this harness learns where things
# are.  Introduced by judgement 61 (option A, v134).
#
# SOURCE IT, do not execute it:
#     . "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"
# (that line is correct from harness/js/tools/ and harness/js/attacks/ -- both
#  are two levels under harness/, and vf_env.sh lives at harness/tools/).
#
# WHY: MEASURED (v131 staging audit, §4): five machine paths were written out
# as string literals in 109 places across 47 files.  They are five facts.
#
# ⛔ THE DEFAULTS REPRODUCE THE OLD LITERALS on the machine they were written
#   on; reports/v134_raw/paths_resolved.txt is the check, not a hope.
#
# Assignments use := so an already-exported value always wins.

# ---- VF_HOME: the scratch root.  Was: /home/<user>/vf1 -------------------
: "${VF_HOME:=$HOME/vf1}"

# ---- VF_SKILL_DIR: this checkout ------------------------------------------
# Derived from THIS FILE's location: it lives at <skill>/harness/tools/vf_env.sh,
# so the skill root is TWO directories above its own directory,
# because a checkout knows where it is better than an exported variable does.
# The exported value is the FALLBACK, used only if the derivation does not land
# on something that looks like a checkout.
# Was: /mnt/c/Users/<user>/.claude/skills/verified-fix
__vf_env_self="${BASH_SOURCE[0]:-$0}"
__vf_derived_skill="$(cd "$(dirname "$__vf_env_self")/../.." && pwd)"
if [ -f "$__vf_derived_skill/SKILL.md" ] && [ -d "$__vf_derived_skill/harness" ]; then
  VF_SKILL_DIR="$__vf_derived_skill"
else
  : "${VF_SKILL_DIR:=$__vf_derived_skill}"
fi
unset __vf_env_self __vf_derived_skill

# ---- the client clone (read only -- never pushed to) ----------------------
# Was: /home/<user>/vf1/client/portal
# ★v135 (judgement 63): the old export name carried the client's initials
#   into the public copy.  VF_CLIENT_PORTAL is the environment spelling;
#   an already-exported CLIENT_PORTAL still wins.
: "${CLIENT_PORTAL:=${VF_CLIENT_PORTAL:-$VF_HOME/client/portal}}"

# ---- the variant / cfg store.  Was: /home/<user>/vf1/client/vf ------------
: "${CLIENT_VF:=${VF_CLIENT_VF:-$VF_HOME/client/vf}}"

# ---- the RUNNING copy of the gates ----------------------------------------
# VF_GATES is honoured first: gate_power.mjs and run_check5.mjs already read
# that spelling and it must keep working.
# Was: /home/<user>/vf1/jsharness/gates
: "${JS_GATES_DIR:=${VF_GATES:-$VF_HOME/jsharness/gates}}"

# ---- Node 22.  Was: /home/<user>/.nvm/versions/node/v22.23.2/bin ----------
# VF_NODE_BIN, else the FIRST $HOME/.nvm/versions/node/v22*/bin that exists
# (ascending name order), else empty -- and empty means "use PATH".
# Callers write:  NODE="${NODE_BIN_DIR:+$NODE_BIN_DIR/}node"
if [ -z "${NODE_BIN_DIR:-}" ]; then
  if [ -n "${VF_NODE_BIN:-}" ]; then
    NODE_BIN_DIR="$VF_NODE_BIN"
  else
    NODE_BIN_DIR=""
    for __vf_d in "$HOME"/.nvm/versions/node/v22*/bin; do
      if [ -d "$__vf_d" ]; then NODE_BIN_DIR="$__vf_d"; break; fi
    done
    unset __vf_d
  fi
fi

export VF_HOME VF_SKILL_DIR CLIENT_PORTAL CLIENT_VF JS_GATES_DIR NODE_BIN_DIR
