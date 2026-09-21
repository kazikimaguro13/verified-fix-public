#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verified-fix -- deep comparison of two whole-corpus result trees.

WHY THIS EXISTS
    The corpus drivers (e.g. reports/v123_raw/v123_run.sh, cmp_one) compare
    exactly two things per entry:

        (accepted, sorted(killed_by_all))

    and print SAME / CHANGED from that.  So a driver "SAME" means only
    "the verdict and the killing mutants are the same".  It says nothing
    about the other ~330 fields in the result JSON.  Predictions that claim
    "nothing else moved either" (decision 46 / v125, decision 47 B' / v126)
    need a different instrument.  This is that instrument.

WHAT IT DOES
    Matches <new_dir>/<profile>/*.json against <old_dir>/<profile>/*.json by
    file name, and for every name present on BOTH sides walks the two JSON
    documents to the leaves and reports every difference as a JSON path
    (check4.survivors[0], check6.explained[3].by_where) with old -> new.
    Names present on one side only are listed, never diffed.

    Volatile fields (wall clock, per-gate cost, machine uptime, run-scoped
    absolute paths) are ignored by default -- see DEFAULT_IGNORES, each entry
    carries the evidence for why it is volatile.

    Verdict-bearing fields are NEVER ignored (see PROTECT_*).  An --ignore that
    would hit one is refused for that path and the refusal is printed, so a
    real movement can never be silently argued away by a clever ignore list.

THREE OUTCOMES, NOT TWO
    Ignoring a field hides it.  Two kinds of movement must NOT be hidden and
    must NOT be counted as a change either, so they get their own category:
    they are ALWAYS printed, in full, in their own block, and are not counted
    in `differing`.

      budget-volatile (BUDGET_VOLATILE)
          check9.n_settings_reached / check9.n_oracle_runs /
          check9.n_settings_held / check9.coverage_note.
          MEASURED (v118 vs v123): 75/84 entries moved here, 28-59 settings
          reached on identical code; these track machine load, not the patch.
          They are protected n_* counts, so they could not be ignored even on
          request -- and they should not be: they are printed with old -> new,
          every one of them, and left out of the count.
          Under --no-default-ignore (audit mode) they are counted as ordinary
          differences again: an audit shows everything.
          Only a VALUE move is folded here.  An added / removed / type change
          at one of those paths is a schema change, not budget noise, and stays
          counted.

      reordered, set-valued (SET_VALUED_LISTS)
          r5_runs[].new_fail and suite_regression.by_seed[*] -- the R5 failure
          sets.  A set written as a JSON list has no meaningful order, so the
          same members in a different order is the same value (MEASURED: the
          only such movement in v118 vs v123 is strict/M2_reset_all, both
          paths, identical members).  Order inside ANY OTHER list is still a
          difference, as before.
          check4.survivors / check4.survivors_reached /
          check4.survivors_unreached -- added 2026-09-20 after v129: StrykerJS
          reports survivors in worker-completion order (MEASURED v129 vs v128,
          S16_scrypt_cost: same multiset, first two swapped).  The surviving
          mutants of one run are a SET; which worker finished first is not a
          fact about the patch.  survivors_reached[] holds dicts
          ({file,start_row,operator,note,raw}), so members are compared by
          canonical value (json.dumps(sort_keys=True)), not by position.
          This category stays folded in audit mode as well: set equality is a
          fact about the value, not a suppression of volatility.

    An entry that moved only in these categories is reported as
    budget-volatile-only / reordered-only, never as `differing`.

EXIT CODE
    Always 0.  The verdict is for a human to read (HANDOFF §0-h: do not put
    meaning into exit codes of reporting tools).

USAGE
    python deepdiff_results.py <new_dir> <old_dir> [options]

      --ignore FIELD        ignore this field (repeatable).  FIELD is a dotted
                            path ("check4.survivors") or a bare key name
                            ("elapsed_s") which then matches at any depth.
      --profile strict|fast|both      default: both
      --json OUT.json       also write the machine-readable report
      --no-default-ignore   compare the volatile fields too, AND count the
                            budget-volatile category as ordinary differences
                            (audit mode)
      --no-value-normalize  do not fold timestamps / pids / run-scoped paths
                            inside string values (alias: --no-path-normalize)
      --show-same           list the identical entries as well (and the
                            entries that moved only in a folded category)
      --max-diffs N         at most N diffs printed per entry (default 40;
                            0 = no limit).  Applies to COUNTED diffs only:
                            the budget-volatile and reordered blocks are
                            never capped.  The JSON report is never capped.
      --list-ignores        print the effective ignore list, the budget-volatile
                            paths and the set-valued lists, then exit

    Both <dir>s are expected to look like reports/vNNN_raw/ : a strict/ and a
    fast/ subdirectory of NAME.json files.  A missing profile directory is
    reported, not fatal.

SUMMARY LINE
    compared / identical / differing / budget-volatile-only / reordered-only /
    only_in_new / only_in_old, and they close:

        identical + budget-volatile-only + reordered-only
                  + both-categories + differing == compared

    `identical` means every field matched, verdict fields included (nothing
    was folded for that entry either).  `both-categories` is an entry that
    moved in the budget-volatile AND the reordered category and nowhere else;
    it is listed in both blocks.  The same split is written to --json under
    "counts" and per entry under "category".
"""

import io
import json
import os
import re
import sys

VERSION = 3          # v3: check4.survivors* are set-valued too (dict members)

# ---------------------------------------------------------------------------
# Default ignore list.
#
# Every entry below was picked by reading the real JSONs (reports/v118_raw and
# reports/v123_raw, 168 files, 335 distinct key names) and keeping only fields
# that CANNOT be stable between two runs of the same code: wall-clock seconds,
# process uptime, and free-text tails of a subprocess that embed timings.
#
# Deliberately NOT here, although the brief suggested them:
#   t_baseline  -- the only key containing it is check4.asconst_t_baseline, and
#                  it is a RESULT ({ok, n, failed, names, exit}: did the test
#                  suite pass on the as-const-stripped tree), not a duration.
#   vitest_runs -- the only key is check4.asconst_vitest_runs, a COUNT of
#                  vitest invocations.  A count that moves is a real change in
#                  what the gate did; it is cheap to see and must be seen.
#   timeout / no_coverage / errors -- check4 mutant outcomes, not durations.
#   start_row   -- a source line number in check4.survivors*, not a timestamp.
#   started/finished/when/timestamp -- no such key exists in these results;
#                  they are listed anyway so the list survives a schema that
#                  starts emitting them.
# ---------------------------------------------------------------------------
DEFAULT_IGNORES = [
    # whole subtree: per-gate wall clock, written by the driver
    "cost_s",
    # per-gate wall clock inside the gate's own block
    "elapsed_s",         # check4 / check5 / check6 / check7 / check8 / check9 / check12 / check13
    "elapsed_s_wall",    # check8
    "asconst_elapsed_s",  # check4 as-const pass
    "asconst_stryker_s",  # check4 as-const pass, StrykerJS subprocess time
    "driver_s",          # check5
    "sweep_secs",        # check8
    "secs",              # check8.classes.<K>.secs
    "node_uptime_s",     # check8: process uptime, volatile by construction
    # timestamps: not emitted today, kept so a future schema is covered
    "started", "finished", "when", "timestamp", "ts", "started_at", "finished_at",
]

# Free-text subprocess tails.  NOT ignored by default: they can carry the only
# evidence of a gate that could not run.  Named here so --ignore can reach them
# in one word when a run is known to differ only in a progress bar.
NOISY_TEXT = ["stryker_stdout_tail", "stryker_stderr_tail"]

# ---------------------------------------------------------------------------
# Budget-volatile.  NOT an ignore: these are printed in full, with old -> new,
# in their own block, and left out of the `differing` count.
#
# MEASURED (v118 vs v123, 84 entries compared on identical corpus code):
#   75/84 entries moved ONLY here.  n_settings_reached went 56/57 -> 28..59,
#   i.e. 検査9's time budget ran out at a different place because the machine
#   was differently loaded.  Same code, same verdict, different number.
#   Counting that as a change makes every rerun look like a regression;
#   ignoring it makes a real coverage collapse invisible.  So: print, do not
#   count.
#
# Only a VALUE move is folded (see Differ.classify): an added / removed / type
# change at these paths is a schema change and stays counted.
#
# --no-default-ignore (audit mode) counts these as ordinary differences.
# ---------------------------------------------------------------------------
BUDGET_VOLATILE = [
    "check9.n_settings_reached",   # how far the sweep got before the budget ended
    "check9.n_oracle_runs",        # one run per reached setting (+1)
    "check9.n_settings_held",      # of the reached settings, how many held
    "check9.coverage_note",        # the prose twin of n_settings_reached
]

# ---------------------------------------------------------------------------
# Set-valued lists: JSON lists whose order carries no meaning.  Same members in
# a different order is the SAME value -- printed in its own block, not counted.
#
# MEASURED (v118 vs v123): the only reordering in the whole comparison is
# strict/M2_reset_all, r5_runs[0].new_fail and suite_regression.by_seed["11"],
# identical members both times (the R5 failure set; vitest reports failures in
# completion order, which is not stable between runs).
#
# A pattern matches as a contiguous run of KEY segments, list indices dropped,
# so "r5_runs.new_fail" covers r5_runs[i].new_fail for every i and
# "suite_regression.by_seed" covers by_seed["11"], by_seed["22"], ...
# Order inside any list NOT named here is still a difference.
#
# Members are compared as a MULTISET of canonical forms
# (json.dumps(el, sort_keys=True), see same_multiset), so a set-valued list may
# hold dicts, not only strings.  A list NOT named here keeps the old, narrower
# rule (scalar members only): folding a dict list by value everywhere would
# rewrite conclusions already drawn from this tool (v126's 72 by_where entries),
# and set equality is a claim about a NAMED field, not about lists in general.
# ---------------------------------------------------------------------------
SET_VALUED_NOTE_V3 = (
    "added 2026-09-20 after v129: StrykerJS reports survivors in "
    "worker-completion order (MEASURED v129 vs v128, S16_scrypt_cost: "
    "same multiset, first two swapped)")

SET_VALUED_LISTS = [
    "r5_runs.new_fail",
    "suite_regression.by_seed",
    "check4.survivors",             # the reported survivor lines (strings)
    "check4.survivors_reached",     # dicts: {file,start_row,operator,note,raw}
    "check4.survivors_unreached",   # same shape, the unreached remainder
]

# Why a pattern is in the list, printed by --list-ignores.
SET_VALUED_WHY = {
    "r5_runs.new_fail":
        "R5 failure set; vitest reports failures in completion order "
        "(MEASURED v118 vs v123, strict/M2_reset_all).",
    "suite_regression.by_seed":
        "same R5 failure set, per seed (MEASURED v118 vs v123, "
        "strict/M2_reset_all).",
    "check4.survivors": SET_VALUED_NOTE_V3,
    "check4.survivors_reached": SET_VALUED_NOTE_V3 + "; members are dicts, "
        "compared by canonical value.",
    "check4.survivors_unreached": SET_VALUED_NOTE_V3 + "; same shape as "
        "survivors_reached (empty in every v128/v129 result).",
}

# ---------------------------------------------------------------------------
# Protected: verdict-bearing fields.  No ignore, default or user-supplied,
# can remove these from the comparison.
# ---------------------------------------------------------------------------
PROTECT_EXACT = {
    "accepted", "escalated", "errored_gates", "gates",
    "pass", "mutants", "killed", "survived", "reason",
    "timeout", "no_coverage", "errors", "verdict",
    "R4", "R5", "r4", "r5",
}
PROTECT_PREFIX = ("killed_by", "n_")


def seg_keys(segs):
    """The string segments of a path (list indices dropped)."""
    return [s for s in segs if isinstance(s, str)]


def is_protected(segs):
    keys = seg_keys(segs)
    if not keys:
        return False
    for k in keys:
        if k in ("gates",):          # the whole verdict map
            return True
    last = keys[-1]
    if last in PROTECT_EXACT:
        return True
    for p in PROTECT_PREFIX:
        if last.startswith(p):
            return True
    return False


def subtree_has_protected(value, segs):
    """True if segs itself, or any leaf below `value`, is protected."""
    if is_protected(segs):
        return True
    if isinstance(value, dict):
        for k, v in value.items():
            if subtree_has_protected(v, segs + [k]):
                return True
    elif isinstance(value, list):
        for i, v in enumerate(value):
            if subtree_has_protected(v, segs + [i]):
                return True
    return False


# ---------------------------------------------------------------------------
# Ignore matching.  A pattern is a dotted path split into segments; it matches
# when its segments appear as a contiguous run inside the path's key segments.
# So "cost_s" matches cost_s and everything under it, "elapsed_s" matches
# check4.elapsed_s and check12.elapsed_s, and "check4.ranges" matches only the
# ranges under check4.
# A pattern containing "/" is treated as ONE segment (result JSONs use test
# file paths as object keys: check2_detail["src/lib/anchor-c.vforacle.test.ts"]).
# ---------------------------------------------------------------------------
def parse_pattern(p):
    if "/" in p or "\\" in p:
        return [p]
    return [s for s in p.split(".") if s]


def pattern_matches(pat_segs, path_keys):
    n, m = len(pat_segs), len(path_keys)
    if n == 0 or n > m:
        return False
    for i in range(m - n + 1):
        if path_keys[i:i + n] == pat_segs:
            return True
    return False


# ---------------------------------------------------------------------------
# Run-scoped tokens inside string VALUES.  Two runs of the same corpus at a
# different wall-clock time, in a different clone / temp directory, produce
# strings that differ only by that token.  Folding the token is not the same as
# ignoring the field: the REST of the string is still compared, and every fold
# is counted in the summary.
#
# MEASURED on v118_raw vs v123_raw:
#   * the HH:MM:SS (pid) stamp is the ONLY difference in the 4 differing
#     check4.stryker_stdout_tail values -- the error text under it is identical
#     ("ERROR DryRunExecutor ... failed in the initial test run").  Without this
#     normalizer those 4 read as content changes, which they are not.
#   * no /tmp, no .img, no scratch dir and no clone dir occurs anywhere in the
#     168 result files, so those rules fold nothing today.  They are here so a
#     run made in a scratch clone is still comparable.
# ---------------------------------------------------------------------------
VALUE_NORMALIZERS = [
    # StrykerJS / node logger prefix: "\x1b[91m14:13:32 (852652) ERROR ..."
    # NOTE: no \b in front -- the stamp is preceded by the ANSI escape "…[91m",
    # and m|1 is not a word boundary, so \b never matched (caught on v118/v123).
    (re.compile(r"(?<![\d:])\d{2}:\d{2}:\d{2}(?:\.\d+)? \(\d+\)"), "<TIME> (<PID>)"),
    # bare wall clock and ISO timestamps
    (re.compile(r"(?<!\d)\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"), "<TS>"),
    (re.compile(r"/tmp/[A-Za-z0-9._\-]+"), "/tmp/<RUN>"),
    (re.compile(r"[A-Za-z]:\\\\?[Tt]emp\\[A-Za-z0-9._\-]+"), "<TEMP>\\<RUN>"),
    (re.compile(r"\.stryker-tmp[/\\][A-Za-z0-9._\-]+"), ".stryker-tmp/<RUN>"),
    (re.compile(r"[A-Za-z0-9._\-]*scratch[A-Za-z0-9._\-]*"), "<SCRATCH>"),
    (re.compile(r"[A-Za-z0-9._\-/\\]+\.img\b"), "<IMG>"),
    (re.compile(r"clone[_\-][0-9]+"), "clone_<N>"),
    (re.compile(r"\b[0-9a-f]{12,}\b"), "<HEX>"),
]


def normalize_value(s):
    for rx, rep in VALUE_NORMALIZERS:
        s = rx.sub(rep, s)
    return s


# ---------------------------------------------------------------------------
# Advisory notes.  These paths are NOT ignored (several of them are protected
# n_* counts and could not be ignored even on request) -- they are annotated in
# the frequency table so a reader does not mistake a budget artefact for a
# behaviour change.
# ---------------------------------------------------------------------------
ADVISORY = {
    "check9.n_settings_reached": "検査9 is time-budgeted: this is how far the sweep got before the budget ran out, i.e. machine speed/load, not the patch (MEASURED v118 57 -> v123 28 on 75 of 84 entries).",
    "check9.n_settings_held": "same budget truncation as n_settings_reached.",
    "check9.n_oracle_runs": "same budget truncation: one run per reached setting (+1).",
    "check9.coverage_note": "the prose twin of n_settings_reached; moves with it.",
    "check8.n_candidates_tried": "検査8 sweeps under a time budget as well; check before reading a change here as behaviour.",
    "check12.n_driver_runs": "検査12 is budgeted too.",
}


# ---------------------------------------------------------------------------
# Path rendering
# ---------------------------------------------------------------------------
PLAIN_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def render(segs):
    out = []
    for s in segs:
        if isinstance(s, int):
            out.append("[%d]" % s)
        elif PLAIN_KEY.match(s):
            out.append(("." if out else "") + s)
        else:
            out.append('["%s"]' % s.replace('"', '\\"'))
    return "".join(out) or "<root>"


def render_norm(segs):
    """Same, with list indices collapsed -- used for the frequency table."""
    out = []
    for s in segs:
        if isinstance(s, int):
            out.append("[]")
        elif PLAIN_KEY.match(s):
            out.append(("." if out else "") + s)
        else:
            out.append('["%s"]' % s.replace('"', '\\"'))
    return "".join(out) or "<root>"


def brief(v, n=80):
    if isinstance(v, str):
        s = v
    else:
        try:
            s = json.dumps(v, ensure_ascii=False, sort_keys=True)
        except Exception:
            s = repr(v)
    s = s.replace("\n", "\\n").replace("\r", "\\r")
    return s if len(s) <= n else s[:n] + "…"


def clip(v, n=2000):
    """Full-ish value for the JSON report."""
    if isinstance(v, str) and len(v) > n:
        return v[:n] + "…[+%d chars]" % (len(v) - n)
    return v


def same_scalar(a, b):
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def canon(v):
    """Canonical string for ONE list member, for multiset comparison.

    json.dumps(..., sort_keys=True) so that a dict member compares by VALUE and
    not by key order: check4.survivors_reached[] is
    {file,start_row,operator,note,raw}, and two runs may serialise the same
    mutant in a different slot of the list.  repr() would have worked for the
    string lists only, which is why v2 could not fold survivors_reached.
    """
    try:
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    except Exception:
        return repr(v)


def same_multiset(a, b):
    """Same members, any order (duplicates counted)."""
    if len(a) != len(b):
        return False
    try:
        return sorted(canon(x) for x in a) == sorted(canon(x) for x in b)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# The diff walk
# ---------------------------------------------------------------------------
class Differ(object):
    def __init__(self, ignores, normalize, budget_volatile=None,
                 set_valued=None, count_budget_volatile=False):
        self.ignores = ignores            # list of (raw, segs)
        self.normalize = normalize
        # list of (raw, segs); folded into their own category, never hidden
        self.budget = [(p, parse_pattern(p)) for p in (budget_volatile or [])]
        self.setval = [(p, parse_pattern(p)) for p in (set_valued or [])]
        self.count_budget_volatile = count_budget_volatile   # audit mode
        self.n_suppressed_ignore = 0
        self.n_suppressed_valuenorm = 0
        self.n_budget = 0
        self.n_reordered_set = 0
        self.rescued = {}                 # raw pattern -> set of protected paths

    def classify(self, segs, kind):
        """'budget' / 'reordered' / 'diff' -- which bucket this movement is in.

        'budget' and 'reordered' are printed in full but not counted; see the
        module docstring (THREE OUTCOMES, NOT TWO).
        """
        keys = seg_keys(segs)
        if kind == "value" and not self.count_budget_volatile:
            for _raw, pat in self.budget:
                if pattern_matches(pat, keys):
                    return "budget"
        if kind == "reordered" and self.is_set_valued(segs):
            return "reordered"
        return "diff"

    def is_set_valued(self, segs):
        """True if this path is one of SET_VALUED_LISTS (order carries no
        meaning).  Used twice: to allow dict members to be folded at all, and
        to put the movement in the `reordered` bucket."""
        keys = seg_keys(segs)
        for _raw, pat in self.setval:
            if pattern_matches(pat, keys):
                return True
        return False

    def ignored(self, segs, value_for_protect_scan=None):
        keys = seg_keys(segs)
        hit = None
        for raw, pat in self.ignores:
            if pattern_matches(pat, keys):
                hit = raw
                break
        if hit is None:
            return False
        if value_for_protect_scan is not None:
            prot = subtree_has_protected(value_for_protect_scan, segs)
        else:
            prot = is_protected(segs)
        if prot:
            self.rescued.setdefault(hit, set()).add(render(segs))
            return False
        return True

    def emit(self, out, segs, kind, old, new, value_for_protect_scan=None):
        if self.ignored(segs, value_for_protect_scan):
            self.n_suppressed_ignore += 1
            return
        if (self.normalize and kind == "value"
                and isinstance(old, str) and isinstance(new, str)
                and normalize_value(old) == normalize_value(new)):
            self.n_suppressed_valuenorm += 1
            return
        cat = self.classify(segs, kind)
        if cat == "budget":
            self.n_budget += 1
        elif cat == "reordered":
            self.n_reordered_set += 1
        out.append({"path": render(segs), "norm": render_norm(segs),
                    "kind": kind, "cat": cat, "old": old, "new": new})

    def walk(self, new, old, segs, out):
        if isinstance(old, dict) and isinstance(new, dict):
            for k in sorted(set(old) | set(new)):
                if k not in new:
                    self.emit(out, segs + [k], "removed", old[k], None,
                              value_for_protect_scan=old[k])
                elif k not in old:
                    self.emit(out, segs + [k], "added", None, new[k],
                              value_for_protect_scan=new[k])
                else:
                    self.walk(new[k], old[k], segs + [k], out)
            return
        if isinstance(old, list) and isinstance(new, list):
            if old == new:
                return
            # "same members, different order".  Members are canonicalized with
            # json.dumps(sort_keys=True) (see same_multiset), so this also
            # works for a list of dicts -- but a dict list is only folded when
            # the path is named in SET_VALUED_LISTS.  Anywhere else the old
            # rule stands (scalar members only), so no earlier conclusion of
            # this tool changes.  Whether the movement is then COUNTED is
            # classify()'s decision, unchanged: reordering outside
            # SET_VALUED_LISTS is still an ordinary difference.
            scalarish = all(not isinstance(x, (dict, list)) for x in old + new)
            if (scalarish or self.is_set_valued(segs)) and same_multiset(old, new):
                self.emit(out, segs, "reordered", old, new)
                return
            for i in range(max(len(old), len(new))):
                if i >= len(new):
                    self.emit(out, segs + [i], "removed", old[i], None,
                              value_for_protect_scan=old[i])
                elif i >= len(old):
                    self.emit(out, segs + [i], "added", None, new[i],
                              value_for_protect_scan=new[i])
                else:
                    self.walk(new[i], old[i], segs + [i], out)
            return
        if type(old) is not type(new) and not (
                isinstance(old, (int, float)) and isinstance(new, (int, float))
                and not isinstance(old, bool) and not isinstance(new, bool)):
            self.emit(out, segs, "type", old, new)
            return
        if not same_scalar(old, new):
            self.emit(out, segs, "value", old, new)


# ---------------------------------------------------------------------------
def load_json(path):
    with io.open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_results(d):
    if not os.path.isdir(d):
        return None
    return sorted(fn for fn in os.listdir(d) if fn.endswith(".json"))


def print_folded_block(entries, key, title, why):
    """Print one folded category in full: every entry, every path, old -> new.

    Nothing here is capped by --max-diffs.  A category that is deliberately
    left out of the count has to be visible in full, or it is just an ignore
    list with a friendlier name.
    """
    rows = [e for e in entries if e[key]]
    n_mov = sum(len(e[key]) for e in rows)
    print(title)
    print("   %s" % why)
    if not rows:
        print("   (none)")
        print("")
        return
    print("   %d entr%s, %d movement(s), none omitted:"
          % (len(rows), "y" if len(rows) == 1 else "ies", n_mov))
    tally = {}
    for e in rows:
        print("  [%s] %s" % (e["profile"], e["name"]))
        for d in e[key]:
            tally[d["norm"]] = tally.get(d["norm"], 0) + 1
            o, n = brief(d["old"], 200), brief(d["new"], 200)
            note = ""
            if isinstance(d["old"], list) and isinstance(d["new"], list):
                moved = [i for i in range(min(len(d["old"]), len(d["new"])))
                         if canon(d["old"][i]) != canon(d["new"][i])]
                note = "   (%d members, same set; %d slot(s) moved: %s)" % (
                    len(d["old"]), len(moved),
                    ", ".join("[%d]" % i for i in moved[:12])
                    + (" ..." if len(moved) > 12 else ""))
            if not note and len(o) <= 46 and len(n) <= 46:
                print("      %s: %s -> %s" % (d["path"], o, n))
            else:
                print("      %s%s" % (d["path"], note))
                print("          old: %s" % o)
                print("          new: %s" % n)
    print("   paths: %s"
          % ", ".join("%s x%d" % (p, c)
                      for p, c in sorted(tally.items(),
                                         key=lambda kv: (-kv[1], kv[0]))))
    print("")


def main(argv):
    new_dir = old_dir = None
    user_ignores = []
    profile = "both"
    json_out = None
    use_defaults = True
    normalize = True
    show_same = False
    max_diffs = 40
    list_only = False

    i = 0
    positional = []
    while i < len(argv):
        a = argv[i]
        if a == "--ignore":
            i += 1
            if i >= len(argv):
                print("--ignore needs a FIELD")
                return
            user_ignores.append(argv[i])
        elif a.startswith("--ignore="):
            user_ignores.append(a.split("=", 1)[1])
        elif a == "--profile":
            i += 1
            profile = argv[i] if i < len(argv) else "both"
        elif a.startswith("--profile="):
            profile = a.split("=", 1)[1]
        elif a == "--json":
            i += 1
            json_out = argv[i] if i < len(argv) else None
        elif a.startswith("--json="):
            json_out = a.split("=", 1)[1]
        elif a == "--no-default-ignore":
            use_defaults = False
        elif a in ("--no-path-normalize", "--no-value-normalize"):
            normalize = False
        elif a == "--show-same":
            show_same = True
        elif a == "--max-diffs":
            i += 1
            max_diffs = int(argv[i]) if i < len(argv) else 40
        elif a.startswith("--max-diffs="):
            max_diffs = int(a.split("=", 1)[1])
        elif a == "--list-ignores":
            list_only = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return
        elif a.startswith("-"):
            print("unknown option: %s  (see --help)" % a)
            return
        else:
            positional.append(a)
        i += 1

    if profile not in ("strict", "fast", "both"):
        print("--profile must be strict, fast or both (got %r)" % profile)
        return
    profiles = ["strict", "fast"] if profile == "both" else [profile]

    eff = (DEFAULT_IGNORES if use_defaults else []) + user_ignores
    if list_only:
        print("default ignores (%d):" % len(DEFAULT_IGNORES))
        for p in DEFAULT_IGNORES:
            print("   " + p)
        print("user ignores (%d):" % len(user_ignores))
        for p in user_ignores:
            print("   " + p)
        print("named but NOT ignored by default (pass --ignore to use): "
              + ", ".join(NOISY_TEXT))
        print("protected (never ignorable): "
              + ", ".join(sorted(PROTECT_EXACT))
              + " + any key starting with " + ", ".join(PROTECT_PREFIX))
        print("budget-volatile (%d) -- printed in full, not counted%s:"
              % (len(BUDGET_VOLATILE),
                 "" if use_defaults else "; COUNTED here (--no-default-ignore)"))
        for p in BUDGET_VOLATILE:
            print("   " + p)
        print("set-valued lists (%d) -- same members in another order is the "
              "same value, printed, not counted" % len(SET_VALUED_LISTS))
        print("   (members compared as a multiset of json.dumps(sort_keys=True)"
              " forms, so dict members work;")
        print("    stays folded under --no-default-ignore too: set equality is "
              "a fact about the value.)")
        for p in SET_VALUED_LISTS:
            print("   " + p)
            if p in SET_VALUED_WHY:
                print("         why: %s" % SET_VALUED_WHY[p])
        return

    if len(positional) != 2:
        print("usage: python deepdiff_results.py <new_dir> <old_dir> "
              "[--ignore FIELD ...] [--profile strict|fast|both] [--json out.json]")
        print("       (--help for the rest)")
        return

    new_dir, old_dir = positional
    # audit mode (--no-default-ignore): the budget-volatile category is counted
    # as an ordinary difference.  The set-valued reordering stays folded -- it
    # is a statement about the value, not a suppression of volatility.
    differ = Differ([(p, parse_pattern(p)) for p in eff], normalize,
                    budget_volatile=BUDGET_VOLATILE,
                    set_valued=SET_VALUED_LISTS,
                    count_budget_volatile=not use_defaults)

    entries = []
    only_new, only_old = [], []
    missing_dirs = []
    unreadable = []

    for prof in profiles:
        nd = os.path.join(new_dir, prof)
        od = os.path.join(old_dir, prof)
        ln, lo = list_results(nd), list_results(od)
        if ln is None:
            missing_dirs.append(nd)
        if lo is None:
            missing_dirs.append(od)
        if ln is None or lo is None:
            continue
        sn, so = set(ln), set(lo)
        for fn in sorted(sn - so):
            only_new.append("%s/%s" % (prof, fn))
        for fn in sorted(so - sn):
            only_old.append("%s/%s" % (prof, fn))
        for fn in sorted(sn & so):
            try:
                a = load_json(os.path.join(nd, fn))
            except Exception as e:
                unreadable.append("%s/%s (new): %s" % (prof, fn, e))
                continue
            try:
                b = load_json(os.path.join(od, fn))
            except Exception as e:
                unreadable.append("%s/%s (old): %s" % (prof, fn, e))
                continue
            diffs = []
            differ.walk(a, b, [], diffs)
            counted = [d for d in diffs if d["cat"] == "diff"]
            budget = [d for d in diffs if d["cat"] == "budget"]
            reord = [d for d in diffs if d["cat"] == "reordered"]
            if counted:
                category = "diff"
            elif budget and reord:
                category = "both"
            elif budget:
                category = "budget_volatile_only"
            elif reord:
                category = "reordered_only"
            else:
                category = "identical"
            entries.append({"profile": prof, "name": fn[:-5],
                            "file": fn, "n_diffs": len(counted),
                            "n_budget": len(budget), "n_reordered": len(reord),
                            "status": ("diff" if counted else
                                       "same" if category == "identical"
                                       else "folded"),
                            "category": category,
                            "diffs": diffs, "counted": counted,
                            "budget": budget, "reordered": reord})

    same = [e for e in entries if e["category"] == "identical"]
    diff = [e for e in entries if e["category"] == "diff"]
    bv_only = [e for e in entries if e["category"] == "budget_volatile_only"]
    ro_only = [e for e in entries if e["category"] == "reordered_only"]
    both = [e for e in entries if e["category"] == "both"]

    # the frequency table is about movements that COUNT; the folded categories
    # get their own blocks, printed in full, just above it.
    freq = {}
    for e in diff:
        for p in set(d["norm"] for d in e["counted"]):
            freq[p] = freq.get(p, 0) + 1
    freq_rows = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))

    # ---------------- human report ----------------
    W = "=" * 78
    print(W)
    print("deepdiff_results  new=%s" % os.path.abspath(new_dir))
    print("                  old=%s" % os.path.abspath(old_dir))
    print("profiles: %s   ignores: %d default%s + %d user   value-normalize: %s"
          % (", ".join(profiles), len(DEFAULT_IGNORES) if use_defaults else 0,
             "" if use_defaults else " (DISABLED)", len(user_ignores),
             "on" if normalize else "off"))
    print("folded (printed, not counted): budget-volatile %d path(s)%s, "
          "set-valued lists %d"
          % (len(BUDGET_VOLATILE),
             " (COUNTED: audit mode)" if differ.count_budget_volatile else "",
             len(SET_VALUED_LISTS)))
    print(W)
    for m in missing_dirs:
        print("!! missing profile directory: %s" % m)
    for m in unreadable:
        print("!! unreadable: %s" % m)

    for e in entries:
        if e["status"] != "diff":
            if show_same:
                extra = ""
                if e["status"] == "folded":
                    bits = []
                    if e["n_budget"]:
                        bits.append("budget-volatile %d" % e["n_budget"])
                    if e["n_reordered"]:
                        bits.append("reordered %d" % e["n_reordered"])
                    extra = "   (%s)" % ", ".join(bits)
                print("[%s] %-34s %s%s"
                      % (e["profile"], e["name"],
                         "SAME" if e["status"] == "same" else "NO COUNTED DIFF",
                         extra))
            continue
        folded = []
        if e["n_budget"]:
            folded.append("%d budget-volatile" % e["n_budget"])
        if e["n_reordered"]:
            folded.append("%d reordered" % e["n_reordered"])
        print("[%s] %-34s DIFF (%d)%s"
              % (e["profile"], e["name"], e["n_diffs"],
                 ("   [+%s, see the blocks below]" % ", ".join(folded))
                 if folded else ""))
        shown = e["counted"] if max_diffs == 0 else e["counted"][:max_diffs]
        for d in shown:
            k = d["kind"]
            if k == "added":
                print("    + %s" % d["path"])
                print("        new: %s" % brief(d["new"]))
            elif k == "removed":
                print("    - %s" % d["path"])
                print("        old: %s" % brief(d["old"]))
            elif k == "reordered":
                print("    ~ %s   (same members, different order)" % d["path"])
                print("        old: %s" % brief(d["old"]))
                print("        new: %s" % brief(d["new"]))
            else:
                print("    %s %s" % ("!" if k == "type" else "~", d["path"]))
                print("        old: %s" % brief(d["old"]))
                print("        new: %s" % brief(d["new"]))
        if max_diffs and len(e["counted"]) > max_diffs:
            print("    ... %d more (raise --max-diffs, or read the --json)"
                  % (len(e["counted"]) - max_diffs))

    # ---- the two folded categories: always printed, never capped ----
    print_folded_block(
        entries, "budget",
        "-- budget-volatile (reported, not counted) --",
        "MEASURED (v118 vs v123): 75/84 entries moved here, 28-59 settings "
        "reached\n   on identical code; these track machine load, not the "
        "patch.\n   --no-default-ignore counts them as ordinary differences.")
    print_folded_block(
        entries, "reordered",
        "-- reordered (set-valued, not counted) --",
        "same members, different order, in a list whose order carries no "
        "meaning\n   (SET_VALUED_LISTS: %s).  Order in any other list is still "
        "a difference.\n   check4.survivors*: %s"
        % (", ".join(SET_VALUED_LISTS), SET_VALUED_NOTE_V3))

    print(W)
    print("compared: %d   identical: %d   differing: %d"
          % (len(entries), len(same), len(diff)))
    print("budget-volatile-only: %d   reordered-only: %d   both-categories: %d"
          % (len(bv_only), len(ro_only), len(both)))
    print("   %d + %d + %d + %d + %d = %d  (identical + budget-volatile-only + "
          "reordered-only + both + differing = compared)%s"
          % (len(same), len(bv_only), len(ro_only), len(both), len(diff),
             len(same) + len(bv_only) + len(ro_only) + len(both) + len(diff),
             "" if (len(same) + len(bv_only) + len(ro_only) + len(both)
                    + len(diff)) == len(entries) else "   !! DOES NOT CLOSE"))
    print("   identical = every field matched, verdict fields included, "
          "nothing folded.")
    if differ.count_budget_volatile:
        print("   AUDIT MODE (--no-default-ignore): budget-volatile is counted "
              "as an ordinary difference;")
        print("   set-valued reordering stays folded (set equality is a fact "
              "about the value).")
    print("only_in_new (%d): %s" % (len(only_new), ", ".join(only_new) or "-"))
    print("only_in_old (%d): %s" % (len(only_old), ", ".join(only_old) or "-"))
    print("suppressed: %d by the ignore list, %d by value normalization "
          "(timestamps / pids / run-scoped paths inside strings)"
          % (differ.n_suppressed_ignore, differ.n_suppressed_valuenorm))
    print("folded (printed above, not counted): %d budget-volatile, "
          "%d set-valued reordering"
          % (differ.n_budget, differ.n_reordered_set))
    if differ.rescued:
        print("REFUSED to ignore (verdict-bearing, compared anyway):")
        for raw in sorted(differ.rescued):
            ex = sorted(differ.rescued[raw])
            print("   pattern %-20s -> %d path(s), e.g. %s"
                  % (raw, len(ex), ", ".join(ex[:3])))
    print("-- paths that moved and COUNT (entries touched / path) --")
    if not freq_rows:
        print("   (none)")
    for p, c in freq_rows:
        print("  %5d  %s" % (c, p))
        if p in ADVISORY:
            print("         note: %s" % ADVISORY[p])
    print(W)

    if json_out:
        rep = {
            "tool": "deepdiff_results.py", "version": VERSION,
            "new_dir": os.path.abspath(new_dir),
            "old_dir": os.path.abspath(old_dir),
            "profiles": profiles,
            "ignores": {"default": DEFAULT_IGNORES if use_defaults else [],
                        "user": user_ignores,
                        "refused_protected": dict(
                            (k, sorted(v)) for k, v in differ.rescued.items())},
            "folded_categories": {
                "budget_volatile": BUDGET_VOLATILE,
                "budget_volatile_counted_as_diff":
                    differ.count_budget_volatile,
                "set_valued_lists": SET_VALUED_LISTS},
            "value_normalize": normalize,
            "counts": {"compared": len(entries), "identical": len(same),
                       "differing": len(diff),
                       "budget_volatile_only": len(bv_only),
                       "reordered_only": len(ro_only),
                       "both_folded_categories": len(both),
                       "only_in_new": len(only_new),
                       "only_in_old": len(only_old),
                       "suppressed_by_ignore": differ.n_suppressed_ignore,
                       "suppressed_by_value_normalize":
                           differ.n_suppressed_valuenorm,
                       "folded_budget_volatile": differ.n_budget,
                       "folded_reordered_set_valued":
                           differ.n_reordered_set},
            "only_in_new": only_new, "only_in_old": only_old,
            "missing_dirs": missing_dirs, "unreadable": unreadable,
            "path_frequency": [
                dict([("path", p), ("entries", c)]
                     + ([("note", ADVISORY[p])] if p in ADVISORY else []))
                for p, c in freq_rows],
            "entries": [
                {"profile": e["profile"], "name": e["name"],
                 "status": e["status"], "category": e["category"],
                 "n_diffs": e["n_diffs"],
                 "n_budget_volatile": e["n_budget"],
                 "n_reordered_set_valued": e["n_reordered"],
                 "diffs": [{"path": d["path"], "kind": d["kind"],
                            "category": ("budget_volatile" if d["cat"] == "budget"
                                         else "reordered_set_valued"
                                         if d["cat"] == "reordered" else "diff"),
                            "counted": d["cat"] == "diff",
                            "old": clip(d["old"]), "new": clip(d["new"])}
                           for d in e["diffs"]]}
                for e in entries],
        }
        try:
            with io.open(json_out, "w", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(rep, ensure_ascii=False, indent=1))
            print("wrote %s" % os.path.abspath(json_out))
        except Exception as e:
            print("!! could not write %s: %s" % (json_out, e))


if __name__ == "__main__":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                      errors="replace", line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8",
                                      errors="replace", line_buffering=True)
    except Exception:
        pass                       # already text-wrapped (some WSL pipelines)
    try:
        main(sys.argv[1:])
    except Exception:
        import traceback
        traceback.print_exc()
        print("deepdiff_results: crashed above; exit code is still 0 by design")
    sys.exit(0)                    # §0-h: no meaning in the exit code
