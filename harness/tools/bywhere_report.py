#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verified-fix -- tally and classify check6's `by_where` field (decision 47 B').

WHY THIS EXISTS
    check6 ("new literals must be explained") prints, per literal it accepted,
    WHO explained it (`by`).  Until v126 it did not print WHERE.  Decision
    47 B' added `by_where`, so for the first time we can ask the question that
    decision 47 D hangs on:

        how often is a NEW literal of the attack declared "already explained"
        by a test file that has nothing to do with the anchor being changed?

    That count -- `tests` records whose `by_where` lives in a DIFFERENT
    directory than the anchor file -- is the `unrelated` column below.  If it
    is ~0, explanation authority is already effectively per-anchor and D can
    stay closed.  If it is not, explanation authority is corpus-wide and D is
    real.

WHAT IT READS
    <results_dir>/strict/*.json and <results_dir>/fast/*.json, in the v126
    shape.  Each record of check6.explained[] is

        {file, line, kind, repr, keys, by, by_where?}

    `by_where` is attached ONLY to the addCode-borne sources
    (`oracle` / `tests` / `pre:*`).  It is NOT attached to `callsites`,
    to prose-borne sources (`inProse`: finding / docs), nor to `charwise`.
    Those are counted separately as "no-where" and are NOT a defect.
    (HANDOFF: "N < n_explained は正常".)

    Entry -> config is resolved from --cfg-dir by the entry name (the JSON
    `name`, else the file stem).  From the cfg it takes `anchor_file`,
    `oracle_files` and `repo`.

CLASSIFICATION (fixed by the owner -- do not "improve" it)
    by == "oracle"      -> oracle.  by_where is expected to be one of
                           cfg.oracle_files; if it is not, the record is ALSO
                           listed under `oracle-mismatch` (own block).
    by startswith "pre:" -> pre.
    by == "tests"       -> compare by_where against cfg.anchor_file:
                             anchor-own : same directory AND the by_where stem
                                          contains the anchor stem
                                          (anchor-c.ts  <-  anchor-c.test.ts,
                                           anchor-c.vforacle.test.ts,
                                           anchor-c.reasoncodes.vforacle.test.ts)
                             sibling    : same directory, different stem
                             unrelated  : different directory
                           Both repo-relative and absolute by_where occur, so
                           both sides are normalised against cfg.repo first.
    anything else       -> no-where (count only).

EXIT CODE
    Always 0.  The verdict is for a human to read (HANDOFF §0-h: do not put
    meaning into the exit code of a reporting tool).

USAGE
    python bywhere_report.py <results_dir> --cfg-dir <dir> [--cfg-dir <dir> ...]
                             [--json out.json] [--md out.md]
                             [--profile strict|fast|both] [--quiet-lists]

      --cfg-dir DIR      directory holding <name>.cfg.json (repeatable; the
                         first directory that defines a name wins, collisions
                         are reported)
      --profile          default: both
      --json OUT.json    machine-readable report with the same content
      --md OUT.md        Markdown report with sections 1-4
      --quiet-lists      suppress sections 3/4 on stdout only (the --json and
                         --md outputs always carry them in full)
"""

import io
import json
import os
import re
import sys

VERSION = 1

PROFILES = ("strict", "fast")
WIN_ABS = re.compile(r"^[A-Za-z]:/")


# ---------------------------------------------------------------------------
# path handling
# ---------------------------------------------------------------------------

def norm_slashes(p):
    """Forward slashes, collapsed, no leading './'.  None stays None."""
    if p is None:
        return None
    s = str(p).replace("\\", "/").strip()
    while "//" in s:
        s = s.replace("//", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def is_abs(s):
    return bool(s) and (s.startswith("/") or bool(WIN_ABS.match(s)))


def rel_to_repo(p, repo):
    """Normalise a path so repo-relative and absolute spellings compare equal.

    Returns (path, outside_repo).  `outside_repo` is True when the path is
    absolute and does not live under `repo` -- such a path is kept verbatim
    (stripping the root would fake a relative path and could fake a match).
    """
    s = norm_slashes(p)
    if s is None:
        return None, False
    if not is_abs(s):
        return s, False
    r = norm_slashes(repo)
    if r:
        r = r.rstrip("/")
        if s.startswith(r + "/"):
            return s[len(r) + 1:], False
        if s.lower().startswith(r.lower() + "/"):
            return s[len(r) + 1:], False
    return s, True


def dirname_of(s):
    s = s or ""
    i = s.rfind("/")
    return s[:i] if i >= 0 else ""


def basename_of(s):
    s = s or ""
    i = s.rfind("/")
    return s[i + 1:] if i >= 0 else s


def stem_of(s):
    """Basename with the LAST extension removed.

    anchor-c.ts                              -> anchor-c
    anchor-c.reasoncodes.vforacle.test.ts    -> anchor-c.reasoncodes.vforacle.test
    """
    b = basename_of(s)
    i = b.rfind(".")
    return b[:i] if i > 0 else b


def one_line(s, limit=0):
    t = "" if s is None else str(s)
    t = t.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    if limit and len(t) > limit:
        t = t[:limit - 3] + "..."
    return t


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def load_cfgs(cfg_dirs, problems):
    """name -> {'path':..., 'repo':..., 'anchor_file':..., 'oracle_files':[...]}"""
    cfgs = {}
    for d in cfg_dirs:
        if not os.path.isdir(d):
            problems.plain("cfg-dir missing: %s" % d)
            continue
        try:
            names = sorted(os.listdir(d))
        except Exception as e:
            problems.plain("cfg-dir unreadable: %s (%s)" % (d, e))
            continue
        for fn in names:
            if not fn.endswith(".cfg.json"):
                continue
            path = os.path.join(d, fn)
            stem = fn[:-len(".cfg.json")]
            try:
                with io.open(path, "r", encoding="utf-8") as fh:
                    j = json.load(fh)
            except Exception as e:
                problems.plain("cfg unreadable: %s (%s)" % (path, e))
                continue
            name = j.get("name") or stem
            rec = {
                "path": path,
                "name": name,
                "file_stem": stem,
                "repo": j.get("repo"),
                "anchor_file": j.get("anchor_file"),
                "oracle_files": list(j.get("oracle_files") or []),
            }
            for key in (name, stem):
                if key in cfgs:
                    if cfgs[key]["path"] != path:
                        problems.plain(
                            "cfg name collision for %r: keeping %s, ignoring %s"
                            % (key, cfgs[key]["path"], path))
                else:
                    cfgs[key] = rec
    return cfgs


def load_results(results_dir, profiles, problems):
    """-> list of (profile, entry_name, json_path, doc)"""
    out = []
    for prof in profiles:
        d = os.path.join(results_dir, prof)
        if not os.path.isdir(d):
            problems.plain("profile dir missing (not fatal): %s" % d)
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".json"):
                continue
            path = os.path.join(d, fn)
            try:
                with io.open(path, "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
            except Exception as e:
                problems.plain("result unreadable, skipped: %s (%s)"
                               % (path, e))
                continue
            name = doc.get("name") or fn[:-len(".json")]
            out.append((prof, name, path, doc))
    return out


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------

NOTE_CAP = 20          # per category, then "... and N more"


class Notes(object):
    """Problem log that caps each repeated category.

    A pre-v126 tree has NO by_where anywhere, which would otherwise emit one
    note per record (972 of them on v125_raw).  The cap keeps the signal of a
    real v126 anomaly readable without hiding that it happened.
    """

    def __init__(self):
        self.lines = []
        self.counts = {}

    def add(self, category, msg):
        n = self.counts.get(category, 0) + 1
        self.counts[category] = n
        if n <= NOTE_CAP:
            self.lines.append(msg)

    def plain(self, msg):
        self.lines.append(msg)

    def finish(self):
        out = list(self.lines)
        for cat in sorted(self.counts):
            n = self.counts[cat]
            if n > NOTE_CAP:
                out.append("... and %d more of category %r (capped at %d)"
                           % (n - NOTE_CAP, cat, NOTE_CAP))
        return out


def classify_tests(where_norm, outside, anchor_norm):
    """-> 'anchor-own' | 'sibling' | 'unrelated' | 'tests-no-where'"""
    if where_norm is None:
        return "tests-no-where"
    if anchor_norm is None:
        return "unrelated"      # no anchor to compare against: cannot be 'own'
    if outside:
        return "unrelated"
    if dirname_of(where_norm) != dirname_of(anchor_norm):
        return "unrelated"
    a_stem = stem_of(anchor_norm)
    w_stem = stem_of(where_norm)
    if a_stem and a_stem in w_stem:
        return "anchor-own"
    return "sibling"


def analyse(results, cfgs, problems):
    entries = []
    unrelated, sibling, mismatch = [], [], []
    tot = {
        "n_records": 0,
        "by_bucket": {"oracle": 0, "pre": 0, "tests": 0, "other": 0},
        "by_raw": {},
        "tests": {"anchor-own": 0, "sibling": 0, "unrelated": 0,
                  "tests-no-where": 0},
        "with_by_where": 0,
        "without_by_where": 0,
        "oracle_mismatch": 0,
        "oracle_no_where": 0,
        "oracle_no_cfg": 0,
        "unexpected_by_where": 0,
        "records_without_cfg": 0,
        "n_entries": 0,
        "n_entries_without_cfg": 0,
        "legacy_tree_no_by_where": False,
    }

    for prof, name, path, doc in results:
        c6 = doc.get("check6") or {}
        ex = c6.get("explained")
        if ex is None:
            ex = []
            if "check6" not in doc:
                problems.add("no-check6", "no check6 in %s" % path)
        cfg = cfgs.get(name)
        if cfg is None:
            cfg = cfgs.get(os.path.basename(path)[:-len(".json")])
        if cfg is None:
            problems.add("no-cfg",
                         "no cfg for entry %r (%s/%s)" % (name, prof, name))
            tot["n_entries_without_cfg"] += 1
            repo = anchor = None
            oracle_set = set()
        else:
            repo = cfg.get("repo")
            anchor, _out = rel_to_repo(cfg.get("anchor_file"), repo)
            oracle_set = set()
            for of in cfg.get("oracle_files") or []:
                o, _o2 = rel_to_repo(of, repo)
                if o:
                    oracle_set.add(o)

        row = {
            "entry": name, "profile": prof, "result_file": path,
            "cfg": (cfg or {}).get("path"),
            "repo": repo, "anchor_file": anchor,
            "oracle_files": sorted(oracle_set),
            "n_explained": len(ex),
            "oracle": 0, "pre": 0,
            "anchor-own": 0, "sibling": 0, "unrelated": 0,
            "no-where": 0,
            "oracle-mismatch": 0, "oracle-no-where": 0, "tests-no-where": 0,
            "unexpected-by-where": 0,
            "n_declared_by_where": (c6.get("n_by_where")
                                    if isinstance(c6.get("n_by_where"), int)
                                    else None),
        }

        for idx, r in enumerate(ex):
            if not isinstance(r, dict):
                problems.add("non-dict",
                             "non-dict explained[%d] in %s" % (idx, path))
                continue
            tot["n_records"] += 1
            by = r.get("by")
            by_s = "" if by is None else str(by)
            key = "pre:*" if by_s.startswith("pre:") else by_s
            tot["by_raw"][key] = tot["by_raw"].get(key, 0) + 1

            raw_where = r.get("by_where")
            has_where = raw_where not in (None, "")
            if has_where:
                tot["with_by_where"] += 1
            else:
                tot["without_by_where"] += 1
            where_norm, outside = rel_to_repo(raw_where, repo) if has_where else (None, False)

            item = {
                "entry": name, "profile": prof,
                "file": r.get("file"), "line": r.get("line"),
                "kind": r.get("kind"), "repr": r.get("repr"),
                "by": by, "by_where": raw_where,
                "by_where_norm": where_norm,
                "anchor_file": anchor,
                "outside_repo": outside,
                "index": idx,
            }
            if cfg is None:
                tot["records_without_cfg"] += 1

            if by_s == "oracle":
                row["oracle"] += 1
                tot["by_bucket"]["oracle"] += 1
                if cfg is None:
                    tot["oracle_no_cfg"] += 1
                elif not has_where:
                    # Expected on a pre-v126 tree; an anomaly on a v126 tree.
                    # Counted and noted, but kept OUT of the mismatch list so
                    # one missing field cannot bury a real value mismatch.
                    row["oracle-no-where"] += 1
                    tot["oracle_no_where"] += 1
                    problems.add(
                        "oracle-no-where",
                        "oracle record without by_where: %s/%s explained[%d] "
                        "(normal for a pre-v126 tree)" % (prof, name, idx))
                elif where_norm not in oracle_set:
                    row["oracle-mismatch"] += 1
                    tot["oracle_mismatch"] += 1
                    item["why"] = "by_where not in cfg.oracle_files"
                    mismatch.append(item)
            elif by_s.startswith("pre:"):
                row["pre"] += 1
                tot["by_bucket"]["pre"] += 1
            elif by_s == "tests":
                tot["by_bucket"]["tests"] += 1
                klass = classify_tests(where_norm, outside, anchor)
                tot["tests"][klass] += 1
                if klass == "anchor-own":
                    row["anchor-own"] += 1
                elif klass == "sibling":
                    row["sibling"] += 1
                    sibling.append(item)
                elif klass == "unrelated":
                    row["unrelated"] += 1
                    unrelated.append(item)
                else:
                    row["tests-no-where"] += 1
                    problems.add(
                        "tests-no-where",
                        "tests record without by_where: %s/%s explained[%d] "
                        "(normal for a pre-v126 tree)" % (prof, name, idx))
            else:
                row["no-where"] += 1
                tot["by_bucket"]["other"] += 1
                if has_where:
                    row["unexpected-by-where"] += 1
                    tot["unexpected_by_where"] += 1
                    problems.add(
                        "unexpected-by-where",
                        "by=%r carries by_where=%r (%s/%s explained[%d]) -- "
                        "schema note, not a defect of the corpus"
                        % (by, raw_where, prof, name, idx))

        tot["n_entries"] += 1
        entries.append(row)

    def sk(it):
        return (it["entry"], it["profile"], str(it.get("file")),
                it.get("line") if isinstance(it.get("line"), int) else -1)

    if tot["n_records"] > 0 and tot["with_by_where"] == 0:
        tot["legacy_tree_no_by_where"] = True

    unrelated.sort(key=sk)
    sibling.sort(key=sk)
    mismatch.sort(key=sk)
    entries.sort(key=lambda r: (r["entry"], r["profile"]))
    return entries, unrelated, sibling, mismatch, tot


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

TABLE_COLS = [
    ("entry", "name"),
    ("profile", "profile"),
    ("n_explained", "n_explained"),
    ("oracle", "oracle"),
    ("pre", "pre"),
    ("anchor-own", "anchor-own"),
    ("sibling", "sibling"),
    ("unrelated", "unrelated"),
    ("no-where", "no-where"),
]

LIST_COLS = [
    ("entry", "entry"),
    ("profile", "profile"),
    ("loc", "file:line"),
    ("kind", "kind"),
    ("repr", "repr"),
    ("by", "by"),
    ("by_where", "by_where"),
]


def loc_of(item):
    ln = item.get("line")
    return "%s:%s" % (one_line(item.get("file")), "?" if ln is None else ln)


def render_table(rows, cols, totals_row=None):
    data = []
    for r in rows:
        data.append([one_line(r.get(k, "")) for k, _h in cols])
    heads = [h for _k, h in cols]
    if totals_row is not None:
        data.append([one_line(totals_row.get(k, "")) for k, _h in cols])
    widths = [len(h) for h in heads]
    for row in data:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)
    out = []
    out.append("  ".join(h.ljust(widths[i]) for i, h in enumerate(heads)))
    out.append("  ".join("-" * widths[i] for i in range(len(heads))))
    for n, row in enumerate(data):
        if totals_row is not None and n == len(data) - 1:
            out.append("  ".join("-" * widths[i] for i in range(len(heads))))
        out.append("  ".join(row[i].ljust(widths[i]) for i in range(len(heads))))
    return "\n".join(out)


def md_table(rows, cols):
    heads = [h for _k, h in cols]
    out = ["| " + " | ".join(heads) + " |",
           "|" + "|".join("---" for _ in heads) + "|"]
    for r in rows:
        cells = []
        for k, _h in cols:
            v = one_line(r.get(k, ""))
            cells.append(v.replace("|", "\\|"))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def list_rows(items):
    rows = []
    for it in items:
        rows.append({
            "entry": it["entry"],
            "profile": it["profile"],
            "loc": loc_of(it),
            "kind": it.get("kind"),
            "repr": one_line(it.get("repr")),
            "by": it.get("by"),
            "by_where": one_line(it.get("by_where")),
        })
    return rows


def totals_row_of(entries):
    t = {"entry": "TOTAL (%d rows)" % len(entries), "profile": ""}
    for k in ("n_explained", "oracle", "pre", "anchor-own", "sibling",
              "unrelated", "no-where"):
        t[k] = sum(int(e.get(k) or 0) for e in entries)
    return t


def section1_lines(tot):
    L = []
    if tot["legacy_tree_no_by_where"]:
        L.append("!! THIS TREE CARRIES NO by_where AT ALL (%d records) -- "
                 "pre-v126 shape." % tot["n_records"])
        L.append("   The tests split below is therefore empty by construction, "
                 "not by measurement.")
        L.append("")
    L.append("1. OVERALL")
    L.append("   explained records            : %d" % tot["n_records"])
    L.append("   entries (result files)       : %d  (without cfg: %d)"
             % (tot["n_entries"], tot["n_entries_without_cfg"]))
    L.append("   by bucket  oracle / pre / tests / other :  %d / %d / %d / %d"
             % (tot["by_bucket"]["oracle"], tot["by_bucket"]["pre"],
                tot["by_bucket"]["tests"], tot["by_bucket"]["other"]))
    L.append("   raw `by` values:")
    for k in sorted(tot["by_raw"], key=lambda x: (-tot["by_raw"][x], x)):
        L.append("       %-24s %d" % (k, tot["by_raw"][k]))
    L.append("   tests classification:")
    L.append("       anchor-own           %d" % tot["tests"]["anchor-own"])
    L.append("       sibling              %d" % tot["tests"]["sibling"])
    L.append("       unrelated            %d   <== decision 47 D material"
             % tot["tests"]["unrelated"])
    L.append("       (tests w/o by_where) %d" % tot["tests"]["tests-no-where"])
    L.append("   by_where present / absent    : %d / %d"
             % (tot["with_by_where"], tot["without_by_where"]))
    L.append("       absent is EXPECTED for callsites / inProse / charwise "
             "(not a defect)")
    L.append("   oracle-mismatch (wrong file) : %d%s"
             % (tot["oracle_mismatch"],
                "  (no cfg to check: %d)" % tot["oracle_no_cfg"]
                if tot["oracle_no_cfg"] else ""))
    L.append("   oracle without by_where      : %d%s"
             % (tot["oracle_no_where"],
                "   (expected: pre-v126 tree)"
                if tot["legacy_tree_no_by_where"] else ""))
    if tot["unexpected_by_where"]:
        L.append("   by_where on a non-addCode source: %d  (schema note)"
                 % tot["unexpected_by_where"])
    return L


def report_stdout(results_dir, cfg_dirs, entries, unrelated, sibling,
                  mismatch, tot, problems, quiet_lists):
    print("bywhere_report v%d" % VERSION)
    print("results_dir : %s" % results_dir)
    print("cfg_dirs    : %s" % ", ".join(cfg_dirs))
    print("")
    for line in section1_lines(tot):
        print(line)
    print("")
    print("2. PER ENTRY (one row per entry x profile)")
    if entries:
        print(render_table(entries, TABLE_COLS, totals_row_of(entries)))
    else:
        print("   (no entries)")
    print("")
    print("3. UNRELATED -- tests in a DIFFERENT directory than the anchor "
          "(%d, full list)" % len(unrelated))
    if not unrelated:
        print("   (none)")
    elif quiet_lists:
        print("   (suppressed by --quiet-lists; see --json / --md)")
    else:
        print(render_table(list_rows(unrelated), LIST_COLS))
    print("")
    print("4. SIBLING -- tests in the SAME directory, different stem "
          "(%d, full list)" % len(sibling))
    if not sibling:
        print("   (none)")
    elif quiet_lists:
        print("   (suppressed by --quiet-lists; see --json / --md)")
    else:
        print(render_table(list_rows(sibling), LIST_COLS))
    if mismatch:
        print("")
        print("4b. ORACLE-MISMATCH -- by=='oracle' whose by_where is not in "
              "cfg.oracle_files (%d, full list)" % len(mismatch))
        rows = list_rows(mismatch)
        for i, it in enumerate(mismatch):
            rows[i]["why"] = it.get("why")
        print(render_table(rows, LIST_COLS + [("why", "why")]))
    if problems:
        print("")
        print("NOTES / PROBLEMS (%d)" % len(problems))
        for p in problems:
            print("   !! %s" % p)
    print("")
    print("exit code is 0 by design (HANDOFF §0-h)")


def report_md(path, results_dir, cfg_dirs, entries, unrelated, sibling,
              mismatch, tot, problems):
    L = []
    L.append("# by_where report (check6 / decision 47 B')")
    L.append("")
    L.append("- `results_dir`: `%s`" % results_dir)
    L.append("- `cfg_dirs`: %s" % ", ".join("`%s`" % d for d in cfg_dirs))
    L.append("")
    L.append("## 1. Overall")
    L.append("")
    L.append("| metric | value |")
    L.append("|---|---|")
    L.append("| explained records | %d |" % tot["n_records"])
    L.append("| entries (result files) | %d (without cfg: %d) |"
             % (tot["n_entries"], tot["n_entries_without_cfg"]))
    L.append("| by = oracle | %d |" % tot["by_bucket"]["oracle"])
    L.append("| by = pre:* | %d |" % tot["by_bucket"]["pre"])
    L.append("| by = tests | %d |" % tot["by_bucket"]["tests"])
    L.append("| by = other (no-where) | %d |" % tot["by_bucket"]["other"])
    L.append("| tests / anchor-own | %d |" % tot["tests"]["anchor-own"])
    L.append("| tests / sibling | %d |" % tot["tests"]["sibling"])
    L.append("| **tests / unrelated** | **%d** |" % tot["tests"]["unrelated"])
    L.append("| tests without by_where | %d |" % tot["tests"]["tests-no-where"])
    L.append("| by_where present | %d |" % tot["with_by_where"])
    L.append("| by_where absent (expected for callsites / inProse / charwise) | %d |"
             % tot["without_by_where"])
    L.append("| oracle-mismatch (by_where not in cfg.oracle_files) | %d |"
             % tot["oracle_mismatch"])
    L.append("| oracle without by_where | %d |" % tot["oracle_no_where"])
    L.append("")
    if tot["legacy_tree_no_by_where"]:
        L.append("> **This tree carries no `by_where` at all (pre-v126 shape).**"
                 " The `tests` split is empty by construction, not by"
                 " measurement.")
        L.append("")
    L.append("Raw `by` values:")
    L.append("")
    L.append("| by | n |")
    L.append("|---|---|")
    for k in sorted(tot["by_raw"], key=lambda x: (-tot["by_raw"][x], x)):
        L.append("| `%s` | %d |" % (k, tot["by_raw"][k]))
    L.append("")
    L.append("## 2. Per entry")
    L.append("")
    rows = list(entries) + [totals_row_of(entries)]
    L.append(md_table(rows, TABLE_COLS))
    L.append("")
    L.append("## 3. unrelated (tests in a different directory than the anchor) -- %d"
             % len(unrelated))
    L.append("")
    L.append(md_table(list_rows(unrelated), LIST_COLS) if unrelated else "(none)")
    L.append("")
    L.append("## 4. sibling (same directory, different stem) -- %d" % len(sibling))
    L.append("")
    L.append(md_table(list_rows(sibling), LIST_COLS) if sibling else "(none)")
    if mismatch:
        rows = list_rows(mismatch)
        for i, it in enumerate(mismatch):
            rows[i]["why"] = it.get("why")
        L.append("")
        L.append("## 4b. oracle-mismatch -- %d" % len(mismatch))
        L.append("")
        L.append(md_table(rows, LIST_COLS + [("why", "why")]))
    if problems:
        L.append("")
        L.append("## Notes / problems (%d)" % len(problems))
        L.append("")
        for p in problems:
            L.append("- %s" % p)
    L.append("")
    try:
        with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(L))
        print("wrote markdown: %s" % path)
    except Exception as e:
        print("!! could not write %s: %s" % (path, e))


def report_json(path, results_dir, cfg_dirs, entries, unrelated, sibling,
                mismatch, tot, problems):
    doc = {
        "tool": "bywhere_report",
        "version": VERSION,
        "results_dir": results_dir,
        "cfg_dirs": list(cfg_dirs),
        "totals": tot,
        "entries": entries,
        "unrelated": unrelated,
        "sibling": sibling,
        "oracle_mismatch": mismatch,
        "problems": problems,
    }
    try:
        with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(doc, ensure_ascii=False, indent=1,
                                sort_keys=True))
            fh.write("\n")
        print("wrote json: %s" % path)
    except Exception as e:
        print("!! could not write %s: %s" % (path, e))


# ---------------------------------------------------------------------------

def usage():
    print(__doc__.strip())


def main(argv):
    results_dir = None
    cfg_dirs = []
    json_out = None
    md_out = None
    profile = "both"
    quiet_lists = False

    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            usage()
            return
        elif a == "--cfg-dir":
            i += 1
            if i >= len(argv):
                print("!! --cfg-dir needs a directory")
                return
            cfg_dirs.append(argv[i])
        elif a == "--json":
            i += 1
            json_out = argv[i] if i < len(argv) else None
        elif a == "--md":
            i += 1
            md_out = argv[i] if i < len(argv) else None
        elif a == "--profile":
            i += 1
            profile = argv[i] if i < len(argv) else "both"
        elif a == "--quiet-lists":
            quiet_lists = True
        elif a.startswith("-"):
            print("!! unknown option %r (ignored)" % a)
        elif results_dir is None:
            results_dir = a
        else:
            print("!! extra positional argument %r (ignored)" % a)
        i += 1

    if results_dir is None:
        usage()
        print("")
        print("!! no <results_dir> given")
        return
    if not cfg_dirs:
        print("!! no --cfg-dir given: tests can only be split into "
              "anchor-own/sibling/unrelated with the cfgs.  Continuing, "
              "everything will land in 'unrelated' or be reported.")
    if profile == "both":
        profiles = PROFILES
    elif profile in PROFILES:
        profiles = (profile,)
    else:
        print("!! unknown --profile %r, using both" % profile)
        profiles = PROFILES

    notes = Notes()
    cfgs = load_cfgs(cfg_dirs, notes)
    results = load_results(results_dir, profiles, notes)
    entries, unrelated, sibling, mismatch, tot = analyse(results, cfgs, notes)
    problems = notes.finish()

    report_stdout(results_dir, cfg_dirs, entries, unrelated, sibling,
                  mismatch, tot, problems, quiet_lists)
    if json_out:
        report_json(json_out, results_dir, cfg_dirs, entries, unrelated,
                    sibling, mismatch, tot, problems)
    if md_out:
        report_md(md_out, results_dir, cfg_dirs, entries, unrelated,
                  sibling, mismatch, tot, problems)


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
        print("bywhere_report: crashed above; exit code is still 0 by design")
    sys.exit(0)                    # §0-h: no meaning in the exit code
