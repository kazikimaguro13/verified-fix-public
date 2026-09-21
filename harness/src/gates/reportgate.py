"""pytest plugin for the verified-fix gate harness.

- ``--gate-seed N``  shuffles the collected test order (R5 order randomisation)
- writes ``{nodeid: outcome}`` JSON to ``$GATE_OUT`` (R4 count + 検査5a diff)
"""

from __future__ import annotations

import json
import os
import random

_OUTCOMES: dict[str, str] = {}


def pytest_addoption(parser):
    parser.addoption("--gate-seed", action="store", default=None)


def pytest_collection_modifyitems(config, items):
    seed = config.getoption("--gate-seed")
    if seed is not None:
        random.Random(int(seed)).shuffle(items)


def pytest_runtest_logreport(report):
    nid = report.nodeid
    if report.when == "call":
        _OUTCOMES[nid] = report.outcome
    elif report.outcome == "failed":  # setup/teardown error
        _OUTCOMES[nid] = "error"
    elif report.when == "setup" and report.outcome == "skipped":
        _OUTCOMES.setdefault(nid, "skipped")


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get("GATE_OUT")
    if out:
        with open(out, "w") as fh:
            json.dump(_OUTCOMES, fh, indent=0, sort_keys=True)
