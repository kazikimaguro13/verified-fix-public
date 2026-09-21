"""pytest plugin: import an extra *local* module so the Hypothesis
source-constant pool changes, without changing the code under test."""

try:
    import ccd._preimport_probe  # noqa: F401
except Exception:  # pragma: no cover
    pass
