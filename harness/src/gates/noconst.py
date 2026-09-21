"""pytest plugin: disable Hypothesis source-constant injection entirely."""
from hypothesis.internal.conjecture import providers as P

_orig = P.HypothesisProvider._maybe_draw_constant


def _never(self, choice_type, constraints, *, p=0.05):
    # keep the random stream identical to the "no constants available" case
    assert self._random is not None
    self._random.random()
    return None


P.HypothesisProvider._maybe_draw_constant = _never
