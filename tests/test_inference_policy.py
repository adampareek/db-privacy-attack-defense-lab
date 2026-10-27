from app.security import cohort_is_safe


def test_small_cohort_is_suppressed():
    assert cohort_is_safe(1, minimum=5) is False
    assert cohort_is_safe(3, minimum=5) is False


def test_large_cohort_is_allowed():
    assert cohort_is_safe(5, minimum=5) is True
    assert cohort_is_safe(20, minimum=5) is True
