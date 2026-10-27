from app.security import cohort_is_safe, normalize_filter


def test_normalize_filter():
    assert normalize_filter("  Research  ") == "Research"
    assert normalize_filter("   ") is None
    assert normalize_filter(None) is None


def test_cohort_policy_boundary():
    assert cohort_is_safe(5, minimum=5)
    assert not cohort_is_safe(4, minimum=5)
