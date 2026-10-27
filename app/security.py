import os

MIN_COHORT_SIZE = int(os.getenv("MIN_COHORT_SIZE", "5"))


def cohort_is_safe(count: int, minimum: int | None = None) -> bool:
    threshold = MIN_COHORT_SIZE if minimum is None else minimum
    return count >= threshold


def normalize_filter(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None
