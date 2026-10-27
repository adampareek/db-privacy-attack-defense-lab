# Remediation Guide

## SQL injection

The vulnerable login concatenates user-controlled strings into SQL.

The hardened login uses a parameterized query and verifies a PBKDF2 password hash in application code.

## Blacklist filtering

Keyword removal is not a dependable SQL-injection defense. The secure implementation separates SQL code from data using bound parameters.

## Inference attacks

The vulnerable report returns aggregate statistics regardless of cohort size. Repeated filtering can reduce a cohort until an individual fact becomes inferable.

The secure report suppresses results when:

```text
cohort_size < MIN_COHORT_SIZE
```

The default threshold is 5.

Potential production extensions:

- query budgets;
- differential privacy;
- broader bucketing;
- minimum distinct-subject rules.

## Broken authorization

The vulnerable endpoint trusts `/schema?role=admin`. The secure endpoint reads the role from a server-side session.

## Excessive database privilege

Application compromise should not automatically imply database ownership. Separate read-only, normal-write, and administrative database principals.
