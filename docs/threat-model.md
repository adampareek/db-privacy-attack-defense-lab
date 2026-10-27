# Threat Model

## Assets

- User credentials
- Session tokens
- Employee aggregate data
- Database schema metadata
- Security audit records
- Database privileges

## Trust boundaries

1. Client → FastAPI application
2. FastAPI application → PostgreSQL
3. Authenticated user → privileged application functions
4. Aggregate reporting layer → sensitive underlying records

## STRIDE review

### Spoofing
Risk: SQL injection can bypass vulnerable authentication; knowledge-based recovery may rely on public information.

Controls: parameterized SQL, password hashing, random sessions, stronger reset mechanisms.

### Tampering
Risk: an over-privileged application account can modify data if the web tier is compromised.

Controls: separate database roles, least privilege, audit logging.

### Repudiation
Risk: sensitive aggregate queries and authorization failures may otherwise leave no evidence.

Controls: structured audit events.

### Information disclosure
Risk: tiny aggregate cohorts permit inference; client-controlled roles expose schema metadata.

Controls: minimum cohort suppression, server-side role derivation, reduced metadata exposure.

### Denial of service
Potential extensions: rate limiting, query timeout, caching.

### Elevation of privilege
Risk: client-controlled roles and excessive DB permissions.

Controls: server-side sessions and separate `app_reader`, `app_writer`, and `app_admin` roles.
