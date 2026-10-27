# Detection Engineering Notes

The hardened application writes security-relevant events to `audit_log`.

## Events

- `AUTH_FAILURE`
- `AUTH_SUCCESS`
- `AGGREGATE_QUERY`
- `SCHEMA_ACCESS`

## Detection ideas

- repeated login failures against one account;
- repeated suppressed aggregate queries;
- progressive narrowing of aggregate filters;
- unexpected privileged schema access.

## Example query

```sql
SELECT event_type, COUNT(*)
FROM audit_log
GROUP BY event_type
ORDER BY COUNT(*) DESC;
```

## Extensions

- forward JSON events to a SIEM;
- include source IP and user agent;
- build dashboard panels for failed logins, inference-query suppression, and admin access.
