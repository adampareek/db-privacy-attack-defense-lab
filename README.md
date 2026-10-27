# Database Privacy Attack & Defense Lab

An original, intentionally vulnerable database-backed security lab demonstrating how data-layer design mistakes become application-security problems.

The project focuses on five themes:

1. SQL injection and authentication bypass
2. Inference attacks against aggregate reports
3. Client-controlled authorization and schema disclosure
4. Excessive database privilege and least-privilege redesign
5. Weak knowledge-based authentication versus stronger recovery controls

Each vulnerable pattern is paired with a hardened design, security tests, and remediation notes.

> **Scope:** This repository uses synthetic data and an original application. It is intended for local defensive education.

## Why this project exists

Many security demos stop at `"OR 1=1"`. This lab goes further by showing the engineering lifecycle:

**vulnerability → root cause → exploitation concept → impact → detection → remediation → regression test**

## Quick start

Requirements:

- Docker
- Docker Compose

Run:

```bash
docker compose up --build
```

Open:

```text
http://localhost:8000/docs
```

Health check:

```bash
curl http://localhost:8000/health
```

Both exposed services bind to `127.0.0.1` in Compose. The database password and user accounts below are fixed **synthetic lab credentials**; do not reuse them in a real environment. Keep the vulnerable service off the public internet.

## Demo credentials

```text
analyst@example.test / analyst-demo-password
admin@example.test   / admin-demo-password
```

## Vulnerability matrix

| Area | Vulnerable design | Security impact | Hardened design |
|---|---|---|---|
| Authentication | Dynamic SQL concatenation | SQL injection / login bypass | Parameterized SQL |
| Input filtering | Keyword blacklist mentality | Brittle defenses | Bound parameters |
| Aggregate reporting | Tiny cohorts returned | Attribute inference | Minimum cohort suppression |
| Authorization | `role` query parameter trusted | Broken access control | Server-issued session role |
| DB privileges | Broad application DB account | Larger blast radius | Least-privilege DB roles |
| Recovery | Public knowledge question | OSINT-based recovery | Strong reset flow |

## Demo sequence

### Vulnerable vs secure authentication

```bash
curl -X POST http://localhost:8000/vuln/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.test","password":"wrong"}'
```

```bash
curl -X POST http://localhost:8000/secure/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.test","password":"analyst-demo-password"}'
```

### Inference risk

```bash
curl 'http://localhost:8000/vuln/report?department=Research&state=NY&age_band=30-39'
```

```bash
curl 'http://localhost:8000/secure/report?department=Research&state=NY&age_band=30-39'
```

### Broken authorization

```bash
curl 'http://localhost:8000/vuln/schema?role=admin'
```

The secure endpoint derives role information from a server-side session instead of accepting it from the client.

## Repository structure

```text
db-privacy-attack-defense-lab/
├── app/
│   ├── main.py
│   ├── db.py
│   ├── models.py
│   ├── vulnerable.py
│   ├── secure.py
│   ├── auth.py
│   └── security.py
├── database/
│   ├── init.sql
│   └── roles.sql
├── docs/
│   ├── threat-model.md
│   ├── remediation.md
│   └── detection.md
├── tests/
│   ├── test_security_helpers.py
│   └── test_inference_policy.py
├── .github/workflows/security.yml
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── SECURITY.md
```

## Security controls demonstrated

- Parameterized SQL
- PBKDF2 password hashing
- Random opaque session tokens
- Server-side authorization
- Minimum cohort size for aggregate reporting
- Structured security-event logging
- Database least privilege
- CI security checks
- Regression tests

## Ethics

Run only against the included local application and synthetic dataset. Do not use these demonstrations against systems you do not own or have explicit authorization to test.
