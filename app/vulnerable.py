from fastapi import APIRouter, Query

from .db import connection
from .models import LoginRequest, RecoveryRequest

router = APIRouter(prefix="/vuln", tags=["intentionally vulnerable"])


@router.post("/login")
def vulnerable_login(payload: LoginRequest):
    # INTENTIONALLY VULNERABLE: user input is concatenated directly into SQL.
    query = (
        "SELECT id, email, role FROM users "
        f"WHERE email = '{payload.email}' "
        f"AND password_plain = '{payload.password}'"
    )

    try:
        with connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                row = cur.fetchone()
    except Exception as exc:
        return {
            "ok": False,
            "message": "Database error in intentionally vulnerable endpoint.",
            "demo_error": str(exc),
        }

    if not row:
        return {"ok": False, "message": "Invalid credentials"}

    return {
        "ok": True,
        "message": "Authenticated through vulnerable login",
        "user": row,
    }


@router.get("/report")
def vulnerable_report(
    department: str | None = None,
    state: str | None = None,
    age_band: str | None = None,
):
    clauses = []
    params = []

    for column, value in [
        ("department", department),
        ("state", state),
        ("age_band", age_band),
    ]:
        if value:
            clauses.append(f"{column} = %s")
            params.append(value)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) AS cohort_size,
                    ROUND(AVG(salary), 2) AS average_salary,
                    SUM(CASE WHEN security_training_complete THEN 1 ELSE 0 END)
                        AS training_complete
                FROM employee_facts
                {where}
                """,
                params,
            )
            return cur.fetchone()


@router.get("/schema")
def vulnerable_schema(role: str = Query(default="user")):
    public_schema = {
        "employee_facts": [
            "department",
            "state",
            "age_band",
            "salary",
            "security_training_complete",
        ]
    }

    if role.lower() != "admin":
        return {"role": role, "schema": public_schema}

    return {
        "role": role,
        "schema": {
            **public_schema,
            "users": [
                "id",
                "email",
                "password_salt",
                "password_hash",
                "password_plain",
                "role",
            ],
            "sessions": ["token_hash", "user_id", "role", "expires_at"],
            "audit_log": ["event_type", "actor", "details", "created_at"],
        },
        "warning": "Admin schema disclosed because the client supplied role=admin.",
    }


@router.post("/recover")
def vulnerable_recovery(payload: RecoveryRequest):
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT email, recovery_answer
                FROM users
                WHERE email = %s
                """,
                (payload.email,),
            )
            row = cur.fetchone()

    if not row or row["recovery_answer"].lower() != payload.answer.lower():
        return {"ok": False, "message": "Recovery answer did not match"}

    return {
        "ok": True,
        "message": "Knowledge-based recovery accepted",
        "risk": "Publicly discoverable answers are not a strong authentication factor.",
    }
