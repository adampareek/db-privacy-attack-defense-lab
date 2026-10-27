import json
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException

from .auth import create_session, get_session, verify_password
from .db import connection
from .models import LoginRequest
from .security import MIN_COHORT_SIZE, cohort_is_safe, normalize_filter

router = APIRouter(prefix="/secure", tags=["hardened"])


def audit(event_type: str, actor: str, details: dict):
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_log (event_type, actor, details, created_at)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    event_type,
                    actor,
                    json.dumps(details),
                    datetime.now(timezone.utc),
                ),
            )
        conn.commit()


def require_session(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    token = authorization.removeprefix("Bearer ").strip()
    session = get_session(token)

    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    return session


@router.post("/login")
def secure_login(payload: LoginRequest):
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, password_salt, password_hash, role
                FROM users
                WHERE email = %s
                """,
                (payload.email,),
            )
            row = cur.fetchone()

    if not row or not verify_password(
        payload.password, row["password_salt"], row["password_hash"]
    ):
        audit("AUTH_FAILURE", payload.email, {"reason": "invalid_credentials"})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_session(row["id"], row["role"])
    audit("AUTH_SUCCESS", row["email"], {"role": row["role"]})

    return {
        "ok": True,
        "token": token,
        "role": row["role"],
        "message": "Authenticated using parameterized SQL and PBKDF2 password hashing.",
    }


@router.get("/report")
def secure_report(
    department: str | None = None,
    state: str | None = None,
    age_band: str | None = None,
):
    department = normalize_filter(department)
    state = normalize_filter(state)
    age_band = normalize_filter(age_band)

    clauses = []
    params = []

    for column, value in [
        ("department", department),
        ("state", state),
        ("age_band", age_band),
    ]:
        if value is not None:
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
            row = cur.fetchone()

    audit(
        "AGGREGATE_QUERY",
        "anonymous",
        {
            "department": department,
            "state": state,
            "age_band": age_band,
            "cohort_size": row["cohort_size"],
        },
    )

    if not cohort_is_safe(row["cohort_size"]):
        return {
            "suppressed": True,
            "cohort_size": row["cohort_size"],
            "minimum_required": MIN_COHORT_SIZE,
            "message": "Aggregate suppressed to reduce inference risk.",
        }

    return {"suppressed": False, **row}


@router.get("/schema")
def secure_schema(authorization: str | None = Header(default=None)):
    session = require_session(authorization)

    schema = {
        "employee_facts": [
            "department",
            "state",
            "age_band",
            "salary",
            "security_training_complete",
        ]
    }

    if session["role"] == "admin":
        schema["audit_log"] = ["event_type", "actor", "details", "created_at"]

    audit(
        "SCHEMA_ACCESS",
        session["email"],
        {"role": session["role"], "objects": list(schema)},
    )

    return {
        "role": session["role"],
        "schema": schema,
        "note": "Authorization is derived from the server-side session.",
    }


@router.post("/recover")
def secure_recovery():
    raise HTTPException(
        status_code=410,
        detail=(
            "Knowledge-based recovery is disabled. "
            "Use a verified reset channel or stronger MFA in production."
        ),
    )
