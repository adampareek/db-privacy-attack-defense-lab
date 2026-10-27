from fastapi import FastAPI

from .secure import router as secure_router
from .vulnerable import router as vulnerable_router

app = FastAPI(
    title="Database Privacy Attack & Defense Lab",
    version="1.0.0",
    description=(
        "Original local security lab comparing intentionally vulnerable "
        "database-backed patterns with hardened implementations."
    ),
)

app.include_router(vulnerable_router)
app.include_router(secure_router)


@app.get("/health")
def health():
    return {"status": "ok"}
