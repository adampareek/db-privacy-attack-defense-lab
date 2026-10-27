from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str


class RecoveryRequest(BaseModel):
    email: str
    answer: str
