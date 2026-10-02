from fastapi import FastAPI

from app.models import (
    PasswordPolicyResponse,
    PasswordValidationRequest,
    PasswordValidationResponse,
)
from app.policy import DEFAULT_POLICY, validate_password


app = FastAPI(
    title="Password Validator API",
    version="1.0.0",
    description="Deterministic password-policy validation with explainable feedback.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/policy", response_model=PasswordPolicyResponse)
def policy() -> PasswordPolicyResponse:
    return PasswordPolicyResponse(**DEFAULT_POLICY.__dict__)


@app.post("/validate", response_model=PasswordValidationResponse)
def validate(request: PasswordValidationRequest) -> PasswordValidationResponse:
    return validate_password(
        request.password,
        username=request.username,
        email=str(request.email) if request.email else None,
    )
