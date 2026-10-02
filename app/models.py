from pydantic import BaseModel, EmailStr, Field


class PasswordValidationRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    username: str | None = Field(default=None, max_length=100)
    email: EmailStr | None = None


class PasswordMetrics(BaseModel):
    length: int
    has_uppercase: bool
    has_lowercase: bool
    has_digit: bool
    has_symbol: bool
    estimated_entropy_bits: float


class PasswordValidationResponse(BaseModel):
    valid: bool
    score: int = Field(ge=0, le=4)
    strength: str
    violations: list[str]
    suggestions: list[str]
    metrics: PasswordMetrics


class PasswordPolicyResponse(BaseModel):
    min_length: int
    max_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_digit: bool
    require_symbol: bool
    reject_common_passwords: bool
    reject_repeated_patterns: bool
    reject_sequential_patterns: bool
