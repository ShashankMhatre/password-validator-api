from __future__ import annotations

import math
import re
from dataclasses import dataclass

from app.models import PasswordMetrics, PasswordValidationResponse


COMMON_PASSWORDS = {
    "password",
    "password1",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "abc123",
    "letmein",
    "admin",
    "welcome",
    "iloveyou",
}

SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    reject_common_passwords: bool = True
    reject_repeated_patterns: bool = True
    reject_sequential_patterns: bool = True


DEFAULT_POLICY = PasswordPolicy()


def _contains_sequence(password: str, length: int = 4) -> bool:
    lowered = password.lower()
    for sequence in SEQUENCES:
        for index in range(len(sequence) - length + 1):
            token = sequence[index : index + length]
            if token in lowered or token[::-1] in lowered:
                return True
    return False


def _contains_repeated_pattern(password: str) -> bool:
    if re.search(r"(.)\1{2,}", password):
        return True

    lowered = password.lower()
    for size in range(2, 5):
        for start in range(0, len(lowered) - (size * 2) + 1):
            token = lowered[start : start + size]
            if token and token * 2 in lowered:
                return True
    return False


def _contains_identity_term(password: str, username: str | None, email: str | None) -> bool:
    lowered = password.lower()
    candidates: set[str] = set()

    if username:
        candidates.add(username.lower())

    if email:
        local_part = email.split("@", 1)[0].lower()
        candidates.add(local_part)

    for value in candidates:
        compact = re.sub(r"[^a-z0-9]", "", value)
        if len(compact) >= 4 and compact in re.sub(r"[^a-z0-9]", "", lowered):
            return True
    return False


def _estimate_entropy_bits(password: str) -> float:
    pool = 0
    if any(char.islower() for char in password):
        pool += 26
    if any(char.isupper() for char in password):
        pool += 26
    if any(char.isdigit() for char in password):
        pool += 10
    if any(not char.isalnum() for char in password):
        pool += 33

    if pool == 0 or not password:
        return 0.0

    entropy = len(password) * math.log2(pool)

    if _contains_sequence(password):
        entropy *= 0.7
    if _contains_repeated_pattern(password):
        entropy *= 0.7

    return round(entropy, 2)


def _score_password(
    password: str,
    *,
    has_uppercase: bool,
    has_lowercase: bool,
    has_digit: bool,
    has_symbol: bool,
    violations: list[str],
) -> int:
    score = 0

    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    if sum((has_uppercase, has_lowercase, has_digit, has_symbol)) >= 3:
        score += 1
    if sum((has_uppercase, has_lowercase, has_digit, has_symbol)) == 4:
        score += 1

    if violations:
        score = min(score, 2)

    return max(0, min(4, score))


def _strength_label(score: int) -> str:
    return {
        0: "very_weak",
        1: "weak",
        2: "moderate",
        3: "strong",
        4: "very_strong",
    }[score]


def validate_password(
    password: str,
    *,
    username: str | None = None,
    email: str | None = None,
    policy: PasswordPolicy = DEFAULT_POLICY,
) -> PasswordValidationResponse:
    violations: list[str] = []
    suggestions: list[str] = []

    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(not char.isalnum() for char in password)

    if len(password) < policy.min_length:
        violations.append(f"Password must be at least {policy.min_length} characters long.")
        suggestions.append("Use a longer passphrase with multiple unrelated words.")

    if len(password) > policy.max_length:
        violations.append(f"Password must not exceed {policy.max_length} characters.")

    if policy.require_uppercase and not has_uppercase:
        violations.append("Password must include at least one uppercase letter.")
        suggestions.append("Add at least one uppercase letter.")

    if policy.require_lowercase and not has_lowercase:
        violations.append("Password must include at least one lowercase letter.")
        suggestions.append("Add at least one lowercase letter.")

    if policy.require_digit and not has_digit:
        violations.append("Password must include at least one digit.")
        suggestions.append("Add at least one number.")

    if policy.require_symbol and not has_symbol:
        violations.append("Password must include at least one symbol.")
        suggestions.append("Add a symbol such as !, @, #, or $.")

    if policy.reject_common_passwords and password.lower() in COMMON_PASSWORDS:
        violations.append("Password is too common.")
        suggestions.append("Choose a unique password that is not based on a common phrase.")

    if policy.reject_repeated_patterns and _contains_repeated_pattern(password):
        violations.append("Password contains an obvious repeated pattern.")
        suggestions.append("Avoid repeated characters or repeated short patterns.")

    if policy.reject_sequential_patterns and _contains_sequence(password):
        violations.append("Password contains an obvious sequential pattern.")
        suggestions.append("Avoid alphabetic, numeric, or keyboard sequences.")

    if _contains_identity_term(password, username, email):
        violations.append("Password contains an obvious account-specific term.")
        suggestions.append("Avoid using your username or email name in the password.")

    score = _score_password(
        password,
        has_uppercase=has_uppercase,
        has_lowercase=has_lowercase,
        has_digit=has_digit,
        has_symbol=has_symbol,
        violations=violations,
    )

    metrics = PasswordMetrics(
        length=len(password),
        has_uppercase=has_uppercase,
        has_lowercase=has_lowercase,
        has_digit=has_digit,
        has_symbol=has_symbol,
        estimated_entropy_bits=_estimate_entropy_bits(password),
    )

    return PasswordValidationResponse(
        valid=not violations,
        score=score,
        strength=_strength_label(score),
        violations=violations,
        suggestions=list(dict.fromkeys(suggestions)),
        metrics=metrics,
    )
