# Password Validator API

A lightweight, explainable **password-policy validation API** built with FastAPI. It evaluates password strength using deterministic rules, returns actionable feedback, and avoids storing or returning the submitted password.

This project is designed as a small production-style API example covering validation, typed request/response models, testing, containerization, and CI.

## Features

- `POST /validate` password validation endpoint
- Configurable default policy implemented in one place
- Strength score from `0` to `4`
- Human-readable strength labels and suggestions
- Checks for:
  - minimum and maximum length
  - uppercase and lowercase characters
  - digits and symbols
  - common passwords
  - repeated-character patterns
  - simple keyboard/alphabetic/numeric sequences
  - optional username/email similarity
- Estimated entropy returned as a diagnostic metric
- No password persistence
- Health and policy endpoints
- Pytest API tests
- Docker support
- GitHub Actions CI

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Service health check |
| `GET` | `/policy` | Returns the active default password policy |
| `POST` | `/validate` | Evaluates a password and returns validation results |

## Example Request

```bash
curl -X POST http://localhost:8000/validate \
  -H "Content-Type: application/json" \
  -d '{
    "password": "Nebula!River7Quartz",
    "username": "demo-user",
    "email": "demo@example.com"
  }'
```

Example response:

```json
{
  "valid": true,
  "score": 4,
  "strength": "very_strong",
  "violations": [],
  "suggestions": [],
  "metrics": {
    "length": 19,
    "has_uppercase": true,
    "has_lowercase": true,
    "has_digit": true,
    "has_symbol": true,
    "estimated_entropy_bits": 124.56
  }
}
```

## Run Locally

Requires Python 3.12+.

```bash
git clone https://github.com/ShashankMhatre/password-validator-api.git
cd password-validator-api
python -m venv .venv
```

Activate the virtual environment, then install the project:

```bash
pip install -e ".[dev]"
```

Start the API:

```bash
uvicorn app.main:app --reload
```

Open the interactive API documentation at:

```text
http://localhost:8000/docs
```

## Run Tests

```bash
pytest
```

## Run with Docker

```bash
docker build -t password-validator-api .
docker run --rm -p 8000:8000 password-validator-api
```

## Project Structure

```text
password-validator-api/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   └── policy.py
├── tests/
│   └── test_api.py
├── .github/workflows/ci.yml
├── .gitignore
├── Dockerfile
├── pyproject.toml
└── README.md
```

## Design Notes

The API deliberately uses transparent, deterministic checks rather than claiming that a password-strength score is a guarantee of security. Entropy is an estimate based on observed character classes and is reduced when obvious repeated or sequential patterns are found.

The optional `username` and `email` fields let the validator flag passwords that contain obvious account-specific terms. The raw password is not included in the response or written to application storage.

## Security Notes

This is a portfolio/demo API, not a complete authentication system. A real production deployment should also consider rate limiting, TLS, centralized identity controls, secret-management standards, security monitoring, and a breached-password service such as a privacy-preserving k-anonymity lookup.

Never log request bodies containing passwords in production.

## Main Technologies

`Python` · `FastAPI` · `Pydantic` · `Pytest` · `Docker` · `GitHub Actions`
