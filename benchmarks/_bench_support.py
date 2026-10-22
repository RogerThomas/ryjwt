"""What the CodSpeed benchmarks share: claim types and payloads."""

import msgspec
import pydantic

EXP = 4_102_444_800  # 2100-01-01: tokens that don't expire while the benchmarks run
HMAC_SECRET = b"benchmark-secret-" * 4  # 68 bytes: long enough for HS512
AUDIENCE = "my-api"
ISSUER = "https://issuer.example.com"


class ClaimsStruct(msgspec.Struct):
    sub: str
    aud: str
    iss: str
    exp: int
    iat: int
    scope: str


class ClaimsModel(pydantic.BaseModel):
    sub: str
    aud: str
    iss: str
    exp: int
    iat: int
    scope: str


def make_claims() -> dict[str, object]:
    """A typical access token's claims."""
    return {
        "sub": "user-1234567890",
        "aud": AUDIENCE,
        "iss": ISSUER,
        "exp": EXP,
        "iat": 1_700_000_000,
        "scope": "read:messages write:messages profile email",
    }


def make_large_claims() -> dict[str, object]:
    """Claims with a larger payload: many roles and nested metadata."""
    claims = make_claims()
    claims["roles"] = [f"role-{i}" for i in range(100)]
    claims["metadata"] = {f"key-{i}": {"value": i, "enabled": i % 2 == 0} for i in range(50)}
    return claims
