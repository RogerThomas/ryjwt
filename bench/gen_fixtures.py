#!yeet
"""Generate a deterministic matrix of HS256 JWTs (payload size x key size) for benchmarking."""

import json
import random
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import jwt


@dataclass(frozen=True, slots=True)
class FixtureMatrix:
    # extra random claims on top of the base set; "typical" instead adds realistic claims (~600 B)
    payload_sizes: ClassVar[dict[str, int]] = {"small": 0, "typical": 0, "medium": 40, "large": 400}
    key_sizes: ClassVar[dict[str, int]] = {
        "k32": 32,
        "k64": 64,
        "k256": 256,
        "k4096": 4096,
    }  # bytes
    typical_claims: ClassVar[dict[str, Any]] = {
        "sub": "8f14e45f-ceea-467a-9575-6d1e3b1a2c4d",
        "nbf": 1_700_000_000,
        "jti": "b6a1c2f0-3d4e-4f5a-8b9c-0d1e2f3a4b5c",
        "sid": "sess_01HF8ZK3QW7X9V2M4N6P8R0T2Y",
        "email": "jane.doe@example.com",
        "name": "Jane Doe",
        "scope": "openid profile email read:orders write:orders",
        "roles": ["user", "billing-admin", "support-readonly"],
        "amr": ["pwd", "mfa"],
    }


def _payload(extra: int, rng: random.Random) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "sub": "user-1234567890",
        "iss": "https://auth.example.com",
        "aud": "ryjwt-bench",
        "iat": 1_700_000_000,
        "exp": 4_102_444_800,  # 2100-01-01, so verification never expires
    }
    for i in range(extra):
        payload[f"claim_{i}"] = "".join(rng.choices(string.ascii_letters, k=24))
    return payload


def main(seed: int = 42) -> None:
    rng = random.Random(seed)  # noqa: S311 - deterministic fixtures, not secrets
    cases: list[dict[str, Any]] = []
    for p_name, extra in FixtureMatrix.payload_sizes.items():
        payload = _payload(extra, rng)
        if p_name == "typical":
            payload |= FixtureMatrix.typical_claims
        for k_name, k_len in FixtureMatrix.key_sizes.items():
            key = "".join(rng.choices(string.ascii_letters + string.digits, k=k_len))
            headers = {"kid": "2024-10-key-1"} if p_name == "typical" else None
            token = jwt.encode(payload, key, algorithm="HS256", headers=headers)  # pyright: ignore[reportUnknownMemberType]
            cases.append(
                {
                    "name": f"{p_name}-{k_name}",
                    "alg": "HS256",
                    "key": key,
                    "token": token,
                    "token_len": len(token),
                    "audience": "ryjwt-bench",
                    "payload": payload,
                },
            )
    (Path(__file__).parent / "fixtures.json").write_text(json.dumps(cases, indent=2))
    for c in cases:
        print(f"{c['name']:<16} token_len={c['token_len']:>6} key_len={len(c['key']):>5}")
