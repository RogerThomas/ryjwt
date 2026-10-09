#!yeet
"""Generate deterministic JWT fixtures for benchmarking.

- `fixtures.json`: HS256 tokens, payload size x secret size (`task bench-docker`).
- `matrix/fixtures.json`: the full matrix (`task bench-matrix`): those HS256 cases, plus RS256,
  ES256, ES384, ES512 and EdDSA tokens over the same payloads, each with a `kid`. Every asymmetric
  key comes with its public PEM and a 3-key JWKS document, with the signing key in the middle; the
  documents are also written to `matrix/jwks/<key>.json`, which the JWKS server serves.

Every case also has two tokens, signed the same way, that every library must reject before it's
timed: `expired_token` (`exp` a minute after `iat`, in 2023) and `wrong_audience_token` (`aud`
another audience's). They show each one checks `exp` and `aud`, not just the signature.

Asymmetric private keys are generated once into `matrix/keys/` and then reused (delete them to make
new ones). RSA and EdDSA signatures are deterministic; ECDSA ones aren't, so re-running changes the
ES tokens (not the keys).
"""

import base64
import json
import random
import string
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any, ClassVar

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from rich.console import Console

type PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


@dataclass(frozen=True, slots=True)
class AsymmetricKey:
    """One signing key of the matrix: `size` is small / medium / large within its algorithm."""

    id: str
    alg: str
    size: str
    label: str


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
    # the size class of each HS256 secret in the full matrix (4096 bytes is beyond "large")
    key_size_classes: ClassVar[dict[str, str]] = {
        "k32": "small",
        "k64": "medium",
        "k256": "large",
        "k4096": "x-large",
    }
    asymmetric_keys: ClassVar[tuple[AsymmetricKey, ...]] = (
        AsymmetricKey("rs2048", "RS256", "small", "RSA 2048"),
        AsymmetricKey("rs3072", "RS256", "medium", "RSA 3072"),
        AsymmetricKey("rs4096", "RS256", "large", "RSA 4096"),
        AsymmetricKey("es256", "ES256", "small", "P-256"),
        AsymmetricKey("es384", "ES384", "medium", "P-384"),
        AsymmetricKey("es512", "ES512", "large", "P-521"),
        AsymmetricKey("ed25519", "EdDSA", "-", "Ed25519"),
    )
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


@dataclass(slots=True)
class AsymmetricFixtures:
    """Writes the asymmetric part of `matrix/`: keys, JWKS documents and tokens."""

    _dir: Path
    _curves: ClassVar[dict[str, ec.EllipticCurve]] = {
        "ES256": ec.SECP256R1(),
        "ES384": ec.SECP384R1(),
        "ES512": ec.SECP521R1(),
    }
    _rsa_bits: ClassVar[dict[str, int]] = {"rs2048": 2048, "rs3072": 3072, "rs4096": 4096}

    def _new_private_key(self, key: AsymmetricKey) -> PrivateKey:
        if key.alg == "RS256":
            return rsa.generate_private_key(public_exponent=65537, key_size=self._rsa_bits[key.id])
        if key.alg == "EdDSA":
            return ed25519.Ed25519PrivateKey.generate()
        return ec.generate_private_key(self._curves[key.alg])

    def _private_key(self, key: AsymmetricKey, name: str) -> PrivateKey:
        """The stored private key `name`, generated (and stored) first if it's missing."""
        path = self._dir / "keys" / f"{name}.pem"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            pem = self._new_private_key(key).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            path.write_bytes(pem)
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(
            loaded, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
        ):
            raise TypeError(f"{path}: unexpected key type {type(loaded).__name__}")
        return loaded

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _jwk(self, private_key: PrivateKey, kid: str, alg: str) -> dict[str, str]:
        public_key = private_key.public_key()
        jwk = {"kid": kid, "use": "sig", "alg": alg}
        if isinstance(public_key, rsa.RSAPublicKey):
            numbers = public_key.public_numbers()
            n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8)
            e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8)
            return jwk | {"kty": "RSA", "n": self._b64(n), "e": self._b64(e)}
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            numbers = public_key.public_numbers()
            length = (public_key.curve.key_size + 7) // 8
            crv = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
            return jwk | {
                "kty": "EC",
                "crv": crv[public_key.curve.name],
                "x": self._b64(numbers.x.to_bytes(length)),
                "y": self._b64(numbers.y.to_bytes(length)),
            }
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return jwk | {"kty": "OKP", "crv": "Ed25519", "x": self._b64(raw)}

    def write(
        self, payloads: dict[str, dict[str, Any]], audience: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Returns the matrix's asymmetric keys (by id) and cases, and writes the JWKS documents."""
        keys: dict[str, Any] = {}
        cases: list[dict[str, Any]] = []
        for key in FixtureMatrix.asymmetric_keys:
            kid = f"{key.id}-signing"
            private_key = self._private_key(key, key.id)
            decoys = [
                self._jwk(
                    self._private_key(key, f"{key.id}-decoy-{i}"), f"{key.id}-decoy-{i}", key.alg
                )
                for i in (1, 2)
            ]
            jwks = json.dumps({
                "keys": [decoys[0], self._jwk(private_key, kid, key.alg), decoys[1]]
            })
            jwks_path = self._dir / "jwks" / f"{key.id}.json"
            jwks_path.parent.mkdir(parents=True, exist_ok=True)
            jwks_path.write_text(jwks)
            pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            keys[key.id] = {
                "alg": key.alg,
                "size": key.size,
                "label": key.label,
                "kid": kid,
                "pem": pem.decode(),
                "jwks": jwks,
            }
            for p_name, payload in payloads.items():
                sign = partial(jwt.encode, key=private_key, algorithm=key.alg, headers={"kid": kid})
                token = sign(payload)
                cases.append({
                    "name": f"{p_name}-{key.id}",
                    "key": key.id,
                    "alg": key.alg,
                    "payload_size": p_name,
                    "token": token,
                    "token_len": len(token),
                    "audience": audience,
                    "payload": payload,
                    **_rejected_tokens(sign, payload),
                })
        return keys, cases


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


def _rejected_tokens(
    sign: Callable[[dict[str, Any]], str], payload: dict[str, Any]
) -> dict[str, str]:
    """The tokens a case's decode must reject, signed by `sign` as its own token is."""
    return {
        "expired_token": sign(payload | {"exp": payload["iat"] + 60}),
        "wrong_audience_token": sign(payload | {"aud": "another-audience"}),
    }


def _key_size_order(case: dict[str, Any]) -> int:
    """Where an HS256 case sorts: by its key size (the `k64` of `typical-k64`)."""
    return list(FixtureMatrix.key_sizes).index(case["name"].split("-")[1])


def main(seed: int = 42) -> None:
    bench_dir = Path(__file__).parent
    rng = random.Random(seed)  # noqa: S311 - deterministic fixtures, not secrets
    cases: list[dict[str, Any]] = []
    payloads: dict[str, dict[str, Any]] = {}
    for p_name, extra in FixtureMatrix.payload_sizes.items():
        payload = _payload(extra, rng)
        if p_name == "typical":
            payload |= FixtureMatrix.typical_claims
        payloads[p_name] = payload
        for k_name, k_len in FixtureMatrix.key_sizes.items():
            key = "".join(rng.choices(string.ascii_letters + string.digits, k=k_len))
            headers = {"kid": "2024-10-key-1"} if p_name == "typical" else None
            sign = partial(jwt.encode, key=key, algorithm="HS256", headers=headers)
            token = sign(payload)
            cases.append(
                {
                    "name": f"{p_name}-{k_name}",
                    "alg": "HS256",
                    "key": key,
                    "token": token,
                    "token_len": len(token),
                    "audience": "ryjwt-bench",
                    "payload": payload,
                    **_rejected_tokens(sign, payload),
                },
            )
    (bench_dir / "fixtures.json").write_text(json.dumps(cases, indent=2))

    # The full matrix: the HS256 cases above (by key size), then the asymmetric ones.
    matrix_dir = bench_dir / "matrix"
    keys: dict[str, Any] = {
        k_name: {
            "alg": "HS256",
            "size": FixtureMatrix.key_size_classes[k_name],
            "label": f"{k_len} B",
        }
        for k_name, k_len in FixtureMatrix.key_sizes.items()
    }
    matrix_cases: list[dict[str, Any]] = [
        {
            "name": c["name"],
            "key": c["name"].split("-")[1],
            "alg": "HS256",
            "payload_size": c["name"].split("-")[0],
            "secret": c["key"],
            "token": c["token"],
            "token_len": c["token_len"],
            "audience": c["audience"],
            "payload": c["payload"],
            "expired_token": c["expired_token"],
            "wrong_audience_token": c["wrong_audience_token"],
        }
        for c in sorted(cases, key=_key_size_order)
    ]
    asymmetric_keys, asymmetric_cases = AsymmetricFixtures(matrix_dir).write(
        payloads, "ryjwt-bench"
    )
    keys |= asymmetric_keys
    matrix_cases += asymmetric_cases
    matrix_path = matrix_dir / "fixtures.json"
    matrix_path.write_text(json.dumps({"keys": keys, "cases": matrix_cases}, indent=2) + "\n")

    console = Console()
    for c in cases:
        console.print(f"{c['name']:<16} token_len={c['token_len']:>6} key_len={len(c['key']):>5}")
    console.print(f"wrote {matrix_path}: {len(matrix_cases)} cases over {len(keys)} keys")
