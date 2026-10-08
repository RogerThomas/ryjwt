"""The algorithm names each key class takes, as Literal types for annotations."""

from typing import Literal

type HMACAlgorithm = Literal["HS256", "HS384", "HS512"]
"""The algorithms `HMAC` takes."""

type AsymmetricAlgorithm = Literal[
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "ES521",
    "EdDSA",
]
"""The algorithms `PrivateKey` and `PublicKey` take."""

__all__ = ["AsymmetricAlgorithm", "HMACAlgorithm"]
