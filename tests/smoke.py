"""A quick check of an installed ryjwt wheel, which the wheel builds run on each wheel they make.

Needs only ryjwt, and cryptography to make an ES256 key: `python tests/smoke.py`.
"""

from importlib.metadata import distribution

import ryjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _check_hs256() -> None:
    hmac = ryjwt.HMAC("secret" * 8, algorithms=["HS256"])

    assert hmac.decode(hmac.encode({"sub": "sub"})) == {"sub": "sub"}


def _check_es256() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signer = ryjwt.PrivateKey(private_pem, algorithms=["ES256"])
    verifier = ryjwt.PublicKey(public_pem, algorithms=["ES256"])

    assert verifier.decode(signer.encode({"sub": "sub"})) == {"sub": "sub"}


def _check_license_files() -> None:
    files = distribution("ryjwt").files or []
    licenses = {file.name for file in files if file.parent.name == "licenses"}

    assert {"LICENSE", "THIRD_PARTY_LICENSES"} <= licenses, licenses


def main() -> None:
    _check_hs256()
    _check_es256()
    _check_license_files()


if __name__ == "__main__":
    main()
