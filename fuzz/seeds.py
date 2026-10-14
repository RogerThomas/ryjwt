#!yeet
"""Write the fuzz targets' seed corpus, `corpus/<target>/seed-*`: realistic inputs for libFuzzer to
start from, made from the bench's keys and tokens (bench/matrix) and a few hand-picked edge cases.
The inputs libFuzzer finds go into the same directories. `task fuzz` runs this first.

Each `claims`, `jwks` and `keys` seed starts with the options byte its check reads (harness.py):
0 for the defaults (HS256, no audience; strict JWKS reading as bytes; key material as bytes).
"""

import base64
import json
import random
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

HERE = Path(__file__).parent
BENCH = HERE.parent / "bench" / "matrix"
KEYS = ("rs2048", "rs3072", "rs4096", "es256", "es384", "es512", "ed25519")
# JSON nested deeper than the harness's reference parses it (harness.py MAX_REFERENCE_DEPTH).
DEEP = b"[" * 1200 + b"]" * 1200


def _secp256k1_key() -> ec.EllipticCurvePrivateKey:
    """A secp256k1 key (ES256K's curve, which the bench has no key on), the same every time."""
    return ec.derive_private_key(0x5EED, ec.SECP256K1())


def _b64decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _write(target: str, seeds: dict[str, bytes]) -> None:
    directory = HERE / "corpus" / target
    directory.mkdir(parents=True, exist_ok=True)
    for name, seed in seeds.items():
        (directory / f"seed-{name}").write_bytes(seed)


def _decode_seeds(cases: list[dict[str, str]]) -> dict[str, bytes]:
    seeds = {
        f"{case['name']}-{kind}": case[kind].encode()
        for case in cases
        if case["payload_size"] in {"small", "typical"}
        for kind in ("token", "expired_token", "wrong_audience_token")
    }
    header, payload, signature = cases[0]["token"].split(".")
    odd_headers = {
        "crit": {"alg": "HS256", "crit": ["exp"]},
        "none": {"alg": "none"},
        "kid-number": {"alg": "ES256", "kid": 1},
        "unknown-kid": {"alg": "ES256", "kid": "nobody"},
        "duplicate-alg": '{"alg":"HS256","alg":"HS256"}',
    }
    for name, value in odd_headers.items():
        text = value if isinstance(value, str) else json.dumps(value)
        seeds[f"header-{name}"] = f"{_b64encode(text.encode())}.{payload}.{signature}".encode()
    seeds["padded"] = f"{header}=.{payload}.{signature}".encode()
    seeds["four-segments"] = f"{header}.{payload}.{payload}.{signature}".encode()
    return seeds


def _claims_seeds(cases: list[dict[str, str]]) -> dict[str, bytes]:
    payloads = {
        case["name"]: _b64decode(case["token"].split(".")[1])
        for case in cases
        if case["alg"] == "HS256"
        and case["key"] == "k64"
        and case["payload_size"] in {"small", "typical"}
    }
    payloads |= {
        "dates": b'{"exp":4102444800,"iat":946684800,"nbf":1000000000,"sub":"s"}',
        "dates-escaped": b'{"\\u0065xp":4102444800,"i\\u0061t":946684800,"sub":"s"}',
        "dates-fraction": b'{"exp":4102444800.5,"iat":-1,"nbf":253402300800}',
        "registered": b'{"exp":4102444800,"nbf":1000000000,"aud":["a","b"],"iss":"i"}',
        "repeated": b'{"exp":1,"exp":4102444800,"aud":"a","aud":["a"]}',
        "values": b'{"l":[true,false,null,-1.5e3,1e400],"o":{"k":"\\u00e9\\ud83d\\ude00"},'
        b'"n":123456789012345678901234567890,"e":"\xc3\xa9"}',
    }
    seeds = {name: b"\0" + payload for name, payload in payloads.items()}
    headers = {
        "hs384-kid": b'{"alg":"HS384","kid":"k","typ":"JWT"}',
        "crit": b'{"alg":"HS256","crit":["exp"]}',
        "alg-number": b'{"typ":"JWT","alg":256}',
    }
    for name, header in headers.items():
        seeds[f"header-{name}"] = b"\x80" + header + b"\0" + payloads["registered"]
    seeds["audience"] = b"\x08" + payloads["registered"]
    seeds["issuer"] = b"\x0c" + payloads["registered"]
    seeds["deep"] = b"\0" + b'{"a":' + DEEP + b"}"
    seeds["header-deep"] = b"\x80" + b'{"alg":"HS256","a":' + DEEP + b"}\0" + payloads["dates"]
    return seeds


def _jwks_seeds() -> dict[str, bytes]:
    documents = {key: json.loads((BENCH / "jwks" / f"{key}.json").read_text()) for key in KEYS}
    seeds = {key: json.dumps(document).encode() for key, document in documents.items()}
    es256 = documents["es256"]["keys"]
    variants = {
        "use-enc": [{**es256[0], "use": "enc"}, es256[1]],
        "use-other": [{**es256[0], "use": "other"}, es256[1]],
        "private": [{**es256[0], "d": "AAAA"}],
        "same-kid": [es256[0], {**es256[1], "kid": es256[0]["kid"]}],
        "no-kid": [{k: v for k, v in es256[0].items() if k != "kid"}],
        "unsupported": [{"kty": "oct", "kid": "s"}, {"kty": "EC", "crv": "P-192"}, es256[1]],
        "mixed": [documents["rs2048"]["keys"][1], es256[1], documents["ed25519"]["keys"][1]],
    }
    seeds |= {name: json.dumps({"keys": keys}).encode() for name, keys in variants.items()}
    seeds = {name: b"\0" + seed for name, seed in seeds.items()}
    seeds["es256-str"] = b"\x01" + json.dumps(documents["es256"]).encode()
    seeds["es256-dict"] = b"\x02" + json.dumps(documents["es256"]).encode()
    numbers = _secp256k1_key().public_key().public_numbers()
    point = {name: _b64encode(n.to_bytes(32)) for name, n in (("x", numbers.x), ("y", numbers.y))}
    es256k = {"kid": "es256k", "kty": "EC", "crv": "secp256k1", **point}
    seeds["es256k"] = b"\0" + json.dumps({"keys": [es256k]}).encode()
    seeds["deep"] = b"\0" + b'{"keys":' + DEEP + b"}"
    return seeds


def _keys_seeds(fixtures: dict[str, dict[str, str]]) -> dict[str, bytes]:
    seeds: dict[str, bytes] = {}
    pkcs1, sec1 = serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    pem, der = serialization.Encoding.PEM, serialization.Encoding.DER
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    for key in KEYS:
        private_pem = (BENCH / "keys" / f"{key}.pem").read_bytes()
        seeds[f"{key}-private"] = private_pem
        seeds[f"{key}-public"] = fixtures[key]["pem"].encode()
        private = serialization.load_pem_private_key(private_pem, None)
        public_der = private.public_key().public_bytes(der, spki)
        seeds[f"{key}-public-der"] = public_der
        seeds[f"{key}-public-base64"] = base64.b64encode(public_der)
        if isinstance(private, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
            seeds[f"{key}-private-traditional"] = private.private_bytes(pem, pkcs1, sec1)
        if isinstance(private, rsa.RSAPrivateKey):
            pkcs1_public = serialization.PublicFormat.PKCS1
            seeds[f"{key}-public-pkcs1"] = private.public_key().public_bytes(pem, pkcs1_public)
        ssh = serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        seeds[f"{key}-ssh"] = private.public_key().public_bytes(*ssh)
    pkcs8 = serialization.PrivateFormat.PKCS8
    seeds["es256k-private"] = _secp256k1_key().private_bytes(pem, pkcs8, sec1)
    seeds["es256k-public"] = _secp256k1_key().public_key().public_bytes(pem, spki)
    seeds = {name: b"\0" + seed for name, seed in seeds.items()}
    # A curve's parameters ahead of its key, as `openssl ecparam -genkey` writes them.
    parameters = b"-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n"
    seeds["es256-with-parameters"] = b"\0" + parameters + seeds["es256-private-traditional"][1:]
    seeds["es256-public-str"] = b"\x01" + fixtures["es256"]["pem"].encode()
    seeds["es256-public-utf16"] = b"\0" + fixtures["es256"]["pem"].encode("utf-16")
    jwk = json.loads((BENCH / "jwks" / "es256.json").read_text())["keys"][0]
    seeds["es256-jwk"] = b"\0" + json.dumps(jwk).encode()
    seeds["certificate"] = b"\0" + (BENCH / "tls" / "ca.pem").read_bytes()
    seeds["secret"] = b"\0" + b"a fine, long and random-looking HMAC secret: 7Kq2xV9pL4mN8rT3"
    seeds["secret-short"] = b"\x04" + b"short"
    return seeds


def main(encode_seeds: int = 16) -> None:
    fixtures = json.loads((BENCH / "fixtures.json").read_text())
    cases: list[dict[str, str]] = fixtures["cases"]
    _write("decode", _decode_seeds(cases))
    _write("claims", _claims_seeds(cases))
    rng = random.Random(0)
    _write("encode", {str(i): rng.randbytes(8 + 16 * i) for i in range(encode_seeds)})
    _write("jwks", _jwks_seeds())
    _write("keys", _keys_seeds(fixtures["keys"]))
