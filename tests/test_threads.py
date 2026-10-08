"""Many threads using one key, or one JWKS client, at once: each must get exactly what it would
alone. On a free-threaded build they run in parallel, racing to fill a key's caches (headers seen,
payload parsers and encoders) and the client's keys; there, ryjwt mustn't turn the GIL back on.
"""

import os
import subprocess
import sys
import sysconfig
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytest
import ryjwt
from _support import ClaimsModel, ClaimsStruct, JWKSServer, SigningKey, make_jwk

_ROUND_TRIP = """
import sys

import ryjwt

key = ryjwt.HMAC("s" * 32, algorithms=["HS256"])
assert key.decode(key.encode({"sub": "sub"})) == {"sub": "sub"}
print(sys._is_gil_enabled())
"""


@dataclass(frozen=True, slots=True)
class _Together:
    """`work(thread)`, once every thread is ready to start it."""

    work: Callable[[int], None]
    ready: threading.Barrier

    def __call__(self, thread: int) -> None:
        self.ready.wait()
        self.work(thread)


def _on_threads(work: Callable[[int], None], threads: int = 16) -> None:
    """Runs `work(thread)` on `threads` threads at once; raises what any of them raised."""
    together = _Together(work, threading.Barrier(threads, timeout=10))
    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(together, range(threads)))


@dataclass(frozen=True, slots=True)
class _RoundTrips:
    """One thread's round trips: claims of its own, encoded as a dict and as a Struct, each with
    one of 8 headers (more than a key remembers), decoded by each verifier to a dict, a Struct and
    a model."""

    signer: ryjwt.HMAC | ryjwt.PrivateKey
    verifiers: list[ryjwt.HMAC | ryjwt.PrivateKey | ryjwt.PublicKey]
    rounds: int

    def __call__(self, thread: int) -> None:
        for n in range(self.rounds):
            sub = f"sub-{thread}-{n}"
            for claims in ({"sub": sub}, ClaimsStruct(sub)):
                token = self.signer.encode(claims, header={"kid": f"kid-{n % 8}"})
                for key in self.verifiers:
                    assert key.decode(token) == {"sub": sub}
                    assert key.decode(token, type=ClaimsStruct) == ClaimsStruct(sub)
                    assert key.decode(token, type=ClaimsModel) == ClaimsModel(sub=sub)


@dataclass(frozen=True, slots=True)
class _ClientCalls:
    """One thread's calls to a JWKS client while the server serves the keys `served`: each round
    decodes their tokens (the client fetching as needed), refreshes, then decodes them without
    waiting; and checks the tokens of `retired` keys are unknown, refetched or not."""

    client: ryjwt.JWKSClient
    tokens: dict[str, str]
    """Per kid, a token its key signed, of claims {"sub": kid}."""
    served: list[str]
    retired: list[str]
    rounds: int

    def __call__(self, _thread: int) -> None:
        for _ in range(self.rounds):
            for kid in self.served:
                assert self.client.decode(self.tokens[kid]) == {"sub": kid}
            self.client.refresh()
            for kid in self.served:
                assert self.client.decode_nowait(self.tokens[kid]) == {"sub": kid}
            for kid in self.retired:
                with pytest.raises(ryjwt.UnknownKeyError):
                    self.client.decode(self.tokens[kid])
                with pytest.raises(ryjwt.UnknownKeyError):
                    self.client.decode_nowait(self.tokens[kid])


def test_hmac(hmac_jwt: ryjwt.HMAC) -> None:
    _on_threads(_RoundTrips(hmac_jwt, [hmac_jwt], rounds=500))


@pytest.mark.parametrize("algorithm", ["RS256", "ES256", "EdDSA"])
def test_private_and_public_keys(
    algorithm: ryjwt.AsymmetricAlgorithm,
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
    public_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    private_key = ryjwt.PrivateKey(private_pems[algorithm], algorithms=[algorithm])
    public_key = ryjwt.PublicKey(public_pems[algorithm], algorithms=[algorithm])

    _on_threads(_RoundTrips(private_key, [private_key, public_key], rounds=25))


def test_jwks_client_through_key_rotation(
    server: JWKSServer,
    private_keys: dict[ryjwt.AsymmetricAlgorithm, SigningKey],
    private_pems: dict[ryjwt.AsymmetricAlgorithm, bytes],
) -> None:
    old_key = ryjwt.PrivateKey(private_pems["ES256"], algorithms=["ES256"])
    new_key = ryjwt.PrivateKey(private_pems["EdDSA"], algorithms=["EdDSA"])
    tokens = {
        "old": old_key.encode({"sub": "old"}, header={"kid": "old"}),
        "new": new_key.encode({"sub": "new"}, header={"kid": "new"}),
    }
    old_jwk = make_jwk(private_keys["ES256"], kid="old")
    new_jwk = make_jwk(private_keys["EdDSA"], kid="new")
    client = ryjwt.JWKSClient(server.url, algorithms=["ES256", "EdDSA"], cooldown=0)

    server.serve(old_jwk)
    _on_threads(_ClientCalls(client, tokens, served=["old"], retired=[], rounds=20))

    # The provider publishes the new key next to the old one, then retires the old one.
    server.serve(old_jwk, new_jwk)
    _on_threads(_ClientCalls(client, tokens, served=["old", "new"], retired=[], rounds=20))
    server.serve(new_jwk)
    _on_threads(_ClientCalls(client, tokens, served=["new"], retired=["old"], rounds=20))


@pytest.mark.skipif(
    not sysconfig.get_config_var("Py_GIL_DISABLED"), reason="not a free-threaded build"
)
def test_free_threaded_build_keeps_the_gil_disabled() -> None:
    """Importing ryjwt and using it, in a fresh interpreter, leaves the GIL disabled: CPython would
    enable it for an extension module that doesn't declare it can run without."""
    environment = {name: value for name, value in os.environ.items() if name != "PYTHON_GIL"}

    result = subprocess.run(
        [sys.executable, "-c", _ROUND_TRIP],
        capture_output=True,
        encoding="utf-8",
        check=True,
        env=environment,
    )

    assert (result.stdout, result.stderr) == ("False\n", "")
