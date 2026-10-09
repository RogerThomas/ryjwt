#!yeet
"""Generate the bench JWKS server's TLS files into `matrix/tls/`: a self-signed test CA
(`ca.pem`, which the benchmarks trust) and a server certificate it signs (`server.pem`, with
`server.key.pem`) for the Compose service's hostname and localhost.

Test-only material: the CA's private key isn't kept. The CA lasts 10 years, the server
certificate 800 days (macOS rejects longer-lived ones, even from a CA it was told to trust); re-run
this when it expires.
"""

import datetime
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from rich.console import Console


@dataclass(frozen=True, slots=True)
class TestCA:
    _key: ec.EllipticCurvePrivateKey
    _cert: x509.Certificate
    _ca_lifetime: ClassVar[datetime.timedelta] = datetime.timedelta(days=3650)
    _server_lifetime: ClassVar[datetime.timedelta] = datetime.timedelta(days=800)

    @classmethod
    def _builder(
        cls, subject: str, issuer: x509.Name, lifetime: datetime.timedelta
    ) -> x509.CertificateBuilder:
        now = datetime.datetime.now(datetime.UTC)
        return (
            x509
            .CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(issuer)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + lifetime)
        )

    @classmethod
    def create(cls) -> Self:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ryjwt bench test CA")])
        cert = (
            cls
            ._builder("ryjwt bench test CA", name, cls._ca_lifetime)
            .public_key(key.public_key())
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        return cls(key, cert)

    def pem(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM)

    def issue(self, hostnames: list[str]) -> tuple[bytes, bytes]:
        """A server certificate for `hostnames` (and 127.0.0.1), and its private key, as PEMs."""
        key = ec.generate_private_key(ec.SECP256R1())
        names: list[x509.GeneralName] = [x509.DNSName(h) for h in hostnames]
        names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        cert = (
            self
            ._builder(hostnames[0], self._cert.subject, self._server_lifetime)
            .public_key(key.public_key())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return cert.public_bytes(serialization.Encoding.PEM), key_pem


def main(hostname: str = "jwks") -> None:
    tls_dir = Path(__file__).parent / "matrix" / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    ca = TestCA.create()
    cert, key = ca.issue([hostname, "localhost"])
    (tls_dir / "ca.pem").write_bytes(ca.pem())
    (tls_dir / "server.pem").write_bytes(cert)
    (tls_dir / "server.key.pem").write_bytes(key)
    Console().print(f"wrote {tls_dir}: ca.pem, server.pem, server.key.pem (for {hostname!r})")
