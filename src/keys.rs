//! Algorithms and keys: a key is parsed once into a verifier (and, for secrets/private keys, a
//! signer) per configured algorithm. aws-lc-rs does the key parsing and type/curve checks.

use std::sync::Arc;

use aws_lc_rs::error::KeyRejected;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, ParsedPublicKey, RsaKeyPair, VerificationAlgorithm,
};
use pyo3::exceptions::PyValueError;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

use crate::errors::InvalidKeyError;
use crate::mac::{self, HmacKey};

#[derive(Clone, Copy)]
enum Family {
    Hmac(mac::Hash),
    Rsa(&'static dyn signature::RsaEncoding),
    Ecdsa(&'static signature::EcdsaSigningAlgorithm),
    Ed25519,
}

/// Which algorithms can share one key: an HMAC secret, an RSA key, an EC key on one curve, Ed25519.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Secret,
    Rsa,
    P256,
    Secp256k1,
    P384,
    P521,
    Ed25519,
}

/// (name, key kind, family, verification algorithm for asymmetric keys)
type AlgSpec = (&'static str, KeyKind, Family, &'static dyn VerificationAlgorithm);

static ALGORITHMS: [AlgSpec; 15] = [
    (
        "HS256",
        KeyKind::Secret,
        Family::Hmac(mac::Hash::Sha256),
        &signature::ED25519,
    ),
    (
        "HS384",
        KeyKind::Secret,
        Family::Hmac(mac::Hash::Sha384),
        &signature::ED25519,
    ),
    (
        "HS512",
        KeyKind::Secret,
        Family::Hmac(mac::Hash::Sha512),
        &signature::ED25519,
    ),
    (
        "RS256",
        KeyKind::Rsa,
        Family::Rsa(&signature::RSA_PKCS1_SHA256),
        &signature::RSA_PKCS1_2048_8192_SHA256,
    ),
    (
        "RS384",
        KeyKind::Rsa,
        Family::Rsa(&signature::RSA_PKCS1_SHA384),
        &signature::RSA_PKCS1_2048_8192_SHA384,
    ),
    (
        "RS512",
        KeyKind::Rsa,
        Family::Rsa(&signature::RSA_PKCS1_SHA512),
        &signature::RSA_PKCS1_2048_8192_SHA512,
    ),
    (
        "PS256",
        KeyKind::Rsa,
        Family::Rsa(&signature::RSA_PSS_SHA256),
        &signature::RSA_PSS_2048_8192_SHA256,
    ),
    (
        "PS384",
        KeyKind::Rsa,
        Family::Rsa(&signature::RSA_PSS_SHA384),
        &signature::RSA_PSS_2048_8192_SHA384,
    ),
    (
        "PS512",
        KeyKind::Rsa,
        Family::Rsa(&signature::RSA_PSS_SHA512),
        &signature::RSA_PSS_2048_8192_SHA512,
    ),
    (
        "ES256",
        KeyKind::P256,
        Family::Ecdsa(&signature::ECDSA_P256_SHA256_FIXED_SIGNING),
        &signature::ECDSA_P256_SHA256_FIXED,
    ),
    (
        "ES256K",
        KeyKind::Secp256k1,
        Family::Ecdsa(&signature::ECDSA_P256K1_SHA256_FIXED_SIGNING),
        &signature::ECDSA_P256K1_SHA256_FIXED,
    ),
    (
        "ES384",
        KeyKind::P384,
        Family::Ecdsa(&signature::ECDSA_P384_SHA384_FIXED_SIGNING),
        &signature::ECDSA_P384_SHA384_FIXED,
    ),
    // ES512 is the common (if misnamed) alias for P-521 + SHA-512.
    (
        "ES512",
        KeyKind::P521,
        Family::Ecdsa(&signature::ECDSA_P521_SHA512_FIXED_SIGNING),
        &signature::ECDSA_P521_SHA512_FIXED,
    ),
    (
        "ES521",
        KeyKind::P521,
        Family::Ecdsa(&signature::ECDSA_P521_SHA512_FIXED_SIGNING),
        &signature::ECDSA_P521_SHA512_FIXED,
    ),
    ("EdDSA", KeyKind::Ed25519, Family::Ed25519, &signature::ED25519),
];

enum Material {
    Secret(Vec<u8>),
    Public(Vec<u8>),
    Private(Vec<u8>),
}

#[allow(clippy::large_enum_variant)] // built once per RYJWT, never moved around
enum Signer {
    Hmac(HmacKey),
    Rsa(Arc<RsaKeyPair>, &'static dyn signature::RsaEncoding),
    Ecdsa(EcdsaKeyPair),
    Ed25519(Arc<Ed25519KeyPair>),
}

#[allow(clippy::large_enum_variant)] // built once per RYJWT, never moved around
enum Verifier {
    Hmac(HmacKey),
    Public(ParsedPublicKey),
}

pub struct PreparedAlg {
    pub name: &'static str,
    verifier: Verifier,
    signer: Option<Signer>,
}

impl PreparedAlg {
    pub fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool {
        match &self.verifier {
            Verifier::Hmac(key) => key.verify(signing_input, signature),
            Verifier::Public(key) => key.verify_sig(signing_input, signature).is_ok(),
        }
    }

    pub fn sign(&self, signing_input: &[u8]) -> PyResult<Vec<u8>> {
        let failed = |_| InvalidKeyError::new_err("Signing failed");
        match &self.signer {
            None => Err(InvalidKeyError::new_err(
                "Can't sign with a public key: construct RYJWT with the private key to encode",
            )),
            Some(Signer::Hmac(key)) => Ok(key.sign(signing_input, &mut [0; mac::MAX_TAG_LEN]).to_vec()),
            Some(Signer::Rsa(pair, encoding)) => {
                let mut sig = vec![0; pair.public_modulus_len()];
                pair.sign(*encoding, &SystemRandom::new(), signing_input, &mut sig)
                    .map_err(failed)?;
                Ok(sig)
            }
            Some(Signer::Ecdsa(pair)) => Ok(pair
                .sign(&SystemRandom::new(), signing_input)
                .map_err(failed)?
                .as_ref()
                .to_vec()),
            Some(Signer::Ed25519(pair)) => Ok(pair.sign(signing_input).as_ref().to_vec()),
        }
    }
}

fn key_bytes(key: &Bound<'_, PyAny>) -> Option<PyResult<Vec<u8>>> {
    if let Ok(s) = key.cast::<PyString>() {
        return Some(s.to_str().map(|s| s.as_bytes().to_vec()));
    }
    key.cast::<PyBytes>().ok().map(|b| Ok(b.as_bytes().to_vec()))
}

fn hmac_secret(key: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let secret =
        key_bytes(key).unwrap_or_else(|| Err(InvalidKeyError::new_err("HMAC keys must be str or bytes")))?;
    if secret.is_empty() {
        return Err(InvalidKeyError::new_err("HMAC key must not be empty"));
    }
    // Guard against configuring HS* with a public key, which makes forging tokens trivial.
    if memchr::memmem::find(&secret, b"-----BEGIN").is_some() || secret.starts_with(b"ssh-") {
        return Err(InvalidKeyError::new_err(
            "This looks like an asymmetric key, not an HMAC secret: use RS*/PS*/ES*/EdDSA",
        ));
    }
    Ok(secret)
}

fn parse_pem(key: &[u8]) -> PyResult<Material> {
    let pem =
        pem::parse(key).map_err(|e| InvalidKeyError::new_err(format!("Expected a PEM-encoded key: {e}")))?;
    let der = pem.contents().to_vec();
    match pem.tag() {
        "PUBLIC KEY" | "RSA PUBLIC KEY" => Ok(Material::Public(der)),
        "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => Ok(Material::Private(der)),
        "ENCRYPTED PRIVATE KEY" => Err(InvalidKeyError::new_err(
            "Encrypted private keys aren't supported",
        )),
        other => Err(InvalidKeyError::new_err(format!("Unsupported PEM type: {other}"))),
    }
}

/// A cryptography key object, exported as DER (PKCS#8 for private keys, SPKI for public keys).
fn material_from_object(key: &Bound<'_, PyAny>) -> PyResult<Material> {
    let py = key.py();
    let is_private = key.hasattr(intern!(py, "private_bytes"))?;
    if !is_private && !key.hasattr(intern!(py, "public_bytes"))? {
        return Err(InvalidKeyError::new_err(format!(
            "Unsupported key type {}: expected str, bytes or a cryptography key object",
            key.get_type().name()?
        )));
    }
    let serialization = py.import("cryptography.hazmat.primitives.serialization")?;
    let der = serialization.getattr("Encoding")?.getattr("DER")?;
    let out = if is_private {
        let format = serialization.getattr("PrivateFormat")?.getattr("PKCS8")?;
        key.call_method1(
            "private_bytes",
            (der, format, serialization.getattr("NoEncryption")?.call0()?),
        )?
    } else {
        let format = serialization
            .getattr("PublicFormat")?
            .getattr("SubjectPublicKeyInfo")?;
        key.call_method1("public_bytes", (der, format))?
    };
    let der = out.cast::<PyBytes>()?.as_bytes().to_vec();
    Ok(if is_private {
        Material::Private(der)
    } else {
        Material::Public(der)
    })
}

/// Shared across algorithms of one key (e.g. RS256 + PS256 with one RSA key).
#[derive(Default)]
struct KeyPairs {
    rsa: Option<Arc<RsaKeyPair>>,
    ed25519: Option<Arc<Ed25519KeyPair>>,
}

fn prepare_alg(spec: &AlgSpec, material: &Material, pairs: &mut KeyPairs) -> PyResult<PreparedAlg> {
    let &(name, _, family, verification) = spec;
    let rejected = |e: KeyRejected| InvalidKeyError::new_err(format!("Key can't be used for {name}: {e}"));
    let public = |bytes: &[u8]| {
        ParsedPublicKey::new(verification, bytes)
            .map(Verifier::Public)
            .map_err(rejected)
    };
    let (verifier, signer) = match (family, material) {
        (Family::Hmac(alg), Material::Secret(secret)) => {
            let key = HmacKey::new(alg, secret);
            (Verifier::Hmac(key.clone()), Some(Signer::Hmac(key)))
        }
        (Family::Hmac(_), _) | (_, Material::Secret(_)) => unreachable!("HMAC iff secret"),
        (_, Material::Public(der)) => (public(der)?, None),
        (Family::Rsa(encoding), Material::Private(der)) => {
            let pair = match &pairs.rsa {
                Some(pair) => Arc::clone(pair),
                None => {
                    let pair = RsaKeyPair::from_pkcs8(der)
                        .or_else(|_| RsaKeyPair::from_der(der))
                        .map_err(rejected)?;
                    Arc::clone(pairs.rsa.insert(Arc::new(pair)))
                }
            };
            (
                public(pair.public_key().as_ref())?,
                Some(Signer::Rsa(pair, encoding)),
            )
        }
        (Family::Ecdsa(alg), Material::Private(der)) => {
            let pair = EcdsaKeyPair::from_private_key_der(alg, der).map_err(rejected)?;
            (public(pair.public_key().as_ref())?, Some(Signer::Ecdsa(pair)))
        }
        (Family::Ed25519, Material::Private(der)) => {
            let pair = match &pairs.ed25519 {
                Some(pair) => Arc::clone(pair),
                None => {
                    let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der).map_err(rejected)?;
                    Arc::clone(pairs.ed25519.insert(Arc::new(pair)))
                }
            };
            (public(pair.public_key().as_ref())?, Some(Signer::Ed25519(pair)))
        }
    };
    Ok(PreparedAlg {
        name,
        verifier,
        signer,
    })
}

/// Validates `algorithms` and prepares `key` for each of them.
pub fn prepare(key: &Bound<'_, PyAny>, algorithms: &[String]) -> PyResult<Vec<PreparedAlg>> {
    let mut specs: Vec<&AlgSpec> = Vec::new();
    for name in algorithms {
        let spec = ALGORITHMS.iter().find(|s| s.0 == name).ok_or_else(|| {
            let known: Vec<&str> = ALGORITHMS.iter().map(|s| s.0).collect();
            PyValueError::new_err(format!(
                "Unsupported algorithm {name:?}; supported: {}",
                known.join(", ")
            ))
        })?;
        if !specs.iter().any(|s| s.0 == spec.0) {
            specs.push(spec);
        }
    }
    let Some(first) = specs.first() else {
        return Err(PyValueError::new_err("algorithms must not be empty"));
    };
    if specs.iter().any(|s| s.1 != first.1) {
        return Err(PyValueError::new_err(
            "algorithms must all use the same kind of key (don't mix HS*, RS*/PS*, EC curves and EdDSA)",
        ));
    }
    let material = match (first.2, key_bytes(key)) {
        (Family::Hmac(_), _) => Material::Secret(hmac_secret(key)?),
        (_, Some(bytes)) => parse_pem(&bytes?)?,
        (_, None) => material_from_object(key)?,
    };
    let mut pairs = KeyPairs::default();
    specs
        .into_iter()
        .map(|spec| prepare_alg(spec, &material, &mut pairs))
        .collect()
}
