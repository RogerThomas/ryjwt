//! Algorithms and keys: a key is parsed once into a verifier (and, for secrets/private keys, a
//! signer) per configured algorithm. aws-lc-rs does the key parsing and type/curve checks.

use std::fmt::Display;
use std::sync::Arc;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::error::KeyRejected;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    self, EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, KeyPair, ParsedPublicKey,
    RsaEncoding, RsaKeyPair, VerificationAlgorithm,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

use crate::errors::InvalidKeyError;
use crate::mac::{self, HmacKey};

/// How an algorithm signs and verifies.
#[derive(Clone, Copy)]
pub enum Family {
    /// A MAC with a shared secret, which both signs and verifies.
    Hmac(mac::Hash),
    /// The asymmetric families sign with a private key, and verify with its public key.
    Rsa {
        signing: &'static dyn RsaEncoding,
        verification: &'static dyn VerificationAlgorithm,
    },
    Ecdsa {
        signing: &'static EcdsaSigningAlgorithm,
        verification: &'static dyn VerificationAlgorithm,
    },
    Ed25519,
}

/// Which algorithms can share one key: an HMAC secret, an RSA key, an EC key on one curve, Ed25519.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Secret,
    Rsa,
    P256,
    Secp256k1,
    P384,
    P521,
    Ed25519,
}

/// A supported algorithm.
pub struct AlgSpec {
    /// Its JWS `alg` name.
    pub name: &'static str,
    /// The kind of key it takes.
    pub key_kind: KeyKind,
    pub family: Family,
}

impl AlgSpec {
    const fn hmac(name: &'static str, hash: mac::Hash) -> Self {
        Self {
            name,
            key_kind: KeyKind::Secret,
            family: Family::Hmac(hash),
        }
    }

    const fn rsa(
        name: &'static str,
        signing: &'static dyn RsaEncoding,
        verification: &'static dyn VerificationAlgorithm,
    ) -> Self {
        Self {
            name,
            key_kind: KeyKind::Rsa,
            family: Family::Rsa {
                signing,
                verification,
            },
        }
    }

    const fn ecdsa(
        name: &'static str,
        key_kind: KeyKind,
        signing: &'static EcdsaSigningAlgorithm,
        verification: &'static dyn VerificationAlgorithm,
    ) -> Self {
        Self {
            name,
            key_kind,
            family: Family::Ecdsa {
                signing,
                verification,
            },
        }
    }
}

static ALGORITHMS: [AlgSpec; 15] = [
    AlgSpec::hmac("HS256", mac::Hash::Sha256),
    AlgSpec::hmac("HS384", mac::Hash::Sha384),
    AlgSpec::hmac("HS512", mac::Hash::Sha512),
    AlgSpec::rsa(
        "RS256",
        &signature::RSA_PKCS1_SHA256,
        &signature::RSA_PKCS1_2048_8192_SHA256,
    ),
    AlgSpec::rsa(
        "RS384",
        &signature::RSA_PKCS1_SHA384,
        &signature::RSA_PKCS1_2048_8192_SHA384,
    ),
    AlgSpec::rsa(
        "RS512",
        &signature::RSA_PKCS1_SHA512,
        &signature::RSA_PKCS1_2048_8192_SHA512,
    ),
    AlgSpec::rsa(
        "PS256",
        &signature::RSA_PSS_SHA256,
        &signature::RSA_PSS_2048_8192_SHA256,
    ),
    AlgSpec::rsa(
        "PS384",
        &signature::RSA_PSS_SHA384,
        &signature::RSA_PSS_2048_8192_SHA384,
    ),
    AlgSpec::rsa(
        "PS512",
        &signature::RSA_PSS_SHA512,
        &signature::RSA_PSS_2048_8192_SHA512,
    ),
    AlgSpec::ecdsa(
        "ES256",
        KeyKind::P256,
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &signature::ECDSA_P256_SHA256_FIXED,
    ),
    AlgSpec::ecdsa(
        "ES256K",
        KeyKind::Secp256k1,
        &signature::ECDSA_P256K1_SHA256_FIXED_SIGNING,
        &signature::ECDSA_P256K1_SHA256_FIXED,
    ),
    AlgSpec::ecdsa(
        "ES384",
        KeyKind::P384,
        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA384_FIXED,
    ),
    // ES512 is the common (if misnamed) alias for P-521 + SHA-512.
    AlgSpec::ecdsa(
        "ES512",
        KeyKind::P521,
        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_FIXED,
    ),
    AlgSpec::ecdsa(
        "ES521",
        KeyKind::P521,
        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_FIXED,
    ),
    AlgSpec {
        name: "EdDSA",
        key_kind: KeyKind::Ed25519,
        family: Family::Ed25519,
    },
];

#[allow(clippy::large_enum_variant)] // built once per key, never moved around
enum VerifyingKey {
    Hmac(HmacKey),
    Public(ParsedPublicKey),
}

/// One (key, algorithm) pair tokens may be verified with.
pub struct Verifier {
    pub algorithm: &'static str,
    /// The key's `kid`, for keys from a JWKS that has one.
    pub kid: Option<Box<str>>,
    key: VerifyingKey,
}

#[allow(clippy::large_enum_variant)] // built once per key, never moved around
enum SigningKey {
    Hmac(HmacKey),
    Rsa(Arc<RsaKeyPair>, &'static dyn RsaEncoding),
    Ecdsa(EcdsaKeyPair),
    Ed25519(Arc<Ed25519KeyPair>),
}

/// A secret or private key, prepared to sign with one algorithm.
pub struct Signer {
    pub algorithm: &'static str,
    key: SigningKey,
}

/// Every (key, algorithm) pair tokens may be verified with.
pub struct KeySet {
    /// The configured algorithm names.
    pub algorithm_names: Vec<&'static str>,
    /// One per (key, algorithm) pair.
    pub verifiers: Vec<Verifier>,
    /// How many keys `verifiers` holds: 1, unless built from a JWKS.
    pub key_count: usize,
}

impl KeySet {
    /// The set for a single key, with a verifier per spec.
    fn single_key(specs: &[&AlgSpec], verifiers: Vec<Verifier>) -> Self {
        Self {
            algorithm_names: specs.iter().map(|s| s.name).collect(),
            verifiers,
            key_count: 1,
        }
    }
}

/// RSA moduli aws-lc-rs signs and verifies with; outside this range every signature fails.
const RSA_BITS: std::ops::RangeInclusive<usize> = 2048..=8192;

/// The encodings of the Ed25519 points of small order, compared without the sign bit (the top bit
/// of the last byte), as libsodium's `has_small_order` does: 0 and 1 (each also non-canonically,
/// as p and p + 1), p - 1, and the two order-8 points' y. A signature by such a key verifies for
/// (nearly) any message.
const ED25519_SMALL_ORDER: [[u8; 32]; 7] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    ed25519_p_plus(-1),
    ed25519_p_plus(0),
    ed25519_p_plus(1),
];

/// The little-endian encoding of p + `offset` (p = 2^255 - 19), for small `offset`s.
const fn ed25519_p_plus(offset: i8) -> [u8; 32] {
    let mut bytes = [0xff; 32];
    bytes[0] = 0xed_u8.wrapping_add_signed(offset);
    bytes[31] = 0x7f;
    bytes
}

/// Whether `key` (an Ed25519 key aws-lc-rs parsed) is one of `ED25519_SMALL_ORDER`.
fn is_small_order_ed25519(key: &ParsedPublicKey) -> bool {
    // Its SubjectPublicKeyInfo ends with the raw 32-byte key.
    let Some(raw) = key
        .as_der()
        .ok()
        .and_then(|der| der.as_ref().last_chunk::<32>().copied())
    else {
        return true; // can't check it, so don't trust it
    };
    ED25519_SMALL_ORDER
        .iter()
        .any(|small| small[..31] == raw[..31] && small[31] == raw[31] & 0x7f)
}

/// Why a key can't be used for the algorithm `name`.
fn unusable(name: &str, why: impl Display) -> String {
    format!("Key can't be used for {name:?}: {why}")
}

impl Verifier {
    /// A verifier for `spec` with a public key: `SubjectPublicKeyInfo` or PKCS#1 DER for RSA, an
    /// uncompressed point for EC, the raw key for Ed25519. Errors say why the key is unusable.
    pub fn public(spec: &AlgSpec, public_key: &[u8], kid: Option<&str>) -> Result<Self, String> {
        let name = spec.name;
        let verification = match spec.family {
            Family::Hmac(_) => return Err(unusable(name, "it needs a SecretKey")),
            Family::Rsa { verification, .. } => {
                let key = aws_lc_rs::rsa::PublicKey::from_der(public_key)
                    .map_err(|e| unusable(name, e))?;
                let n = key.modulus();
                let n = n.big_endian_without_leading_zero();
                let bits = n.len() * 8 - n.first().map_or(0, |b| b.leading_zeros() as usize);
                if !RSA_BITS.contains(&bits) {
                    return Err(unusable(
                        name,
                        format!("RSA keys must be 2048 to 8192 bits, this one has {bits}"),
                    ));
                }
                verification
            }
            Family::Ecdsa { verification, .. } => verification,
            Family::Ed25519 => &signature::ED25519,
        };
        let key = ParsedPublicKey::new(verification, public_key).map_err(|e| unusable(name, e))?;
        if let Family::Ed25519 = spec.family
            && is_small_order_ed25519(&key)
        {
            return Err(unusable(
                name,
                "it's a small-order Ed25519 point, which lets anyone forge signatures",
            ));
        }
        Ok(Self {
            algorithm: name,
            kid: kid.map(Into::into),
            key: VerifyingKey::Public(key),
        })
    }

    pub fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool {
        match &self.key {
            VerifyingKey::Hmac(key) => key.verify(signing_input, signature),
            VerifyingKey::Public(key) => key.verify_sig(signing_input, signature).is_ok(),
        }
    }
}

impl Signer {
    pub fn sign(&self, signing_input: &[u8]) -> PyResult<Vec<u8>> {
        let failed = |_| InvalidKeyError::new_err("Signing failed");
        match &self.key {
            SigningKey::Hmac(key) => {
                Ok(key.sign(signing_input, &mut [0; mac::MAX_TAG_LEN]).to_vec())
            }
            SigningKey::Rsa(pair, encoding) => {
                let mut sig = vec![0; pair.public_modulus_len()];
                pair.sign(*encoding, &SystemRandom::new(), signing_input, &mut sig)
                    .map_err(failed)?;
                Ok(sig)
            }
            SigningKey::Ecdsa(pair) => Ok(pair
                .sign(&SystemRandom::new(), signing_input)
                .map_err(failed)?
                .as_ref()
                .to_vec()),
            SigningKey::Ed25519(pair) => Ok(pair.sign(signing_input).as_ref().to_vec()),
        }
    }
}

/// The key classes: each takes its own kind of key, for its own algorithms.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// `SecretKey`: a shared secret, for HS*.
    Secret,
    /// `PrivateKey`: a private key PEM, for the asymmetric algorithms.
    Private,
    /// `PublicKey`: a public key PEM (or a JWKS), for the asymmetric algorithms.
    Public,
}

impl KeyClass {
    fn name(self) -> &'static str {
        match self {
            Self::Secret => "SecretKey",
            Self::Private => "PrivateKey",
            Self::Public => "PublicKey",
        }
    }
}

/// A str key (or JWKS) as UTF-8: `InvalidKeyError` if it can't be, holding a lone surrogate.
pub fn str_bytes<'a>(s: &'a Bound<'_, PyString>, what: &str) -> PyResult<&'a [u8]> {
    s.to_str().map(str::as_bytes).map_err(|e| {
        let err = InvalidKeyError::new_err(format!(
            "{what} is a str that isn't valid Unicode (it holds a lone surrogate)"
        ));
        err.set_cause(s.py(), Some(e));
        err
    })
}

fn key_bytes<'a>(key: &'a Bound<'_, PyAny>, what: &str) -> Option<PyResult<&'a [u8]>> {
    if let Ok(s) = key.cast::<PyString>() {
        return Some(str_bytes(s, what));
    }
    key.cast::<PyBytes>().ok().map(|b| Ok(b.as_bytes()))
}

/// Whether `secret` looks like a public key: a PEM, or an OpenSSH (including FIDO `sk-`) or RFC
/// 4716 (SSH2) key.
fn looks_like_public_key(secret: &[u8]) -> bool {
    memchr::memmem::find(secret, b"-----BEGIN").is_some()
        || secret.starts_with(b"ssh-")
        || secret.starts_with(b"ecdsa-sha2-")
        || secret.starts_with(b"sk-ssh-")
        || secret.starts_with(b"sk-ecdsa-sha2-")
        || secret.starts_with(b"---- BEGIN SSH2")
}

/// Whether `der` parses as a public key, as `PublicKey` parses the DER of its PEMs: a
/// `SubjectPublicKeyInfo` of a kind of key ryjwt supports, or a PKCS#1 RSA public key (of any
/// size). Only DER is tried, not the raw encodings `Verifier::public` also takes (an EC point, a
/// 32-byte Ed25519 key), which random bytes can be.
fn parses_as_public_key(der: &[u8]) -> bool {
    // Both are a DER SEQUENCE; a raw EC point starts with 2, 3 or 4 instead.
    if der.first() != Some(&0x30) {
        return false;
    }
    aws_lc_rs::rsa::PublicKey::from_der(der).is_ok()
        || ALGORITHMS.iter().any(|spec| match spec.family {
            Family::Ecdsa { verification, .. } => ParsedPublicKey::new(verification, der).is_ok(),
            // 32 bytes would be parsed as a raw key.
            Family::Ed25519 => {
                der.len() != 32 && ParsedPublicKey::new(&signature::ED25519, der).is_ok()
            }
            Family::Hmac(_) | Family::Rsa { .. } => false,
        })
}

/// `data` decoded from base64, if it is that: in the standard or URL-safe alphabet, padded or not,
/// ignoring ASCII whitespace.
fn base64_decoded(data: &[u8]) -> Option<Vec<u8>> {
    let standard: Vec<u8> = data
        .iter()
        .map(|&b| match b {
            b'-' => b'+',
            b'_' => b'/',
            b => b,
        })
        .collect();
    base64_simd::forgiving_decode_to_vec(&standard).ok()
}

/// The DER element at the start of `der`: its tag, its contents, and what follows it.
fn der_element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let size = usize::from(first & 0x7f);
        if size == 0 || size > 4 || rest.len() < size {
            return None;
        }
        let (size_bytes, rest) = rest.split_at(size);
        let len = size_bytes
            .iter()
            .fold(0, |len, &byte| len << 8 | usize::from(byte));
        (len, rest)
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// Whether `der` is an X.509 certificate: a SEQUENCE holding the certificate's fields (a SEQUENCE
/// ending in its `SubjectPublicKeyInfo`, after an optional version and five other fields), with
/// nothing after it. Its key needn't be one ryjwt supports.
fn is_certificate(der: &[u8]) -> bool {
    const SEQUENCE: u8 = 0x30;
    let Some((SEQUENCE, certificate, [])) = der_element(der) else {
        return false;
    };
    let Some((SEQUENCE, mut fields, _)) = der_element(certificate) else {
        return false;
    };
    if fields.first() == Some(&0xa0) {
        fields = der_element(fields).map_or(&[], |(_, _, rest)| rest);
    }
    // The serial number, signature algorithm, issuer, validity and subject.
    for _ in 0..5 {
        let Some((_, _, rest)) = der_element(fields) else {
            return false;
        };
        fields = rest;
    }
    matches!(der_element(fields), Some((SEQUENCE, _, _)))
}

/// Whether `der` is a public key ryjwt parses, or a certificate.
fn is_public_key_der(der: &[u8]) -> bool {
    parses_as_public_key(der) || is_certificate(der)
}

/// The first character of `bytes`, if they start with one in UTF-8.
fn first_char(bytes: &[u8]) -> Option<char> {
    bytes[..bytes.len().min(4)]
        .utf8_chunks()
        .next()?
        .valid()
        .chars()
        .next()
}

/// `text` without what can come before a key in a file: UTF-8 byte-order marks and Unicode
/// whitespace (a no-break space, say).
fn trim_start_text(mut text: &[u8]) -> &[u8] {
    while let Some(c) = first_char(text).filter(|&c| c == '\u{feff}' || c.is_whitespace()) {
        text = &text[c.len_utf8()..];
    }
    text
}

/// For the JSON string starting `bytes` (just after its opening quote): whether it is `kty`,
/// however escaped (`"kty"`), and what follows its closing quote (None if it has none).
fn json_string_is_kty(bytes: &[u8]) -> (bool, Option<&[u8]>) {
    let mut decoded = [0u8; 4];
    let mut len = 0;
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        let c = match byte {
            b'"' => return (decoded[..len] == *b"kty", Some(&bytes[i + 1..])),
            b'\\' if bytes.get(i + 1) == Some(&b'u') => {
                let code = bytes
                    .get(i + 2..i + 6)
                    .and_then(|hex| std::str::from_utf8(hex).ok())
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok());
                i += 6;
                // Anything but ASCII isn't in "kty".
                code.and_then(|code| u8::try_from(code).ok())
                    .filter(u8::is_ascii)
                    .unwrap_or(0)
            }
            b'\\' => {
                i += 2;
                match bytes.get(i - 1) {
                    Some(b'b') => 0x08,
                    Some(b'f') => 0x0c,
                    Some(b'n') => b'\n',
                    Some(b'r') => b'\r',
                    Some(b't') => b'\t',
                    Some(&escaped) => escaped,
                    None => 0,
                }
            }
            byte => {
                i += 1;
                byte
            }
        };
        if len < decoded.len() {
            decoded[len] = c;
            len += 1;
        }
    }
    (false, None)
}

/// Whether `text` is a JSON object or array with a member named `kty` anywhere in it: a JWK, a
/// JWKS, or JWKs in an array. Scanned rather than parsed, so no nesting is too deep for it.
fn has_jwk_member(text: &[u8]) -> bool {
    if !matches!(text.first(), Some(b'{' | b'[')) {
        return false;
    }
    let mut rest = text;
    while let Some(quote) = memchr::memchr(b'"', rest) {
        let (is_kty, after) = json_string_is_kty(&rest[quote + 1..]);
        let Some(after) = after else {
            return false;
        };
        if is_kty && after.trim_ascii_start().first() == Some(&b':') {
            return true;
        }
        rest = after;
    }
    false
}

/// `bytes` as text, if they're UTF-16 or UTF-32 (as some Windows tools save files): known by their
/// byte-order mark, or else by the zero bytes ASCII has in those encodings, as JSON's are told
/// apart (RFC 4627 §3). Unpaired surrogates and invalid code points become U+FFFD.
fn wide_text(bytes: &[u8]) -> Option<String> {
    let (unit, big_endian, bom) = match bytes {
        [0, 0, 0xfe, 0xff, ..] => (4, true, 4),
        [0xff, 0xfe, 0, 0, ..] => (4, false, 4),
        [0xfe, 0xff, ..] => (2, true, 2),
        [0xff, 0xfe, ..] => (2, false, 2),
        [0, 0, 0, _, ..] => (4, true, 0),
        [_, 0, 0, 0, ..] => (4, false, 0),
        [0, _, ..] => (2, true, 0),
        [_, 0, ..] => (2, false, 0),
        _ => return None,
    };
    let units = bytes[bom..].chunks_exact(unit).map(|chunk| {
        let mut code = [0u8; 4];
        code[4 - unit..].copy_from_slice(chunk);
        if !big_endian {
            code[4 - unit..].reverse();
        }
        u32::from_be_bytes(code)
    });
    Some(if unit == 2 {
        // Each unit is 16 bits, so the conversion can't fail.
        char::decode_utf16(units.map(|u| u16::try_from(u).unwrap_or(0xfffd)))
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    } else {
        units
            .map(|u| char::from_u32(u).unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    })
}

/// Whether `text` (UTF-8, or binary) is a public key: as text (`looks_like_public_key`, or a JSON
/// JWK), or as DER, raw or in base64 (as Keycloak shows a realm's public key, and a JWK's `x5c` a
/// certificate), after any byte-order mark and leading whitespace.
fn is_public_key_text(text: &[u8]) -> bool {
    let text = trim_start_text(text);
    looks_like_public_key(text)
        || has_jwk_member(text)
        || is_public_key_der(text)
        || base64_decoded(text).is_some_and(|der| is_public_key_der(&der))
}

/// Whether `secret` is a public key (`is_public_key_text`), read as UTF-8 or binary, or as UTF-16
/// or UTF-32 text.
fn is_public_key(secret: &[u8]) -> bool {
    is_public_key_text(secret)
        || wide_text(secret).is_some_and(|text| is_public_key_text(text.as_bytes()))
}

/// `key` as an HMAC secret for `specs`: at least as long as the longest of their tags (RFC 7518
/// §3.2), unless `allow_short_secret`.
fn hmac_secret<'a>(
    key: &'a Bound<'_, PyAny>,
    specs: &[&AlgSpec],
    allow_short_secret: bool,
) -> PyResult<&'a [u8]> {
    let secret = key_bytes(key, "The HMAC secret").unwrap_or_else(|| {
        Err(InvalidKeyError::new_err(format!(
            "HMAC secret must be str or bytes, got {}",
            key.get_type().name()?
        )))
    })?;
    if secret.is_empty() {
        return Err(InvalidKeyError::new_err("HMAC secret must not be empty"));
    }
    // Guard against configuring HS* with a public key, which makes forging tokens trivial.
    if is_public_key(secret) {
        return Err(InvalidKeyError::new_err(
            "This looks like an asymmetric key, not an HMAC secret: use PrivateKey or PublicKey",
        ));
    }
    let longest = specs
        .iter()
        .filter_map(|spec| match spec.family {
            Family::Hmac(hash) => Some((spec.name, hash.output_len())),
            _ => None,
        })
        .max_by_key(|&(_, len)| len);
    if !allow_short_secret
        && let Some((name, min_len)) = longest
        && secret.len() < min_len
    {
        return Err(InvalidKeyError::new_err(format!(
            "{name:?} needs a secret of at least {min_len} bytes, got {} (pass \
             allow_short_secret=True to accept it)",
            secret.len()
        )));
    }
    Ok(secret)
}

/// The DER of the key in a PEM, which must be of the kind `class` takes. `EC PARAMETERS` blocks
/// (as `openssl ecparam -genkey` writes ahead of the key) are skipped; exactly one key must remain.
fn pem_der(key: &Bound<'_, PyAny>, class: KeyClass) -> PyResult<Vec<u8>> {
    let bytes = key_bytes(key, "The PEM").unwrap_or_else(|| {
        Err(InvalidKeyError::new_err(format!(
            "Expected a PEM-encoded key as str or bytes, got {} (export key objects as PEM)",
            key.get_type().name()?
        )))
    })?;
    let blocks = pem::parse_many(bytes)
        .map_err(|e| InvalidKeyError::new_err(format!("Expected a PEM-encoded key: {e}")))?;
    let blocks: Vec<_> = blocks
        .into_iter()
        .filter(|b| b.tag() != "EC PARAMETERS")
        .collect();
    let pem = match blocks.as_slice() {
        [pem] => pem,
        [] => {
            return Err(InvalidKeyError::new_err(
                "Expected a PEM-encoded key, but found no key block",
            ));
        }
        several => {
            let tags: Vec<&str> = several.iter().map(pem::Pem::tag).collect();
            return Err(InvalidKeyError::new_err(format!(
                "Expected one key in the PEM, but found {} blocks: {}",
                several.len(),
                tags.join(", ")
            )));
        }
    };
    let private = match pem.tag() {
        "PUBLIC KEY" | "RSA PUBLIC KEY" => false,
        "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => true,
        "ENCRYPTED PRIVATE KEY" => {
            return Err(InvalidKeyError::new_err(
                "Encrypted private keys aren't supported",
            ));
        }
        other => {
            return Err(InvalidKeyError::new_err(format!(
                "Unsupported PEM type: {other}"
            )));
        }
    };
    match (class, private) {
        (KeyClass::Private, false) => Err(InvalidKeyError::new_err(
            "PrivateKey needs a private key, but this is a public key: use PublicKey to verify tokens",
        )),
        (KeyClass::Public, true) => Err(InvalidKeyError::new_err(
            "PublicKey needs a public key, but this is a private key: pass its public key, or \
             use PrivateKey",
        )),
        _ => Ok(pem.contents().to_vec()),
    }
}

/// Validates `algorithms` for `class`: each one supported, and at least one. Duplicates are dropped.
pub fn algorithm_specs(
    class: KeyClass,
    algorithms: Vec<String>,
) -> PyResult<Vec<&'static AlgSpec>> {
    let hmac = class == KeyClass::Secret;
    let supported = || {
        ALGORITHMS
            .iter()
            .filter(move |s| (s.key_kind == KeyKind::Secret) == hmac)
    };
    let mut specs: Vec<&AlgSpec> = Vec::new();
    for name in algorithms {
        let Some(spec) = supported().find(|s| s.name == name) else {
            let hint = match (hmac, ALGORITHMS.iter().any(|s| s.name == name)) {
                (_, false) => "",
                (true, true) => " (it needs a PrivateKey or PublicKey)",
                (false, true) => " (it needs a SecretKey)",
            };
            let known: Vec<String> = supported().map(|s| format!("{:?}", s.name)).collect();
            return Err(PyValueError::new_err(format!(
                "Unsupported algorithm {name:?} for {}{hint}; supported: {}",
                class.name(),
                known.join(", ")
            )));
        };
        if !specs.iter().any(|s| s.name == spec.name) {
            specs.push(spec);
        }
    }
    if specs.is_empty() {
        return Err(PyValueError::new_err("algorithms must not be empty"));
    }
    Ok(specs)
}

/// `algorithm_specs`, which must all take the same kind of key: one key serves them all.
fn single_key_specs(class: KeyClass, algorithms: Vec<String>) -> PyResult<Vec<&'static AlgSpec>> {
    let specs = algorithm_specs(class, algorithms)?;
    if let [first, rest @ ..] = specs.as_slice()
        && rest.iter().any(|s| s.key_kind != first.key_kind)
    {
        return Err(PyValueError::new_err(
            "algorithms must all use the same kind of key (don't mix RS*/PS*, EC curves and EdDSA)",
        ));
    }
    Ok(specs)
}

/// Validates `algorithms` for `SecretKey` and prepares `secret` to sign and verify with each of
/// them.
pub fn prepare_secret(
    secret: &Bound<'_, PyAny>,
    algorithms: Vec<String>,
    allow_short_secret: bool,
) -> PyResult<(KeySet, Vec<Signer>)> {
    let specs = single_key_specs(KeyClass::Secret, algorithms)?;
    let secret = hmac_secret(secret, &specs, allow_short_secret)?;
    let (verifiers, signers) = specs
        .iter()
        .map(|spec| {
            let Family::Hmac(hash) = spec.family else {
                return Err(InvalidKeyError::new_err(unusable(
                    spec.name,
                    "it needs a private key",
                )));
            };
            let key = HmacKey::new(hash, secret);
            let verifier = Verifier {
                algorithm: spec.name,
                kid: None,
                key: VerifyingKey::Hmac(key.clone()),
            };
            let signer = Signer {
                algorithm: spec.name,
                key: SigningKey::Hmac(key),
            };
            Ok((verifier, signer))
        })
        .collect::<PyResult<(Vec<_>, Vec<_>)>>()?;
    Ok((KeySet::single_key(&specs, verifiers), signers))
}

/// Key pairs shared across the algorithms of one key (e.g. RS256 + PS256 with one RSA key).
#[derive(Default)]
struct KeyPairs {
    rsa: Option<Arc<RsaKeyPair>>,
    ed25519: Option<Arc<Ed25519KeyPair>>,
}

impl KeyPairs {
    fn rsa(&mut self, der: &[u8]) -> Result<Arc<RsaKeyPair>, KeyRejected> {
        if let Some(pair) = &self.rsa {
            return Ok(Arc::clone(pair));
        }
        let pair = RsaKeyPair::from_pkcs8(der).or_else(|_| RsaKeyPair::from_der(der))?;
        Ok(Arc::clone(self.rsa.insert(Arc::new(pair))))
    }

    fn ed25519(&mut self, der: &[u8]) -> Result<Arc<Ed25519KeyPair>, KeyRejected> {
        if let Some(pair) = &self.ed25519 {
            return Ok(Arc::clone(pair));
        }
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)?;
        Ok(Arc::clone(self.ed25519.insert(Arc::new(pair))))
    }
}

/// The private key `der` prepared to sign with `spec`, and its public key to verify with it.
fn private_key_pair(
    spec: &AlgSpec,
    der: &[u8],
    pairs: &mut KeyPairs,
) -> PyResult<(Verifier, Signer)> {
    let rejected = |e: KeyRejected| InvalidKeyError::new_err(unusable(spec.name, e));
    let public =
        |bytes: &[u8]| Verifier::public(spec, bytes, None).map_err(InvalidKeyError::new_err);
    let (verifier, key) = match spec.family {
        Family::Hmac(_) => {
            return Err(InvalidKeyError::new_err(unusable(
                spec.name,
                "it needs a SecretKey",
            )));
        }
        Family::Rsa { signing, .. } => {
            let pair = pairs.rsa(der).map_err(rejected)?;
            (
                public(pair.public_key().as_ref())?,
                SigningKey::Rsa(pair, signing),
            )
        }
        Family::Ecdsa { signing, .. } => {
            let pair = EcdsaKeyPair::from_private_key_der(signing, der).map_err(rejected)?;
            (public(pair.public_key().as_ref())?, SigningKey::Ecdsa(pair))
        }
        Family::Ed25519 => {
            let pair = pairs.ed25519(der).map_err(rejected)?;
            (
                public(pair.public_key().as_ref())?,
                SigningKey::Ed25519(pair),
            )
        }
    };
    let signer = Signer {
        algorithm: spec.name,
        key,
    };
    Ok((verifier, signer))
}

/// Validates `algorithms` for `PrivateKey` and prepares the private key `pem` to sign with each of
/// them (and its public key to verify with them).
pub fn prepare_private(
    pem: &Bound<'_, PyAny>,
    algorithms: Vec<String>,
) -> PyResult<(KeySet, Vec<Signer>)> {
    let specs = single_key_specs(KeyClass::Private, algorithms)?;
    let der = pem_der(pem, KeyClass::Private)?;
    let mut pairs = KeyPairs::default();
    let (verifiers, signers) = specs
        .iter()
        .map(|spec| private_key_pair(spec, &der, &mut pairs))
        .collect::<PyResult<(Vec<_>, Vec<_>)>>()?;
    Ok((KeySet::single_key(&specs, verifiers), signers))
}

/// Validates `algorithms` for `PublicKey` and prepares the public key `pem` to verify with each of
/// them.
pub fn prepare_public(pem: &Bound<'_, PyAny>, algorithms: Vec<String>) -> PyResult<KeySet> {
    let specs = single_key_specs(KeyClass::Public, algorithms)?;
    let der = pem_der(pem, KeyClass::Public)?;
    let verifiers = specs
        .iter()
        .map(|spec| Verifier::public(spec, &der, None).map_err(InvalidKeyError::new_err))
        .collect::<PyResult<_>>()?;
    Ok(KeySet::single_key(&specs, verifiers))
}
