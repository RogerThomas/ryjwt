//! Exporting public keys as JWKs (RFC 7517, RFC 7518 §6), for a JWKS to publish.

use std::collections::HashSet;

use base64_simd::URL_SAFE_NO_PAD;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::keys::{KeyKind, Verifier};

/// One public key as a JWK, ready to export.
pub struct Jwk {
    kty: &'static str,
    crv: Option<&'static str>,
    /// Its `kid`, if it has one.
    pub kid: Option<Box<str>>,
    /// Its `alg`: set only if the key is configured for exactly one algorithm.
    alg: Option<&'static str>,
    /// The key material's members, base64url-encoded.
    material: Vec<(&'static str, String)>,
}

impl Jwk {
    /// The JWK of a key of `key_kind`, from its `verifiers` (one per algorithm it's configured
    /// for).
    pub fn new(
        key_kind: KeyKind,
        verifiers: &[Verifier],
        kid: Option<&str>,
    ) -> Result<Self, String> {
        let first = verifiers.first().ok_or("no algorithm for the key")?;
        let der = first.public_key_der().ok_or("not a public key")?;
        // A SubjectPublicKeyInfo ends with the key: an uncompressed EC point, or the raw Ed25519
        // key. aws-lc-rs always writes EC points uncompressed.
        let der = der.as_ref();
        let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode_to_string(bytes);
        let ec_point = |len: usize| -> Result<Vec<(&'static str, String)>, String> {
            match der.get(der.len().saturating_sub(2 * len + 1)..) {
                Some([4, point @ ..]) if point.len() == 2 * len => {
                    let (x, y) = point.split_at(len);
                    Ok(vec![("x", b64(x)), ("y", b64(y))])
                }
                _ => Err("the EC point isn't uncompressed".to_string()),
            }
        };
        let (kty, crv, material) = match key_kind {
            KeyKind::Rsa => {
                let key = aws_lc_rs::rsa::PublicKey::from_der(der).map_err(|e| e.to_string())?;
                let n = b64(key.modulus().big_endian_without_leading_zero());
                let e = b64(key.exponent().big_endian_without_leading_zero());
                ("RSA", None, vec![("n", n), ("e", e)])
            }
            KeyKind::P256 => ("EC", Some("P-256"), ec_point(32)?),
            KeyKind::Secp256k1 => ("EC", Some("secp256k1"), ec_point(32)?),
            KeyKind::P384 => ("EC", Some("P-384"), ec_point(48)?),
            KeyKind::P521 => ("EC", Some("P-521"), ec_point(66)?),
            KeyKind::Ed25519 => {
                let x = der.last_chunk::<32>().ok_or("the Ed25519 key is missing")?;
                ("OKP", Some("Ed25519"), vec![("x", b64(x))])
            }
            KeyKind::Secret => return Err("not a public key".to_string()),
        };
        Ok(Self {
            kty,
            crv,
            kid: kid.map(Into::into),
            alg: match verifiers {
                [only] => Some(only.algorithm),
                _ => None,
            },
            material,
        })
    }

    /// The JWK as a new dict, its members in a fixed order: `kty`, `kid` (if any), `use`, `alg`
    /// (if any), `crv` (for EC and OKP keys), then the key material.
    pub fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("kty", self.kty)?;
        if let Some(kid) = &self.kid {
            dict.set_item("kid", &**kid)?;
        }
        dict.set_item("use", "sig")?;
        if let Some(alg) = self.alg {
            dict.set_item("alg", alg)?;
        }
        if let Some(crv) = self.crv {
            dict.set_item("crv", crv)?;
        }
        for (name, value) in &self.material {
            dict.set_item(*name, value)?;
        }
        Ok(dict)
    }
}

/// The only JWK of a key object holding `jwks`.
pub fn only(jwks: &[Jwk]) -> PyResult<&Jwk> {
    match jwks {
        [only] => Ok(only),
        several => Err(PyValueError::new_err(format!(
            "This PublicKey holds {} keys: export them with ryjwt.jwks([key])",
            several.len()
        ))),
    }
}

/// A JWKS of `jwks`, as `{"keys": [...]}`: a document `PublicKey.from_jwks` can use, so with at
/// least one key, and with unique `kid`s, which every key must have if there are several.
pub fn set<'py>(py: Python<'py>, jwks: &[&Jwk]) -> PyResult<Bound<'py, PyDict>> {
    if jwks.is_empty() {
        return Err(PyValueError::new_err("jwks() needs at least one key"));
    }
    let mut kids = HashSet::with_capacity(jwks.len());
    for (i, jwk) in jwks.iter().enumerate() {
        match &jwk.kid {
            Some(kid) if !kids.insert(&**kid) => {
                return Err(PyValueError::new_err(format!(
                    "Several keys have kid {kid:?}"
                )));
            }
            None if jwks.len() > 1 => {
                return Err(PyValueError::new_err(format!(
                    "Key {i} has no kid: with several keys, tokens pick theirs by kid, so each \
                     needs one"
                )));
            }
            _ => {}
        }
    }
    let keys = PyList::empty(py);
    for jwk in jwks {
        keys.append(jwk.to_dict(py)?)?;
    }
    let document = PyDict::new(py);
    document.set_item("keys", keys)?;
    Ok(document)
}
