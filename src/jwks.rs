//! JWKS documents (RFC 7517): each usable key becomes one verifier per algorithm it may be used
//! with. aws-lc-rs validates the key material (RSA components, EC points on their curve).

use std::borrow::Cow;
use std::collections::HashSet;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::RsaPublicKeyComponents;
use base64_simd::URL_SAFE_NO_PAD;
use jiter::JsonValue;
use pyo3::exceptions::{PyTypeError, PyUnicodeEncodeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyDict, PyList, PyMapping, PySequence, PyString};

use crate::errors::InvalidKeyError;
use crate::json_write;
use crate::jwk::Jwk;
use crate::keys::{self, AlgSpec, KeyClass, KeyKind, KeySet, Verifier};

/// Members only private (or symmetric) keys have: a JWKS holding any of them leaks a secret.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A JSON object's members, in document order.
type Members<'a> = [(Cow<'a, str>, JsonValue<'a>)];

/// How `prepare` treats keys it can't use.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `PublicKey.from_jwks`: keys of other types or curves, `"use": "enc"` keys and keys for
    /// other algorithms are skipped; any other unusable key rejects the document.
    Strict,
    /// A JWKS client's fetched document: every key that can't be used is skipped (malformed, too
    /// small, of small order, or with a `use` other than `"sig"`), so one bad key in a provider's
    /// set doesn't take down the others.
    Lenient,
}

/// `value` with every Mapping in it made a dict and every Sequence (but str and bytes) a list, as
/// `json_write` takes them.
fn to_dicts_and_lists<'py>(value: &Bound<'py, PyAny>, depth: u32) -> PyResult<Bound<'py, PyAny>> {
    if depth > json_write::MAX_DEPTH {
        return Err(PyValueError::new_err("Nested too deeply"));
    }
    let py = value.py();
    if value.is_instance_of::<PyString>()
        || value.is_instance_of::<PyBytes>()
        || value.is_instance_of::<PyByteArray>()
    {
        return Ok(value.clone());
    }
    if let Ok(mapping) = value.cast::<PyMapping>() {
        let dict = PyDict::new(py);
        for item in mapping.items()?.iter() {
            let (name, member): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item.extract()?;
            dict.set_item(name, to_dicts_and_lists(&member, depth + 1)?)?;
        }
        return Ok(dict.into_any());
    }
    if let Ok(sequence) = value.cast::<PySequence>() {
        let list = PyList::empty(py);
        for item in sequence.try_iter()? {
            list.append(to_dicts_and_lists(&item?, depth + 1)?)?;
        }
        return Ok(list.into_any());
    }
    Ok(value.clone())
}

/// The document's JSON: as given, or serialised from a Mapping.
fn document_json<'a>(jwks: &'a Bound<'_, PyAny>) -> PyResult<Cow<'a, [u8]>> {
    if let Ok(s) = jwks.cast::<PyString>() {
        return Ok(Cow::Borrowed(keys::str_bytes(s, "The JWKS")?));
    }
    if let Ok(b) = jwks.cast::<PyBytes>() {
        return Ok(Cow::Borrowed(b.as_bytes()));
    }
    let Ok(mapping) = jwks.cast::<PyMapping>() else {
        return Err(PyTypeError::new_err(format!(
            "jwks must be str, bytes or a Mapping, got {}",
            jwks.get_type().name()?
        )));
    };
    let mut json = Vec::new();
    to_dicts_and_lists(mapping, 0)
        .and_then(|dict| json_write::write_object(&mut json, dict.cast()?))
        .map_err(|e| {
            let py = jwks.py();
            // A UnicodeEncodeError can't be rebuilt from a message alone.
            let err = if e.is_instance_of::<PyUnicodeEncodeError>(py) {
                InvalidKeyError::new_err(
                    "The jwks Mapping holds a str that isn't valid Unicode (it holds a lone \
                     surrogate)",
                )
            } else {
                PyErr::from_type(
                    e.get_type(py),
                    format!("The jwks Mapping isn't JSON: {}", e.value(py)),
                )
            };
            err.set_cause(py, Some(e));
            err
        })?;
    Ok(Cow::Owned(json))
}

/// The first private-key member a JWK has, if any.
fn private_member(members: &Members<'_>) -> Option<&'static str> {
    PRIVATE_MEMBERS
        .into_iter()
        .find(|name| member(members, name).is_some())
}

/// A member name that appears more than once, if any: such objects are rejected, as their meaning
/// depends on which occurrence a reader picks.
fn duplicate_member<'m>(members: &'m Members<'_>) -> Option<&'m str> {
    let mut seen = HashSet::with_capacity(members.len());
    members
        .iter()
        .map(|(k, _)| k.as_ref())
        .find(|k| !seen.insert(*k))
}

/// The value of member `name` (names are unique: `duplicate_member` was checked).
fn member<'m, 'a>(members: &'m Members<'a>, name: &str) -> Option<&'m JsonValue<'a>> {
    members
        .iter()
        .find(|(k, _)| k.as_ref() == name)
        .map(|(_, v)| v)
}

fn str_member<'m>(members: &'m Members<'_>, name: &str) -> Result<Option<&'m str>, String> {
    match member(members, name) {
        None => Ok(None),
        Some(JsonValue::Str(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{name} must be a string")),
    }
}

/// A required base64url member, decoded; it must decode to `len` bytes if given.
fn bytes_member(members: &Members<'_>, name: &str, len: Option<usize>) -> Result<Vec<u8>, String> {
    let encoded = str_member(members, name)?.ok_or_else(|| format!("{name} is missing"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode_to_vec(encoded)
        .map_err(|_| format!("{name} is not unpadded base64url"))?;
    match len {
        Some(len) if bytes.len() != len => {
            Err(format!("{name} must be {len} bytes, not {}", bytes.len()))
        }
        _ => Ok(bytes),
    }
}

/// The kind of key a JWK holds, or None if ryjwt doesn't support it.
fn key_kind(kty: &str, crv: Option<&str>) -> Option<KeyKind> {
    match (kty, crv) {
        ("RSA", _) => Some(KeyKind::Rsa),
        ("EC", Some("P-256")) => Some(KeyKind::P256),
        ("EC", Some("secp256k1")) => Some(KeyKind::Secp256k1),
        ("EC", Some("P-384")) => Some(KeyKind::P384),
        ("EC", Some("P-521")) => Some(KeyKind::P521),
        ("OKP", Some("Ed25519")) => Some(KeyKind::Ed25519),
        _ => None,
    }
}

fn without_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// A JWK's public key, in the form `Verifier::public` takes for its kind.
fn public_key(members: &Members<'_>, kind: KeyKind) -> Result<Vec<u8>, String> {
    let ec_point = |len| -> Result<Vec<u8>, String> {
        let x = bytes_member(members, "x", Some(len))?;
        let y = bytes_member(members, "y", Some(len))?;
        Ok([&[4][..], &x, &y].concat())
    };
    match kind {
        KeyKind::Rsa => {
            let n = bytes_member(members, "n", None)?;
            let e = bytes_member(members, "e", None)?;
            // RFC 7518 wants no leading zeros; tolerate them rather than fail on a harmless quirk.
            let components = RsaPublicKeyComponents {
                n: without_leading_zeros(&n),
                e: without_leading_zeros(&e),
            };
            let der = components
                .as_der()
                .map_err(|_| "n and e aren't an RSA public key".to_string())?;
            Ok(der.as_ref().to_vec())
        }
        KeyKind::P256 | KeyKind::Secp256k1 => ec_point(32),
        KeyKind::P384 => ec_point(48),
        KeyKind::P521 => ec_point(66),
        KeyKind::Ed25519 => bytes_member(members, "x", Some(32)),
        KeyKind::Secret => Err("not a public key".to_string()),
    }
}

/// A JWK's verifiers, one per configured algorithm it may be used with, and the key to export:
/// None if it isn't usable here (unsupported `kty`/`crv`, not a signing key for `mode`, or no
/// fitting algorithm).
fn prepare_key(
    members: &Members<'_>,
    specs: &[&AlgSpec],
    mode: Mode,
) -> Result<Option<(Vec<Verifier>, Jwk)>, String> {
    if let Some(name) = duplicate_member(members) {
        return Err(format!("duplicate {name:?} member"));
    }
    let kty = str_member(members, "kty")?.ok_or("kty is missing")?;
    let kid = str_member(members, "kid")?;
    let alg = str_member(members, "alg")?;
    let crv = str_member(members, "crv")?;
    let usage = str_member(members, "use")?;
    let Some(jwk_kind) = key_kind(kty, crv) else {
        return Ok(None);
    };
    let specs: Vec<&AlgSpec> = specs
        .iter()
        .copied()
        .filter(|s| s.key_kind == jwk_kind && alg.is_none_or(|alg| alg == s.name))
        .collect();
    let not_for_signing = match mode {
        Mode::Strict => usage == Some("enc"),
        Mode::Lenient => usage.is_some_and(|usage| usage != "sig"),
    };
    if not_for_signing || specs.is_empty() {
        return Ok(None);
    }
    let public_key = public_key(members, jwk_kind)?;
    let verifiers = specs
        .into_iter()
        .map(|spec| Verifier::public(spec, &public_key, kid))
        .collect::<Result<Vec<_>, _>>()?;
    let jwk = Jwk::new(jwk_kind, &verifiers, kid)?;
    Ok(Some((verifiers, jwk)))
}

/// Validates `algorithms` and prepares the usable keys of the JWKS `jwks` (str, bytes or Mapping)
/// for them. Whatever the `mode`, a key holding private key material rejects the document.
pub fn prepare(jwks: &Bound<'_, PyAny>, algorithms: Vec<String>, mode: Mode) -> PyResult<KeySet> {
    let specs = keys::algorithm_specs(KeyClass::Public, algorithms)?;
    let json = document_json(jwks)?;
    let document = JsonValue::parse(&json, false)
        .map_err(|e| InvalidKeyError::new_err(format!("Invalid JWKS JSON: {e}")))?;
    let JsonValue::Object(document) = document else {
        return Err(InvalidKeyError::new_err("A JWKS must be a JSON object"));
    };
    if let Some(name) = duplicate_member(&document) {
        return Err(InvalidKeyError::new_err(format!(
            "Invalid JWKS: duplicate {name:?} member"
        )));
    }
    let Some(JsonValue::Array(jwks)) = member(&document, "keys") else {
        return Err(InvalidKeyError::new_err(
            "A JWKS must have a \"keys\" array",
        ));
    };
    let mut set = KeySet {
        algorithm_names: specs.iter().map(|s| s.name).collect(),
        verifiers: Vec::new(),
        key_count: 0,
        jwks: Vec::new(),
    };
    let mut kids = HashSet::new();
    for (i, key) in jwks.iter().enumerate() {
        let JsonValue::Object(members) = key else {
            if mode == Mode::Lenient {
                continue;
            }
            return Err(InvalidKeyError::new_err(format!(
                "JWKS key {i} must be a JSON object"
            )));
        };
        let error = |e: String| {
            let label = match member(members, "kid") {
                Some(JsonValue::Str(kid)) => format!("JWKS key {i} (kid {kid:?})"),
                _ => format!("JWKS key {i}"),
            };
            InvalidKeyError::new_err(format!("{label}: {e}"))
        };
        if let Some(name) = private_member(members) {
            return Err(error(format!(
                "holds private key material ({name:?}); a JWKS must only hold public keys"
            )));
        }
        let (verifiers, jwk) = match prepare_key(members, &specs, mode) {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(_) if mode == Mode::Lenient => continue,
            Err(e) => return Err(error(e)),
        };
        if let Some(kid) = &jwk.kid
            && !kids.insert(kid.clone())
        {
            return Err(InvalidKeyError::new_err(format!(
                "Several JWKS keys have kid {kid:?}"
            )));
        }
        set.key_count += 1;
        set.verifiers.extend(verifiers);
        set.jwks.push(jwk);
    }
    if set.key_count == 0 {
        let names: Vec<String> = set
            .algorithm_names
            .iter()
            .map(|n| format!("{n:?}"))
            .collect();
        return Err(InvalidKeyError::new_err(format!(
            "The JWKS has no key usable with {}",
            names.join(", ")
        )));
    }
    Ok(set)
}
