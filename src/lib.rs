//! ryjwt: fast JWT encoding and decoding for Python, backed by Rust (aws-lc-rs + jiter).
//!
//! This module holds the Python bindings; `decoder` and `encoder` do the work.

mod claims;
mod dates;
mod decoder;
mod encoder;
mod errors;
mod json_write;
mod jwk;
mod jwks;
mod jws;
mod keys;
mod mac;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyMapping, PyString, PyTuple};

use claims::Expected;
use decoder::Decoder;
use encoder::Encoder;
use jwk::Jwk;
use keys::{KeyClass, KeySet};

/// The contents of the file at `path` (str or os.PathLike), read with Python's own I/O so OS errors
/// are the usual `FileNotFoundError` etc., naming the file.
fn read_key_file<'py>(path: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    let py = path.py();
    py.import(intern!(py, "pathlib"))?
        .getattr(intern!(py, "Path"))?
        .call1((path,))?
        .call_method0(intern!(py, "read_bytes"))
}

/// A `kid` argument: None, or a str that isn't empty.
fn key_id(kid: Option<&Bound<'_, PyAny>>) -> PyResult<Option<String>> {
    let Some(kid) = kid else { return Ok(None) };
    let Ok(kid) = kid.cast::<PyString>() else {
        return Err(PyTypeError::new_err(format!(
            "kid must be str, got {}",
            kid.get_type().name()?
        )));
    };
    let kid = kid.to_str()?;
    if kid.is_empty() {
        return Err(PyValueError::new_err("kid must not be empty"));
    }
    Ok(Some(kid.to_owned()))
}

/// Encodes and decodes JWTs with a shared secret, str or bytes, for the HMAC algorithms (HS256,
/// HS384, HS512).
#[pyclass(frozen, module = "ryjwt", name = "SecretKey")]
struct SecretKey {
    decoder: Decoder,
    encoder: Encoder,
}

#[pymethods]
impl SecretKey {
    #[new]
    #[pyo3(signature = (secret, *, algorithms, audience=None, issuer=None, allow_short_secret=false))]
    fn new(
        py: Python<'_>,
        secret: &Bound<'_, PyAny>,
        algorithms: Vec<String>,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
        allow_short_secret: bool,
    ) -> PyResult<Self> {
        let (keys, signers) = keys::prepare_secret(secret, algorithms, allow_short_secret)?;
        Ok(Self {
            decoder: Decoder::new(py, keys, audience, issuer)?,
            encoder: Encoder::new(py, signers, None)?,
        })
    }

    /// The configured algorithm names.
    #[getter]
    fn algorithms(&self) -> Vec<&'static str> {
        self.decoder.algorithm_names()
    }

    #[pyo3(signature = (claims, *, algorithm=None, header=None))]
    fn encode<'py>(
        &self,
        claims: &Bound<'py, PyAny>,
        algorithm: Option<&str>,
        header: Option<&Bound<'_, PyMapping>>,
    ) -> PyResult<Bound<'py, PyString>> {
        self.encoder.encode(claims, algorithm, header)
    }

    #[pyo3(signature = (token, *, r#type=None, audience=None, issuer=None, leeway=None))]
    fn decode<'py>(
        &self,
        py: Python<'py>,
        token: &Bound<'py, PyAny>,
        r#type: Option<&Bound<'py, PyAny>>,
        audience: Option<&Bound<'py, PyAny>>,
        issuer: Option<&Bound<'py, PyAny>>,
        leeway: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.decoder
            .decode(py, token, r#type, audience, issuer, leeway)
    }
}

/// Encodes and decodes JWTs with a private key (RS*, PS*, ES*, `EdDSA`).
#[pyclass(frozen, module = "ryjwt", name = "PrivateKey")]
struct PrivateKey {
    decoder: Decoder,
    encoder: Encoder,
    /// Its public key's JWK (just the one).
    jwks: Vec<Jwk>,
}

impl PrivateKey {
    fn from_pem(
        py: Python<'_>,
        pem: &Bound<'_, PyAny>,
        algorithms: Vec<String>,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
        kid: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let kid = key_id(kid)?;
        let (mut keys, signers) = keys::prepare_private(pem, algorithms, kid.as_deref())?;
        Ok(Self {
            jwks: std::mem::take(&mut keys.jwks),
            decoder: Decoder::new(py, keys, audience, issuer)?,
            encoder: Encoder::new(py, signers, kid.as_deref())?,
        })
    }
}

#[pymethods]
impl PrivateKey {
    #[new]
    #[pyo3(signature = (pem, *, algorithms, audience=None, issuer=None, kid=None))]
    fn new(
        py: Python<'_>,
        pem: &Bound<'_, PyAny>,
        algorithms: Vec<String>,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
        kid: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Self::from_pem(py, pem, algorithms, audience, issuer, kid)
    }

    /// Reads the PEM from the file at `path`.
    #[staticmethod]
    #[pyo3(signature = (path, *, algorithms, audience=None, issuer=None, kid=None))]
    fn from_path(
        py: Python<'_>,
        path: &Bound<'_, PyAny>,
        algorithms: Vec<String>,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
        kid: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Self::from_pem(py, &read_key_file(path)?, algorithms, audience, issuer, kid)
    }

    /// The configured algorithm names.
    #[getter]
    fn algorithms(&self) -> Vec<&'static str> {
        self.decoder.algorithm_names()
    }

    /// Its public key as a JWK.
    fn jwk<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        jwk::only(&self.jwks)?.to_dict(py)
    }

    #[pyo3(signature = (claims, *, algorithm=None, header=None))]
    fn encode<'py>(
        &self,
        claims: &Bound<'py, PyAny>,
        algorithm: Option<&str>,
        header: Option<&Bound<'_, PyMapping>>,
    ) -> PyResult<Bound<'py, PyString>> {
        self.encoder.encode(claims, algorithm, header)
    }

    #[pyo3(signature = (token, *, r#type=None, audience=None, issuer=None, leeway=None))]
    fn decode<'py>(
        &self,
        py: Python<'py>,
        token: &Bound<'py, PyAny>,
        r#type: Option<&Bound<'py, PyAny>>,
        audience: Option<&Bound<'py, PyAny>>,
        issuer: Option<&Bound<'py, PyAny>>,
        leeway: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.decoder
            .decode(py, token, r#type, audience, issuer, leeway)
    }
}

/// Decodes JWTs with a public key, or the keys of a JWKS (RS*, PS*, ES*, `EdDSA`). It can't encode.
///
/// Built from a JWKS, it may hold several keys, and each token picks one by its `kid`.
#[pyclass(frozen, module = "ryjwt", name = "PublicKey")]
struct PublicKey {
    decoder: Decoder,
    /// Each key's JWK: one, unless built from a JWKS.
    jwks: Vec<Jwk>,
}

impl PublicKey {
    fn from_keys(
        py: Python<'_>,
        mut keys: KeySet,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Ok(Self {
            jwks: std::mem::take(&mut keys.jwks),
            decoder: Decoder::new(py, keys, audience, issuer)?,
        })
    }

    fn from_pem(
        py: Python<'_>,
        pem: &Bound<'_, PyAny>,
        algorithms: Vec<String>,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
        kid: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let kid = key_id(kid)?;
        let keys = keys::prepare_public(pem, algorithms, kid.as_deref())?;
        Self::from_keys(py, keys, audience, issuer)
    }
}

#[pymethods]
impl PublicKey {
    #[new]
    #[pyo3(signature = (pem, *, algorithms, audience=None, issuer=None, kid=None))]
    fn new(
        py: Python<'_>,
        pem: &Bound<'_, PyAny>,
        algorithms: Vec<String>,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
        kid: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Self::from_pem(py, pem, algorithms, audience, issuer, kid)
    }

    /// Reads the PEM from the file at `path`.
    #[staticmethod]
    #[pyo3(signature = (path, *, algorithms, audience=None, issuer=None, kid=None))]
    fn from_path(
        py: Python<'_>,
        path: &Bound<'_, PyAny>,
        algorithms: Vec<String>,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
        kid: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Self::from_pem(py, &read_key_file(path)?, algorithms, audience, issuer, kid)
    }

    /// Takes the keys from a JWKS document (JSON str/bytes, or a Mapping); tokens pick theirs by
    /// `kid`.
    #[staticmethod]
    #[pyo3(signature = (jwks, *, algorithms, audience=None, issuer=None))]
    fn from_jwks(
        py: Python<'_>,
        jwks: &Bound<'_, PyAny>,
        algorithms: Vec<String>,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let keys = jwks::prepare(jwks, algorithms, jwks::Mode::Strict)?;
        Self::from_keys(py, keys, audience, issuer)
    }

    /// The configured algorithm names.
    #[getter]
    fn algorithms(&self) -> Vec<&'static str> {
        self.decoder.algorithm_names()
    }

    /// Its public key as a JWK; a `ValueError` if it holds several.
    fn jwk<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        jwk::only(&self.jwks)?.to_dict(py)
    }

    #[pyo3(signature = (token, *, r#type=None, audience=None, issuer=None, leeway=None))]
    fn decode<'py>(
        &self,
        py: Python<'py>,
        token: &Bound<'py, PyAny>,
        r#type: Option<&Bound<'py, PyAny>>,
        audience: Option<&Bound<'py, PyAny>>,
        issuer: Option<&Bound<'py, PyAny>>,
        leeway: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.decoder
            .decode(py, token, r#type, audience, issuer, leeway)
    }
}

/// The JWKs of `key`, a `PrivateKey` or `PublicKey`.
fn key_jwks<'a>(key: &'a Bound<'_, PyAny>) -> PyResult<&'a [Jwk]> {
    if let Ok(key) = key.cast::<PrivateKey>() {
        return Ok(&key.get().jwks);
    }
    if let Ok(key) = key.cast::<PublicKey>() {
        return Ok(&key.get().jwks);
    }
    let hint = if key.is_instance_of::<SecretKey>() {
        " (a shared secret must never be published)"
    } else {
        ""
    };
    Err(PyTypeError::new_err(format!(
        "jwks() takes PrivateKey and PublicKey objects, got {}{hint}",
        key.get_type().name()?
    )))
}

/// Return a JWKS document of the public keys of `keys` (`PrivateKey`s and `PublicKey`s), to
/// publish.
#[pyfunction(name = "jwks")]
fn jwks_document<'py>(py: Python<'py>, keys: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyDict>> {
    let keys = keys.try_iter()?.collect::<PyResult<Vec<_>>>()?;
    let mut all = Vec::with_capacity(keys.len());
    for key in &keys {
        all.extend(key_jwks(key)?);
    }
    jwk::set(py, &all)
}

/// `PublicKey.from_jwks` for a JWKS client's fetched document: keys that can't be used are skipped
/// rather than rejecting the document (see `jwks::Mode::Lenient`).
#[pyfunction]
#[pyo3(signature = (jwks, *, algorithms, audience=None, issuer=None))]
fn public_key_from_fetched_jwks(
    py: Python<'_>,
    jwks: &Bound<'_, PyAny>,
    algorithms: Vec<String>,
    audience: Option<&Bound<'_, PyAny>>,
    issuer: Option<&Bound<'_, PyAny>>,
) -> PyResult<PublicKey> {
    let keys = jwks::prepare(jwks, algorithms, jwks::Mode::Lenient)?;
    PublicKey::from_keys(py, keys, audience, issuer)
}

/// Validates `algorithms` as `PublicKey.from_jwks` does, raising the same errors: a JWKS client
/// checks its algorithms when it's built, before it fetches any keys.
#[pyfunction]
fn validate_jwks_algorithms(algorithms: Vec<String>) -> PyResult<()> {
    keys::algorithm_specs(KeyClass::Public, algorithms).map(drop)
}

/// An `audience`/`issuer` value that can be read again: None, a str, or a tuple of str.
type Reusable<'py> = Option<Bound<'py, PyAny>>;

/// `value` (an `audience`/`issuer` argument called `name`) validated as the key classes validate
/// it, in a form that can be read again: an iterable (which may only be read once) as a tuple.
fn reusable<'py>(value: Option<Bound<'py, PyAny>>, name: &str) -> PyResult<Reusable<'py>> {
    let Some(value) = value else { return Ok(None) };
    Ok(match Expected::parse(Some(&value), name)? {
        Expected::Unchecked => None,
        Expected::One(_) => Some(value),
        Expected::AnyOf(values) => Some(PyTuple::new(value.py(), values)?.into_any()),
    })
}

/// Validates `audience` and `issuer` as the key classes do, raising the same errors: a JWKS client
/// checks them when it's built, and keeps what this returns to pass to each `PublicKey` it builds.
#[pyfunction]
#[pyo3(signature = (*, audience, issuer))]
fn validate_audience_and_issuer<'py>(
    audience: Option<Bound<'py, PyAny>>,
    issuer: Option<Bound<'py, PyAny>>,
) -> PyResult<(Reusable<'py>, Reusable<'py>)> {
    Ok((reusable(audience, "audience")?, reusable(issuer, "issuer")?))
}

/// Return a token's header without verifying its signature; use it for routing or logging, never
/// for trust decisions.
#[pyfunction]
fn unverified_header<'py>(
    py: Python<'py>,
    token: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    decoder::unverified(py, token).map(|(header, _)| header)
}

/// Return a token's claims without verifying its signature or checking exp/nbf/aud/iss; don't
/// trust any value in the result.
#[pyfunction]
fn unverified_claims<'py>(
    py: Python<'py>,
    token: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    decoder::unverified(py, token).map(|(_, claims)| claims)
}

/// Return a token's `(header, claims)` without verifying anything; verify with a key's `decode()`
/// before trusting either.
#[pyfunction]
fn unverified_token<'py>(
    py: Python<'py>,
    token: &Bound<'py, PyAny>,
) -> PyResult<(Bound<'py, PyDict>, Bound<'py, PyDict>)> {
    decoder::unverified(py, token)
}

/// Runs without the GIL on free-threaded Python (`gil_used = false`, the default, stated here): the
/// classes are frozen and hold only `Sync` data, and their caches (`Decoder`'s known headers and
/// parsers, `Encoder`'s payload encoders) tolerate racing fills, every racer storing an equal entry.
#[pymodule(gil_used = false)]
fn _ryjwt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(public_key_from_fetched_jwks, m)?)?;
    m.add_function(wrap_pyfunction!(validate_jwks_algorithms, m)?)?;
    m.add_function(wrap_pyfunction!(validate_audience_and_issuer, m)?)?;
    m.add_function(wrap_pyfunction!(unverified_header, m)?)?;
    m.add_function(wrap_pyfunction!(unverified_claims, m)?)?;
    m.add_function(wrap_pyfunction!(unverified_token, m)?)?;
    m.add_function(wrap_pyfunction!(jwks_document, m)?)?;
    m.add_class::<SecretKey>()?;
    m.add_class::<PrivateKey>()?;
    m.add_class::<PublicKey>()?;
    errors::register(m)?;
    Ok(())
}
