//! Verifying and decoding tokens: what `HMAC`, `PrivateKey` and `PublicKey` share.

use std::sync::OnceLock;

use jiter::{FloatMode, PartialMode, PythonParse, StringCacheMode};
use pyo3::exceptions::{PyImportError, PyRecursionError, PyTypeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyString, PyType};

use crate::claims::{self, Checks, ClaimAttributes, Expected};
use crate::errors::{
    ClaimsValidationError, DecodeError, InvalidAlgorithmError, InvalidSignatureError,
    UnknownKeyError,
};
use crate::jws;
use crate::keys::{KeySet, Verifier};

/// Tokens signed by one key nearly always share one header (or a handful).
const KNOWN_HEADERS: usize = 4;

/// Signatures (at most 1024 bytes, for RSA-8192) are decoded on the stack.
const MAX_STACK_SIGNATURE: usize = 1024;
/// Payloads up to this size are decoded on the stack when they needn't outlive the call.
const MAX_STACK_PAYLOAD: usize = 4096;

/// The key(s) prepared to verify tokens with, and the caches that keep decoding fast.
pub struct Decoder {
    /// One per (key, algorithm) pair; for a single key, one per configured algorithm.
    verifiers: Vec<Verifier>,
    /// The configured algorithm names.
    algorithm_names: Vec<&'static str>,
    /// The configured `audience` and `issuer`, which `decode`'s own replace.
    audience: Expected<'static>,
    issuer: Expected<'static>,
    /// How many keys `verifiers` holds: 1, unless built from a JWKS.
    key_count: usize,
    /// Whether any key has a `kid`, so tokens' `kid`s must be read to pick the key.
    any_kid: bool,
    /// `type` -> its `TypedParser`, built on first use of each `type`.
    parsers: Py<PyDict>,
    /// msgspec's untyped JSON decoder if msgspec is installed (it builds typical-sized payload
    /// dicts faster than jiter), else None for jiter. Resolved once, in `new`.
    msgspec_decode: Option<Py<PyAny>>,
    /// Header segments already seen on a successfully verified token, with the index of their
    /// verifier in `verifiers`. A token's header is a pure function of its bytes, so a
    /// byte-identical header needn't be base64-decoded and parsed again, nor its `kid` looked up.
    /// Entries are only added after the signature checked out, so only the key holder can fill
    /// the (fixed, small) cache.
    known_headers: [OnceLock<(Box<[u8]>, usize)>; KNOWN_HEADERS],
}

/// How `decode` turns a payload into an instance of one `type`.
#[pyclass(frozen)]
struct TypedParser {
    /// The `type` itself.
    type_: Py<PyAny>,
    /// callable(bytes) -> instance.
    make: Py<PyAny>,
    /// Where instances hold the registered claims, if they can be read from there.
    claims: Option<ClaimAttributes>,
}

impl TypedParser {
    fn new(type_: &Bound<'_, PyAny>) -> PyResult<Self> {
        let py = type_.py();
        let glue = py.import(intern!(py, "ryjwt._types"))?;
        let make = glue.call_method1(intern!(py, "payload_parser"), (type_,))?;
        let claims = glue
            .call_method1(intern!(py, "claim_attributes"), (type_,))?
            .extract::<Option<[Option<Bound<'_, PyString>>; 4]>>()?
            .map(ClaimAttributes::new);
        Ok(Self {
            type_: type_.clone().unbind(),
            make: make.unbind(),
            claims,
        })
    }

    /// `error`, raised by `make`, as a `ClaimsValidationError` if it's msgspec or pydantic saying
    /// the payload doesn't fit the type (or a `DecodeError` if pydantic says it isn't valid JSON).
    fn mismatch(&self, py: Python<'_>, error: PyErr) -> PyErr {
        let explained = py
            .import(intern!(py, "ryjwt._types"))
            .and_then(|glue| {
                glue.call_method1(
                    intern!(py, "mismatch"),
                    (self.type_.bind(py), error.value(py)),
                )
            })
            .and_then(|m| m.extract::<Option<(String, bool)>>());
        let wrapped = match explained {
            Ok(Some((message, false))) => ClaimsValidationError::new_err(message),
            Ok(Some((message, true))) => DecodeError::new_err(message),
            Ok(None) => return error,
            Err(glue_error) => return glue_error,
        };
        wrapped.set_cause(py, Some(error));
        wrapped
    }

    /// Parses the payload with `make` and validates its registered claims, reporting invalid
    /// claims ahead of the parser's own errors (and never running user code for them).
    fn parse<'py>(
        &self,
        payload: &Bound<'py, PyBytes>,
        checks: &Checks<'_>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let py = payload.py();
        let make = self.make.bind(py);
        let bytes = payload.as_bytes();
        let Some(claims) = self.claims.as_ref().filter(|c| c.cover(bytes)) else {
            checks.validate(&claims::scan(bytes)?)?;
            return make.call1((payload,)).map_err(|e| self.mismatch(py, e));
        };
        // The parser rejects what `scan` would and decodes the claims as `scan` would, running no
        // user code: parse first and read the claims from the instance, scanning only to report
        // invalid claims ahead of the parser's own error.
        let instance = make.call1((payload,)).map_err(|e| {
            claims::scan(bytes)
                .and_then(|registered| checks.validate(&registered))
                .map_or_else(|invalid| invalid, |()| self.mismatch(py, e))
        })?;
        claims.validate(&instance, checks)?;
        Ok(instance)
    }
}

fn token_bytes<'a>(token: &'a Bound<'_, PyAny>) -> PyResult<&'a [u8]> {
    if let Ok(s) = token.cast::<PyString>() {
        return s
            .to_str()
            .map(str::as_bytes)
            .map_err(|_| DecodeError::new_err("Token must be ASCII"));
    }
    if let Ok(b) = token.cast::<PyBytes>() {
        return Ok(b.as_bytes());
    }
    Err(PyTypeError::new_err("token must be str or bytes"))
}

/// `msgspec.json.Decoder().decode`, or None if msgspec isn't installed.
fn msgspec_dict_decoder(py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
    match py.import(intern!(py, "msgspec.json")) {
        Ok(json) => {
            let decoder = json.getattr(intern!(py, "Decoder"))?.call0()?;
            Ok(Some(decoder.getattr(intern!(py, "decode"))?.unbind()))
        }
        Err(e) if e.is_instance_of::<PyImportError>(py) => Ok(None),
        Err(e) => Err(e),
    }
}

impl Decoder {
    /// A decoder for `keys`, checking `audience` and `issuer` (validated as `decode` validates its
    /// own) unless a `decode` call passes its own.
    pub fn new(
        py: Python<'_>,
        keys: KeySet,
        audience: Option<&Bound<'_, PyAny>>,
        issuer: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let KeySet {
            algorithm_names,
            verifiers,
            key_count,
        } = keys;
        Ok(Self {
            any_kid: verifiers.iter().any(|v| v.kid.is_some()),
            verifiers,
            algorithm_names,
            audience: Expected::configured(audience, "audience")?,
            issuer: Expected::configured(issuer, "issuer")?,
            key_count,
            parsers: PyDict::new(py).unbind(),
            msgspec_decode: msgspec_dict_decoder(py)?,
            known_headers: Default::default(),
        })
    }

    pub fn algorithm_names(&self) -> Vec<&'static str> {
        self.algorithm_names.clone()
    }

    fn known_header(&self, header: &[u8]) -> Option<usize> {
        for slot in &self.known_headers {
            match slot.get() {
                Some((known, index)) if **known == *header => return Some(*index),
                Some(_) => {}
                None => return None,
            }
        }
        None
    }

    fn remember_header(&self, header: &[u8], index: usize) {
        // Racing threads may both add the same header; harmless (a duplicate slot).
        if let Some(slot) = self.known_headers.iter().find(|s| s.get().is_none()) {
            let _ = slot.set((header.into(), index));
        }
    }

    /// The index in `verifiers` of the one to verify a token with this header with.
    fn select_verifier(&self, header: &[u8]) -> PyResult<usize> {
        let (alg, kid) = jws::parse_header(header, self.any_kid)?;
        if !self.algorithm_names.contains(&alg.as_str()) {
            return Err(InvalidAlgorithmError::new_err(format!(
                "Algorithm {alg:?} is not allowed"
            )));
        }
        // A token without a `kid`, or a key without one, is only matched in a set of one key.
        let matches_kid = |v: &Verifier| match (&kid, &v.kid) {
            (Some(kid), Some(own)) => **own == **kid,
            _ => self.key_count == 1,
        };
        let mut candidates = self
            .verifiers
            .iter()
            .enumerate()
            .filter(|(_, v)| matches_kid(v))
            .peekable();
        if candidates.peek().is_none() {
            return Err(UnknownKeyError::new_err(match &kid {
                Some(kid) => format!("No key has kid {kid:?}"),
                // Then tokens' `kid`s aren't even read.
                None if !self.any_kid => format!(
                    "None of the {} keys has a kid, so no token can pick one",
                    self.key_count
                ),
                None => "The token has no kid, and there are several keys".to_string(),
            }));
        }
        candidates
            .find(|(_, v)| v.algorithm == alg)
            .map(|(index, _)| index)
            .ok_or_else(|| {
                InvalidAlgorithmError::new_err(match &kid {
                    Some(kid) => format!("Algorithm {alg:?} is not allowed for the key {kid:?}"),
                    None => format!("Algorithm {alg:?} is not allowed for this key"),
                })
            })
    }

    /// Checks the token's signature, with the verifier its header selects.
    #[inline]
    fn verify_signature(&self, token: &jws::Segments<'_>) -> PyResult<()> {
        let known = self.known_header(token.header);
        let index = match known {
            Some(index) => index,
            None => self.select_verifier(token.header)?,
        };
        let verified =
            jws::with_b64_decoded::<MAX_STACK_SIGNATURE, _>(token.signature, "signature", |sig| {
                Ok(self.verifiers[index].verify(token.signing_input, sig))
            })?;
        if !verified {
            return Err(InvalidSignatureError::new_err(
                "Signature verification failed",
            ));
        }
        if known.is_none() {
            self.remember_header(token.header, index);
        }
        Ok(())
    }

    /// Decodes the (verified) payload to a dict, and validates its registered claims.
    fn decode_dict<'py>(
        &self,
        py: Python<'py>,
        token: &jws::Segments<'_>,
        checks: &Checks<'_>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let parsed = match &self.msgspec_decode {
            Some(decoder) => {
                let payload = jws::b64_decode_to_pybytes(py, token.payload, "payload")?;
                decoder.bind(py).call1((payload,)).map_err(|e| {
                    // msgspec's DecodeError and UnicodeDecodeError are both ValueErrors; it
                    // raises RecursionError on deeply nested payloads.
                    if e.is_instance_of::<PyValueError>(py)
                        || e.is_instance_of::<PyRecursionError>(py)
                    {
                        let err =
                            DecodeError::new_err(format!("Invalid payload JSON: {}", e.value(py)));
                        err.set_cause(py, Some(e));
                        err
                    } else {
                        e
                    }
                })?
            }
            None => jws::with_b64_decoded::<MAX_STACK_PAYLOAD, _>(
                token.payload,
                "payload",
                |payload| {
                    PythonParse {
                        allow_inf_nan: false,
                        cache_mode: StringCacheMode::Keys,
                        partial_mode: PartialMode::Off,
                        catch_duplicate_keys: false,
                        float_mode: FloatMode::Float,
                    }
                    .python_parse(py, payload)
                    .map_err(|e| DecodeError::new_err(format!("Invalid payload JSON: {e}")))
                },
            )?,
        };
        let dict = parsed
            .cast_into::<PyDict>()
            .map_err(|_| DecodeError::new_err("Payload must be a JSON object"))?;
        claims::validate_dict(&dict, checks)?;
        Ok(dict)
    }

    fn typed_parser<'py>(&self, type_: &Bound<'py, PyAny>) -> PyResult<Bound<'py, TypedParser>> {
        let py = type_.py();
        let parsers = self.parsers.bind(py);
        if let Some(parser) = parsers.get_item(type_)? {
            return Ok(parser.cast_into()?);
        }
        let parser = Bound::new(py, TypedParser::new(type_)?)?;
        parsers.set_item(type_, &parser)?;
        Ok(parser)
    }

    /// Decodes the (verified) payload to a dict, or an instance of `type`, and validates its
    /// registered claims.
    #[inline]
    fn decode_payload<'py>(
        &self,
        py: Python<'py>,
        token: &jws::Segments<'_>,
        r#type: Option<&Bound<'py, PyAny>>,
        checks: &Checks<'_>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let Some(type_) = r#type else {
            return Ok(self.decode_dict(py, token, checks)?.into_any());
        };

        // A class, or a parametrised generic (`G[int]`), whose origin the parser checks.
        if !type_.is_instance_of::<PyType>() && !type_.hasattr(intern!(py, "__origin__"))? {
            return Err(PyTypeError::new_err(format!(
                "type must be None, a msgspec Struct or a pydantic BaseModel, got {}",
                type_.repr()?
            )));
        }
        let parser = self.typed_parser(type_)?;
        let payload = jws::b64_decode_to_pybytes(py, token.payload, "payload")?;
        parser.get().parse(&payload, checks)
    }

    /// Verifies the signature and returns the decoded claims, or why the token is invalid.
    fn decode_segments<'py>(
        &self,
        py: Python<'py>,
        token: &jws::Segments<'_>,
        r#type: Option<&Bound<'py, PyAny>>,
        checks: &Checks<'_>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.verify_signature(token)?;
        self.decode_payload(py, token, r#type, checks)
    }

    pub fn decode<'py>(
        &self,
        py: Python<'py>,
        token: &Bound<'py, PyAny>,
        r#type: Option<&Bound<'py, PyAny>>,
        audience: Option<&Bound<'py, PyAny>>,
        issuer: Option<&Bound<'py, PyAny>>,
        leeway: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let audience = Expected::parse(audience, "audience")?;
        let issuer = Expected::parse(issuer, "issuer")?;
        let checks = Checks::new(audience.or(&self.audience), issuer.or(&self.issuer), leeway)?;
        let token = jws::split(token_bytes(token)?)?;
        self.decode_segments(py, &token, r#type, &checks)
            .map_err(|e| {
                // A dot in the payload segment means more than three segments; that's what to report.
                if memchr::memchr(b'.', token.payload).is_some() {
                    jws::not_three_segments()
                } else {
                    e
                }
            })
    }
}
