//! ryjwt: fast JWT encoding and decoding for Python, backed by Rust (aws-lc-rs + jiter).

mod claims;
mod errors;
mod json_write;
mod jws;
mod keys;
mod mac;

use jiter::{FloatMode, PartialMode, PythonParse, StringCacheMode};
use std::sync::OnceLock;

use pyo3::exceptions::{PyImportError, PyTypeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyMapping, PyString, PyType};

use claims::Checks;
use errors::{DecodeError, InvalidAlgorithmError, InvalidSignatureError};
use keys::PreparedAlg;

/// Encodes and decodes JWTs with one key, for the configured algorithms.
#[pyclass(frozen, module = "ryjwt", name = "RYJWT")]
struct Ryjwt {
    algorithms: Vec<PreparedAlg>,
    /// `type` -> callable(bytes) -> instance, built on first use of each `type`.
    parsers: Py<PyDict>,
    /// msgspec's untyped JSON decoder if msgspec is installed (it builds typical-sized payload
    /// dicts faster than jiter), else None for jiter. Resolved once, in `new`.
    dict_decoder: Option<Py<PyAny>>,
    /// Header segments already seen on a successfully verified token, with the index of their
    /// algorithm. A token's header is a pure function of its bytes, so a byte-identical header
    /// needn't be base64-decoded and parsed again. Entries are only added after the signature
    /// checked out, so only the key holder can fill the (fixed, small) cache.
    known_headers: [OnceLock<(Box<[u8]>, usize)>; KNOWN_HEADERS],
    /// Per algorithm, the encoded header segment `encode` uses when no `headers` are given.
    default_headers: Vec<Box<[u8]>>,
}

/// Tokens signed by one key nearly always share one header (or a handful).
const KNOWN_HEADERS: usize = 4;

/// Signatures (at most 1024 bytes, for RSA-8192) are decoded on the stack.
const MAX_STACK_SIGNATURE: usize = 1024;
/// Payloads up to this size are decoded on the stack when they needn't outlive the call.
const MAX_STACK_PAYLOAD: usize = 4096;

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

/// Encodes a Struct/BaseModel (anything but a dict) via the library that defined it.
fn encode_typed_claims(claims: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let py = claims.py();
    let encoded = py
        .import(intern!(py, "ryjwt._types"))?
        .call_method1(intern!(py, "encode_claims"), (claims,))?;
    let bytes = encoded.cast::<PyBytes>()?.as_bytes();
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return Err(PyTypeError::new_err("claims must serialise to a JSON object"));
    }
    Ok(bytes.to_vec())
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

impl Ryjwt {
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

    /// Verifies the signature and returns the decoded claims, or why the token is invalid.
    fn decode_segments<'py>(
        &self,
        py: Python<'py>,
        token: &jws::Segments<'_>,
        r#type: Option<&Bound<'py, PyAny>>,
        checks: &Checks<'_>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let known = self.known_header(token.header);
        let index = match known {
            Some(index) => index,
            None => {
                let alg = jws::parse_header(token.header)?;
                self.algorithms
                    .iter()
                    .position(|a| a.name == alg)
                    .ok_or_else(|| {
                        InvalidAlgorithmError::new_err(format!("Algorithm {alg:?} is not allowed"))
                    })?
            }
        };
        let verified =
            jws::with_b64_decoded::<MAX_STACK_SIGNATURE, _>(token.signature, "signature", |sig| {
                Ok(self.algorithms[index].verify(token.signing_input, sig))
            })?;
        if !verified {
            return Err(InvalidSignatureError::new_err("Signature verification failed"));
        }
        if known.is_none() {
            self.remember_header(token.header, index);
        }

        let type_ = r#type.filter(|t| !t.is(py.get_type::<PyDict>()));
        let Some(type_) = type_ else {
            let parsed = match &self.dict_decoder {
                Some(decoder) => {
                    let payload = jws::b64_decode_to_pybytes(py, token.payload, "payload")?;
                    decoder.bind(py).call1((payload,)).map_err(|e| {
                        // msgspec's DecodeError and UnicodeDecodeError are both ValueErrors.
                        if e.is_instance_of::<PyValueError>(py) {
                            let err = DecodeError::new_err(format!("Invalid payload JSON: {}", e.value(py)));
                            err.set_cause(py, Some(e));
                            err
                        } else {
                            e
                        }
                    })?
                }
                None => jws::with_b64_decoded::<MAX_STACK_PAYLOAD, _>(token.payload, "payload", |payload| {
                    PythonParse {
                        allow_inf_nan: false,
                        cache_mode: StringCacheMode::Keys,
                        partial_mode: PartialMode::Off,
                        catch_duplicate_keys: false,
                        float_mode: FloatMode::Float,
                    }
                    .python_parse(py, payload)
                    .map_err(|e| DecodeError::new_err(format!("Invalid payload JSON: {e}")))
                })?,
            };
            let dict = parsed
                .cast_into::<PyDict>()
                .map_err(|_| DecodeError::new_err("Payload must be a JSON object"))?;
            claims::validate_dict(&dict, checks)?;
            return Ok(dict.into_any());
        };

        if !type_.is_instance_of::<PyType>() {
            return Err(PyTypeError::new_err(
                "type must be dict, a msgspec Struct or a pydantic BaseModel",
            ));
        }
        let parser = self.parser(type_)?;
        let payload = jws::b64_decode_to_pybytes(py, token.payload, "payload")?;
        checks.validate(&claims::scan(payload.as_bytes())?)?;
        parser.call1((payload,))
    }

    fn parser<'py>(&self, type_: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let py = type_.py();
        let parsers = self.parsers.bind(py);
        if let Some(parser) = parsers.get_item(type_)? {
            return Ok(parser);
        }
        let parser = py
            .import(intern!(py, "ryjwt._types"))?
            .call_method1(intern!(py, "payload_parser"), (type_,))?;
        parsers.set_item(type_, &parser)?;
        Ok(parser)
    }

    fn algorithm(&self, name: Option<&str>) -> PyResult<usize> {
        match (name, self.algorithms.as_slice()) {
            (None, [_]) => Ok(0),
            (None, _) => Err(PyValueError::new_err(
                "Several algorithms are configured: pass algorithm=",
            )),
            (Some(name), algs) => algs.iter().position(|a| a.name == name).ok_or_else(|| {
                PyValueError::new_err(format!(
                    "algorithm {name:?} is not one of the configured algorithms"
                ))
            }),
        }
    }

    fn header_json(alg: &str, headers: Option<&Bound<'_, PyMapping>>) -> PyResult<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"{\"alg\":");
        json_write::write_str(&mut out, alg);
        let mut has_typ = false;
        let items = match headers {
            Some(headers) => headers.items()?.iter().collect(),
            None => Vec::new(),
        };
        for item in items {
            let (name, value): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item.extract()?;
            let name = name
                .cast_into::<PyString>()
                .map_err(|_| PyTypeError::new_err("Header names must be str"))?;
            match name.to_str()? {
                "alg" => {
                    return Err(PyValueError::new_err(
                        "Set the algorithm with algorithm=, not headers",
                    ));
                }
                "typ" => has_typ = true,
                _ => {}
            }
            out.push(b',');
            json_write::write_str(&mut out, name.to_str()?);
            out.push(b':');
            json_write::write_value(&mut out, &value, 1)?;
        }
        if !has_typ {
            out.extend_from_slice(b",\"typ\":\"JWT\"");
        }
        out.push(b'}');
        Ok(out)
    }
}

#[pymethods]
impl Ryjwt {
    #[new]
    #[pyo3(signature = (key, *, algorithms))]
    fn new(py: Python<'_>, key: &Bound<'_, PyAny>, algorithms: Vec<String>) -> PyResult<Self> {
        let algorithms = keys::prepare(key, &algorithms)?;
        let default_headers = algorithms
            .iter()
            .map(|a| {
                let mut segment = Vec::new();
                jws::b64_encode_append(&Self::header_json(a.name, None)?, &mut segment);
                Ok(segment.into_boxed_slice())
            })
            .collect::<PyResult<_>>()?;
        Ok(Self {
            algorithms,
            default_headers,
            parsers: PyDict::new(py).unbind(),
            dict_decoder: msgspec_dict_decoder(py)?,
            known_headers: Default::default(),
        })
    }

    /// The configured algorithm names.
    #[getter]
    fn algorithms(&self) -> Vec<&'static str> {
        self.algorithms.iter().map(|a| a.name).collect()
    }

    #[pyo3(signature = (claims, *, algorithm=None, headers=None))]
    fn encode<'py>(
        &self,
        claims: &Bound<'py, PyAny>,
        algorithm: Option<&str>,
        headers: Option<&Bound<'_, PyMapping>>,
    ) -> PyResult<Bound<'py, PyString>> {
        let index = self.algorithm(algorithm)?;
        let prepared = &self.algorithms[index];
        let payload = match claims.cast::<PyDict>() {
            Ok(dict) => {
                let mut out = Vec::with_capacity(256);
                json_write::write_object(&mut out, dict, 0)?;
                out
            }
            Err(_) => encode_typed_claims(claims)?,
        };
        let mut token = Vec::with_capacity(64 + payload.len() * 4 / 3 + 700);
        match headers {
            None => token.extend_from_slice(&self.default_headers[index]),
            Some(headers) => {
                jws::b64_encode_append(&Self::header_json(prepared.name, Some(headers))?, &mut token)
            }
        }
        token.push(b'.');
        jws::b64_encode_append(&payload, &mut token);
        let signature = prepared.sign(&token)?;
        token.push(b'.');
        jws::b64_encode_append(&signature, &mut token);
        // SAFETY: base64url and '.' are ASCII.
        Ok(PyString::new(claims.py(), unsafe {
            std::str::from_utf8_unchecked(&token)
        }))
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
        let checks = Checks::new(audience, issuer, leeway)?;
        let token = jws::split(token_bytes(token)?)?;
        self.decode_segments(py, &token, r#type, &checks).map_err(|e| {
            // A dot in the payload segment means more than three segments; that's what to report.
            if memchr::memchr(b'.', token.payload).is_some() {
                jws::not_three_segments()
            } else {
                e
            }
        })
    }
}

#[pymodule]
fn _ryjwt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Ryjwt>()?;
    errors::register(m)?;
    Ok(())
}
