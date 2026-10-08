//! Signing and encoding tokens, for `HMAC` and `PrivateKey`.

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDateTime, PyDict, PyMapping, PyString, PyTuple, PyType};

use crate::json_write;
use crate::jws;
use crate::keys::Signer;

/// One configured algorithm to encode with.
struct EncodingAlgorithm {
    signer: Signer,
    /// The encoded header segment `encode` uses when no `headers` are given.
    default_header: Box<[u8]>,
}

/// The key prepared to sign tokens with, per configured algorithm.
pub struct Encoder {
    algorithms: Vec<EncodingAlgorithm>,
    /// Claims class (a Struct or `BaseModel`) -> how its instances encode, built on the first use
    /// of each class: `ryjwt._types.payload_encoder`'s (encode, date attributes, encode with
    /// dates).
    payload_encoders: Py<PyDict>,
}

/// The header JSON for `alg`, with the given `headers` and a `"typ": "JWT"` unless they set one.
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
        let name = match name.cast_into::<PyString>() {
            Ok(name) => name,
            Err(e) => {
                return Err(PyTypeError::new_err(format!(
                    "Header names must be str, got {}",
                    e.into_inner().get_type().name()?
                )));
            }
        };
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

impl Encoder {
    pub fn new(py: Python<'_>, signers: Vec<Signer>) -> PyResult<Self> {
        let algorithms = signers
            .into_iter()
            .map(|signer| {
                let mut default_header = Vec::new();
                jws::b64_encode_append(&header_json(signer.algorithm, None)?, &mut default_header);
                Ok(EncodingAlgorithm {
                    signer,
                    default_header: default_header.into_boxed_slice(),
                })
            })
            .collect::<PyResult<_>>()?;
        Ok(Self {
            algorithms,
            payload_encoders: PyDict::new(py).unbind(),
        })
    }

    /// How instances of `class` encode, built on its first use.
    fn payload_encoder<'py>(&self, class: &Bound<'py, PyType>) -> PyResult<Bound<'py, PyTuple>> {
        let py = class.py();
        let encoders = self.payload_encoders.bind(py);
        if let Some(encoder) = encoders.get_item(class)? {
            return Ok(encoder.cast_into::<PyTuple>()?);
        }
        let encoder = py
            .import(intern!(py, "ryjwt._types"))?
            .call_method1(intern!(py, "payload_encoder"), (class,))?
            .cast_into::<PyTuple>()?;
        encoders.set_item(class, &encoder)?;
        Ok(encoder)
    }

    /// Encodes a Struct/BaseModel (anything but a dict) via the library that defined it; with its
    /// datetime `exp`, `nbf` and `iat` claims as `NumericDate`s, if it has any.
    fn encode_typed_claims(&self, claims: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
        let encoder = self.payload_encoder(&claims.get_type())?;
        let date_attributes = encoder.get_borrowed_item(1)?;
        let mut with_dates = false;
        for attribute in date_attributes.cast::<PyTuple>()?.iter_borrowed() {
            let value = claims.getattr(attribute.cast::<PyString>()?)?;
            if value.is_instance_of::<PyDateTime>() {
                with_dates = true;
                break;
            }
        }
        let encode = encoder.get_borrowed_item(if with_dates { 2 } else { 0 })?;
        let json = encode.call1((claims,))?;
        let bytes = json.cast::<PyBytes>()?.as_bytes();
        if bytes.trim_ascii_start().first() != Some(&b'{') {
            return Err(PyTypeError::new_err(
                "claims must serialize to a JSON object",
            ));
        }
        Ok(bytes.to_vec())
    }

    /// The claims as JSON: a dict written here, anything else by the library that defined it.
    fn claims_json(&self, claims: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
        let Ok(dict) = claims.cast::<PyDict>() else {
            return self.encode_typed_claims(claims);
        };
        let mut out = Vec::with_capacity(256);
        json_write::write_claims(&mut out, dict)?;
        Ok(out)
    }

    /// The configured algorithm `name`, or the only one configured if `name` is None.
    fn algorithm(&self, name: Option<&str>) -> PyResult<&EncodingAlgorithm> {
        match (name, self.algorithms.as_slice()) {
            (None, [only]) => Ok(only),
            (None, _) => Err(PyValueError::new_err(
                "Several algorithms are configured: pass algorithm=",
            )),
            (Some(name), algorithms) => algorithms
                .iter()
                .find(|a| a.signer.algorithm == name)
                .ok_or_else(|| {
                    PyValueError::new_err(format!(
                        "algorithm {name:?} is not one of the configured algorithms"
                    ))
                }),
        }
    }

    pub fn encode<'py>(
        &self,
        claims: &Bound<'py, PyAny>,
        algorithm: Option<&str>,
        headers: Option<&Bound<'_, PyMapping>>,
    ) -> PyResult<Bound<'py, PyString>> {
        let algorithm = self.algorithm(algorithm)?;
        let payload = self.claims_json(claims)?;
        let mut token = Vec::with_capacity(64 + payload.len() * 4 / 3 + 700);
        match headers {
            None => token.extend_from_slice(&algorithm.default_header),
            Some(headers) => jws::b64_encode_append(
                &header_json(algorithm.signer.algorithm, Some(headers))?,
                &mut token,
            ),
        }
        token.push(b'.');
        jws::b64_encode_append(&payload, &mut token);
        let signature = algorithm.signer.sign(&token)?;
        token.push(b'.');
        jws::b64_encode_append(&signature, &mut token);
        // SAFETY: base64url and '.' are ASCII.
        Ok(PyString::new(claims.py(), unsafe {
            std::str::from_utf8_unchecked(&token)
        }))
    }
}
