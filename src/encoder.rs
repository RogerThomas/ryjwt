//! Signing and encoding tokens, for `SecretKey` and `PrivateKey`.

use std::mem::MaybeUninit;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDateTime, PyDict, PyMapping, PyString, PyType};
use pyo3::{ffi, intern};

use crate::errors::InvalidKeyError;
use crate::json_write;
use crate::jws;
use crate::keys::Signer;

/// What a dict's claims JSON is written into at first: room for all but unusually large claims.
const CLAIMS_JSON_CAPACITY: usize = 1024;

/// One configured algorithm to encode with.
struct EncodingAlgorithm {
    signer: Signer,
    /// The encoded header segment `encode` uses when no `header` is given.
    default_header: Box<[u8]>,
}

/// The key prepared to sign tokens with, per configured algorithm.
pub struct Encoder {
    algorithms: Vec<EncodingAlgorithm>,
    /// The key's `kid`, written into every token's header.
    kid: Option<Box<str>>,
    /// Claims class (a Struct or `BaseModel`) -> how its instances encode, built on the first use
    /// of each class.
    payload_encoders: Py<PyDict>,
}

/// How instances of one claims class (a Struct or `BaseModel`) encode:
/// `ryjwt._types.payload_encoder`'s (see its `PayloadEncoder`).
#[pyclass(frozen)]
struct PayloadEncoder {
    /// callable(instance) -> bytes; None for a `BaseModel` whose `model_dump_json` is pydantic's
    /// own, which `encode` does as that does.
    encode: Option<Py<PyAny>>,
    /// Whether that `BaseModel` encodes by alias.
    by_alias: bool,
    /// Per `NumericDate` claim the class has a field for: its JSON name, and its attribute.
    date_claims: Vec<(Py<PyString>, Py<PyString>)>,
    /// callable(instance) -> dict, and callable(dict) -> bytes: how an instance encodes when any of
    /// those holds a datetime, which is replaced in the dict.
    to_dict: Py<PyAny>,
    to_json: Py<PyAny>,
}

type PayloadEncoderParts<'py> = (
    Option<Bound<'py, PyAny>>,
    bool,
    Vec<(Bound<'py, PyString>, Bound<'py, PyString>)>,
    Bound<'py, PyAny>,
    Bound<'py, PyAny>,
);

impl PayloadEncoder {
    fn new(class: &Bound<'_, PyType>) -> PyResult<Self> {
        let py = class.py();
        let (encode, by_alias, date_claims, to_dict, to_json) = py
            .import(intern!(py, "ryjwt._types"))?
            .call_method1(intern!(py, "payload_encoder"), (class,))?
            .extract::<PayloadEncoderParts<'_>>()?;
        Ok(Self {
            encode: encode.map(Bound::unbind),
            by_alias,
            date_claims: date_claims
                .into_iter()
                .map(|(key, attribute)| (key.unbind(), attribute.unbind()))
                .collect(),
            to_dict: to_dict.unbind(),
            to_json: to_json.unbind(),
        })
    }

    /// Whether any of the instance's `NumericDate` claims holds a datetime.
    fn holds_datetime(&self, claims: &Bound<'_, PyAny>) -> PyResult<bool> {
        let py = claims.py();
        for (_, attribute) in &self.date_claims {
            if claims
                .getattr(attribute.bind(py))?
                .is_instance_of::<PyDateTime>()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The JSON of an instance whose `NumericDate` claims hold no datetime.
    fn encode<'py>(&self, claims: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let py = claims.py();
        if let Some(encode) = &self.encode {
            return encode.bind(py).call1((claims,));
        }
        // What `model_dump_json(by_alias=...).encode()` makes, without the round trip through str.
        let kwargs = PyDict::new(py);
        kwargs.set_item(intern!(py, "by_alias"), self.by_alias)?;
        claims
            .get_type()
            .getattr(intern!(py, "__pydantic_serializer__"))?
            .call_method(intern!(py, "to_json"), (claims,), Some(&kwargs))
    }

    /// The JSON of the instance as a dict, with each of its `NumericDate` claims that holds a
    /// datetime as a `NumericDate`.
    fn encode_with_dates<'py>(&self, claims: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let py = claims.py();
        let data = self.to_dict.bind(py).call1((claims,))?;
        for (key, attribute) in &self.date_claims {
            let key = key.bind(py);
            let value = claims.getattr(attribute.bind(py))?;
            if data.contains(key)? && value.is_instance_of::<PyDateTime>() {
                data.set_item(key, json_write::numeric_date(key.to_str()?, &value)?)?;
            }
        }
        self.to_json.bind(py).call1((data,))
    }
}

/// The claims JSON: written here, or by msgspec or pydantic.
enum ClaimsJson<'py> {
    Written(Vec<u8>),
    Encoded(Bound<'py, PyBytes>),
}

impl ClaimsJson<'_> {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Written(json) => json,
            Self::Encoded(json) => json.as_bytes(),
        }
    }
}

/// The token `header.payload.signature` (`header` already base64url-encoded) that `signer` signs,
/// written straight into the str returned, and signed from there.
fn signed_token<'py>(
    py: Python<'py>,
    header: &[u8],
    payload: &[u8],
    signer: &Signer,
) -> PyResult<Bound<'py, PyString>> {
    let signing_input_len = header.len() + 1 + jws::b64_encoded_len(payload.len());
    let signature_len = signer.signature_len();
    let len = signing_input_len + 1 + jws::b64_encoded_len(signature_len);
    let size = ffi::Py_ssize_t::try_from(len)
        .map_err(|_| PyValueError::new_err("The token would be too long"))?;
    // SAFETY: PyUnicode_New(size, 127) returns a new compact ASCII str of `size` characters, a byte
    // each (it writes the trailing NUL), not yet initialised, which we own exclusively until it's
    // returned. Exactly those `len` bytes are written below, each of them ASCII (base64url and
    // '.'): `b64_encode_into` fills a slice exactly, and the signature is checked to be
    // `signature_len` bytes long. If anything fails first, the str is dropped unread (as
    // `jws::b64_decode_to_pybytes` drops its bytes).
    unsafe {
        let ptr = ffi::PyUnicode_New(size, 127);
        let token = Bound::from_owned_ptr_or_err(py, ptr)?.cast_into_unchecked::<PyString>();
        let data = ffi::PyUnicode_DATA(ptr).cast::<MaybeUninit<u8>>();
        let out = std::slice::from_raw_parts_mut(data, len);
        let (signing_input, signature_out) = out.split_at_mut(signing_input_len);
        let (header_out, payload_out) = signing_input.split_at_mut(header.len());
        header_out.write_copy_of_slice(header);
        payload_out[0].write(b'.');
        jws::b64_encode_into(payload, &mut payload_out[1..]);
        let signing_input = signing_input.assume_init_ref();
        signature_out[0].write(b'.');
        signer.sign(signing_input, |signature| {
            if signature.len() != signature_len {
                return Err(InvalidKeyError::new_err("Signing failed"));
            }
            jws::b64_encode_into(signature, &mut signature_out[1..]);
            Ok(())
        })??;
        Ok(token)
    }
}

/// The header JSON for `alg`, with the key's `kid` if it has one, the parameters in `header`, and a
/// `"typ": "JWT"` unless `header` sets one.
fn header_json(
    alg: &str,
    kid: Option<&str>,
    header: Option<&Bound<'_, PyMapping>>,
) -> PyResult<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"{\"alg\":");
    json_write::write_str(&mut out, alg);
    if let Some(kid) = kid {
        out.extend_from_slice(b",\"kid\":");
        json_write::write_str(&mut out, kid);
    }
    let mut has_typ = false;
    let items = match header {
        Some(header) => header.items()?.iter().collect(),
        None => Vec::new(),
    };
    let parameters = items.len();
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
                    "Set the algorithm with algorithm=, not header",
                ));
            }
            // What `decode` would reject: tokens it can't decode aren't made.
            "crit" => {
                return Err(PyValueError::new_err(
                    "Critical headers (crit) aren't supported: decode rejects them",
                ));
            }
            "b64" => {
                return Err(PyValueError::new_err(
                    "Unencoded payloads (b64) aren't supported",
                ));
            }
            // The key's and the header's could disagree.
            "kid" if let Some(kid) = kid => {
                return Err(PyValueError::new_err(format!(
                    "This key sets kid ({kid:?}) in every header: drop kid from header, or from \
                     the key"
                )));
            }
            "kid" if !value.is_instance_of::<PyString>() => {
                return Err(PyTypeError::new_err(format!(
                    "Header kid must be str, got {}",
                    value.get_type().name()?
                )));
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
    // With `alg`, and the key's `kid` and `typ` if added.
    if parameters + 1 + usize::from(kid.is_some()) + usize::from(!has_typ)
        > jws::MAX_HEADER_PARAMETERS
    {
        return Err(PyValueError::new_err(format!(
            "Header has more parameters than decode takes ({}, with alg, typ and the key's kid)",
            jws::MAX_HEADER_PARAMETERS
        )));
    }
    out.push(b'}');
    Ok(out)
}

impl Encoder {
    pub fn new(py: Python<'_>, signers: Vec<Signer>, kid: Option<&str>) -> PyResult<Self> {
        let algorithms = signers
            .into_iter()
            .map(|signer| {
                let mut default_header = Vec::new();
                jws::b64_encode_append(
                    &header_json(signer.algorithm, kid, None)?,
                    &mut default_header,
                );
                Ok(EncodingAlgorithm {
                    signer,
                    default_header: default_header.into_boxed_slice(),
                })
            })
            .collect::<PyResult<_>>()?;
        Ok(Self {
            algorithms,
            kid: kid.map(Into::into),
            payload_encoders: PyDict::new(py).unbind(),
        })
    }

    /// How instances of `class` encode, built on its first use.
    fn payload_encoder<'py>(
        &self,
        class: &Bound<'py, PyType>,
    ) -> PyResult<Bound<'py, PayloadEncoder>> {
        let py = class.py();
        let encoders = self.payload_encoders.bind(py);
        if let Some(encoder) = encoders.get_item(class)? {
            return Ok(encoder.cast_into()?);
        }
        let encoder = Bound::new(py, PayloadEncoder::new(class)?)?;
        encoders.set_item(class, &encoder)?;
        Ok(encoder)
    }

    /// Encodes a Struct/BaseModel (anything but a dict) via the library that defined it; with its
    /// datetime `exp`, `nbf` and `iat` claims as `NumericDate`s, if it has any.
    fn encode_typed_claims<'py>(
        &self,
        claims: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let encoder = self.payload_encoder(&claims.get_type())?;
        let encoder = encoder.get();
        let json = if encoder.holds_datetime(claims)? {
            encoder.encode_with_dates(claims)?
        } else {
            encoder.encode(claims)?
        };
        let json = json.cast_into::<PyBytes>()?;
        if json.as_bytes().trim_ascii_start().first() != Some(&b'{') {
            return Err(PyTypeError::new_err(
                "claims must serialize to a JSON object",
            ));
        }
        Ok(json)
    }

    /// The claims as JSON: a dict written here, anything else by the library that defined it.
    fn claims_json<'py>(&self, claims: &Bound<'py, PyAny>) -> PyResult<ClaimsJson<'py>> {
        let Ok(dict) = claims.cast::<PyDict>() else {
            return Ok(ClaimsJson::Encoded(self.encode_typed_claims(claims)?));
        };
        let mut out = Vec::with_capacity(CLAIMS_JSON_CAPACITY);
        json_write::write_claims(&mut out, dict)?;
        Ok(ClaimsJson::Written(out))
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
        header: Option<&Bound<'_, PyMapping>>,
    ) -> PyResult<Bound<'py, PyString>> {
        let algorithm = self.algorithm(algorithm)?;
        let payload = self.claims_json(claims)?;
        let mut custom_header = Vec::new();
        let header = match header {
            None => &algorithm.default_header,
            Some(header) => {
                jws::b64_encode_append(
                    &header_json(
                        algorithm.signer.algorithm,
                        self.kid.as_deref(),
                        Some(header),
                    )?,
                    &mut custom_header,
                );
                &custom_header[..]
            }
        };
        signed_token(claims.py(), header, payload.as_bytes(), &algorithm.signer)
    }
}
