//! Compact JWS: parsing (segments, strict base64url, header) and assembling signed tokens.

use std::mem::MaybeUninit;

use base64_simd::{Out, URL_SAFE_NO_PAD};
use jiter::{JsonObject, JsonValue};
use pyo3::PyResult;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::errors::{DecodeError, InvalidAlgorithmError, InvalidTokenError};

pub struct Segments<'a> {
    pub header: &'a [u8],
    pub payload: &'a [u8],
    pub signature: &'a [u8],
    pub signing_input: &'a [u8],
}

/// Real headers have a handful of parameters; capping them bounds the duplicate check (quadratic,
/// but cheaper than hashing at this size) on attacker-controlled input.
pub const MAX_HEADER_PARAMETERS: usize = 64;

pub fn not_three_segments() -> PyErr {
    DecodeError::new_err("Token must have exactly three segments")
}

fn b64_error(name: &str) -> PyErr {
    DecodeError::new_err(format!("Invalid {name} encoding: not unpadded base64url"))
}

/// Decoded length of an unpadded base64url segment (fails on impossible lengths).
fn b64_len(segment: &[u8], name: &str) -> PyResult<usize> {
    URL_SAFE_NO_PAD
        .decoded_length(segment)
        .map_err(|_| b64_error(name))
}

/// Unpadded base64url (RFC 7515 §2), canonical: no `=` and no stray trailing bits. `out` must be
/// exactly the decoded length.
fn b64_decode_into<'o>(
    segment: &[u8],
    out: &'o mut [MaybeUninit<u8>],
    name: &str,
) -> PyResult<&'o [u8]> {
    URL_SAFE_NO_PAD
        .decode(segment, Out::from_uninit_slice(out))
        .map(|decoded| &*decoded)
        .map_err(|_| b64_error(name))
}

/// Runs `f` on the decoded segment, decoding onto the stack when it's at most `N` bytes.
pub fn with_b64_decoded<const N: usize, R>(
    segment: &[u8],
    name: &str,
    f: impl FnOnce(&[u8]) -> PyResult<R>,
) -> PyResult<R> {
    let len = b64_len(segment, name)?;
    if len <= N {
        let mut buf = [MaybeUninit::<u8>::uninit(); N];
        f(b64_decode_into(segment, &mut buf[..len], name)?)
    } else {
        let mut buf = Vec::<u8>::with_capacity(len);
        f(b64_decode_into(
            segment,
            &mut buf.spare_capacity_mut()[..len],
            name,
        )?)
    }
}

/// Decodes a segment straight into a new `bytes` object (no intermediate buffer).
pub fn b64_decode_to_pybytes<'py>(
    py: Python<'py>,
    segment: &[u8],
    name: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let len = b64_len(segment, name)?;
    let size = pyo3::ffi::Py_ssize_t::try_from(len)
        .map_err(|_| DecodeError::new_err(format!("Invalid {name}: too long")))?;
    // SAFETY: PyBytes_FromStringAndSize(NULL, len) returns a new bytes object with `len`
    // uninitialised bytes (plus a trailing NUL) that we own exclusively until it's returned; we
    // fully initialise those bytes before anyone else can see the object.
    unsafe {
        let ptr = pyo3::ffi::PyBytes_FromStringAndSize(std::ptr::null(), size);
        let bytes = Bound::from_owned_ptr_or_err(py, ptr)?.cast_into_unchecked::<PyBytes>();
        let data = pyo3::ffi::PyBytes_AsString(ptr).cast::<MaybeUninit<u8>>();
        b64_decode_into(segment, std::slice::from_raw_parts_mut(data, len), name)?;
        Ok(bytes)
    }
}

/// Appends the unpadded base64url encoding of `data` to `out`.
pub fn b64_encode_append(data: &[u8], out: &mut Vec<u8>) {
    URL_SAFE_NO_PAD.encode_append(data, out);
}

/// The header's `alg`, and its `kid` if `want_kid` (which must then be a string if present), after
/// checking the header is a well-formed object with no duplicate parameters and no `crit`.
pub fn parse_header(segment: &[u8], want_kid: bool) -> PyResult<(String, Option<String>)> {
    with_b64_decoded::<256, _>(segment, "header", |header| {
        parse_header_json(header, want_kid)
    })
}

/// The header's parameters, after checking it's a JSON object with at most
/// `MAX_HEADER_PARAMETERS` of them, none repeated.
fn header_object(header_bytes: &[u8]) -> PyResult<JsonObject<'_>> {
    let header = match JsonValue::parse(header_bytes, false) {
        Ok(JsonValue::Object(header)) => header,
        Ok(_) => {
            return Err(DecodeError::new_err(
                "Invalid header: must be a JSON object",
            ));
        }
        Err(e) => return Err(DecodeError::new_err(format!("Invalid header JSON: {e}"))),
    };
    if header.len() > MAX_HEADER_PARAMETERS {
        return Err(DecodeError::new_err(format!(
            "Invalid header: more than {MAX_HEADER_PARAMETERS} parameters"
        )));
    }
    let keys: Vec<&str> = header.iter().map(|(k, _)| k.as_ref()).collect();
    if let Some(dup) = keys
        .iter()
        .enumerate()
        .find_map(|(i, k)| keys[..i].contains(k).then_some(k))
    {
        return Err(DecodeError::new_err(format!(
            "Invalid header: duplicate {dup:?} parameter"
        )));
    }
    Ok(header)
}

fn parse_header_json(header_bytes: &[u8], want_kid: bool) -> PyResult<(String, Option<String>)> {
    let header = header_object(header_bytes)?;
    let mut alg = None;
    let mut kid = None;
    for (name, value) in header.iter() {
        match (name.as_ref(), value) {
            // RFC 7515 §4.1.11: critical extensions we don't understand MUST be rejected (we know none).
            ("crit", _) => {
                return Err(InvalidTokenError::new_err(
                    "Unsupported critical header (crit)",
                ));
            }
            ("alg", JsonValue::Str(s)) => alg = Some(s.to_string()),
            ("alg", _) => {
                return Err(InvalidAlgorithmError::new_err(
                    "Header alg must be a string",
                ));
            }
            ("kid", JsonValue::Str(s)) if want_kid => kid = Some(s.to_string()),
            ("kid", _) if want_kid => {
                return Err(DecodeError::new_err("Header kid must be a string"));
            }
            _ => {}
        }
    }
    let alg = alg.ok_or_else(|| InvalidAlgorithmError::new_err("Header alg is missing"))?;
    Ok((alg, kid))
}

/// The header as a dict, checked as `parse_header` checks it, but not for its `alg`, `kid` or
/// `crit`: for reading a token's header without verifying the token.
pub fn header_dict<'py>(py: Python<'py>, segment: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    with_b64_decoded::<256, _>(segment, "header", |header| {
        let dict = PyDict::new(py);
        for (name, value) in header_object(header)?.iter() {
            dict.set_item(name.as_ref(), value)?;
        }
        Ok(dict)
    })
}

/// Splits on the first and last dots. A payload segment containing a further dot is caught later
/// (it can't decode as base64url); callers report it as a segment-count error.
pub fn split(token: &[u8]) -> PyResult<Segments<'_>> {
    let first = memchr::memchr(b'.', token).ok_or_else(not_three_segments)?;
    let last = memchr::memrchr(b'.', token).ok_or_else(not_three_segments)?;
    if first == last {
        return Err(not_three_segments());
    }
    Ok(Segments {
        header: &token[..first],
        payload: &token[first + 1..last],
        signature: &token[last + 1..],
        signing_input: &token[..last],
    })
}
