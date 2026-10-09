//! Compact JSON serialisation of plain Python values (dict/list/tuple/str/int/float/bool/None),
//! and of datetime `exp`, `nbf` and `iat` claims as `NumericDate`s.

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDateTime, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

pub const MAX_DEPTH: u32 = 255;

/// Whether any byte needs escaping in a JSON string (`"`, `\\`, or a control character). Branch-free
/// per chunk so it vectorises.
fn needs_escape(bytes: &[u8]) -> bool {
    let flag =
        |acc: u8, &b: &u8| acc | u8::from(b < 0x20) | u8::from(b == b'"') | u8::from(b == b'\\');
    let (chunks, remainder) = bytes.as_chunks::<16>();
    for chunk in chunks {
        if chunk.iter().fold(0, flag) != 0 {
            return true;
        }
    }
    remainder.iter().fold(0, flag) != 0
}

pub fn write_str(out: &mut Vec<u8>, s: &str) {
    if !needs_escape(s.as_bytes()) {
        out.reserve(s.len() + 2);
        out.push(b'"');
        out.extend_from_slice(s.as_bytes());
        out.push(b'"');
        return;
    }
    out.push(b'"');
    let mut start = 0;
    for (i, &b) in s.as_bytes().iter().enumerate() {
        let escape: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x08 => b"\\b",
            0x0C => b"\\f",
            0x00..=0x1F => &[],
            _ => continue,
        };
        out.extend_from_slice(&s.as_bytes()[start..i]);
        if escape.is_empty() {
            out.extend_from_slice(format!("\\u{b:04x}").as_bytes());
        } else {
            out.extend_from_slice(escape);
        }
        start = i + 1;
    }
    out.extend_from_slice(&s.as_bytes()[start..]);
    out.push(b'"');
}

fn not_serializable(value: &Bound<'_, PyAny>) -> PyErr {
    match value.get_type().name() {
        Ok(name) => PyTypeError::new_err(format!("Object of type {name} is not JSON serializable")),
        Err(e) => e,
    }
}

/// Writes `value` if it's a plain value (see the module docs), else returns false, writing nothing.
fn write_plain(out: &mut Vec<u8>, value: &Bound<'_, PyAny>, depth: u32) -> PyResult<bool> {
    if depth > MAX_DEPTH {
        return Err(PyValueError::new_err("Claims are nested too deeply"));
    }
    // Exact str first: by far the most common claim value (and the float check below is a
    // subtype check, i.e. a function call, for everything that isn't exactly a float).
    if let Ok(s) = value.cast_exact::<PyString>() {
        write_str(out, s.to_str()?);
    } else if value.is_none() {
        out.extend_from_slice(b"null");
    } else if let Ok(b) = value.cast::<PyBool>() {
        out.extend_from_slice(if b.is_true() { b"true" } else { b"false" });
    } else if let Ok(i) = value.cast::<PyInt>() {
        if let Ok(i) = i.extract::<i64>() {
            out.extend_from_slice(itoa::Buffer::new().format(i).as_bytes());
        } else {
            // `int.__repr__`, not the value's own `__str__`/`__repr__`, which a subclass may
            // override.
            let py = i.py();
            let digits = py
                .get_type::<PyInt>()
                .call_method1(intern!(py, "__repr__"), (i,))?;
            out.extend_from_slice(digits.cast::<PyString>()?.to_str()?.as_bytes());
        }
    } else if let Ok(f) = value.cast::<PyFloat>() {
        let f = f.value();
        if !f.is_finite() {
            return Err(PyValueError::new_err(
                "Out of range float values (nan, inf) are not JSON compliant",
            ));
        }
        out.extend_from_slice(ryu::Buffer::new().format_finite(f).as_bytes());
    } else if let Ok(s) = value.cast::<PyString>() {
        write_str(out, s.to_str()?);
    } else if let Ok(dict) = value.cast::<PyDict>() {
        write_members(out, dict, depth, false)?;
    } else if let Ok(list) = value.cast::<PyList>() {
        write_array(out, list.iter(), depth)?;
    } else if let Ok(tuple) = value.cast::<PyTuple>() {
        write_array(out, tuple.iter(), depth)?;
    } else {
        return Ok(false);
    }
    Ok(true)
}

pub fn write_value(out: &mut Vec<u8>, value: &Bound<'_, PyAny>, depth: u32) -> PyResult<()> {
    if write_plain(out, value, depth)? {
        Ok(())
    } else {
        Err(not_serializable(value))
    }
}

fn write_array<'py>(
    out: &mut Vec<u8>,
    items: impl Iterator<Item = Bound<'py, PyAny>>,
    depth: u32,
) -> PyResult<()> {
    out.push(b'[');
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push(b',');
        }
        write_value(out, &item, depth + 1)?;
    }
    out.push(b']');
    Ok(())
}

/// A datetime `exp`, `nbf` or `iat` claim as a `NumericDate` (whole seconds since the epoch).
fn write_numeric_date(out: &mut Vec<u8>, claim: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
    let py = value.py();
    let seconds = py
        .import(intern!(py, "ryjwt._types"))?
        .call_method1(intern!(py, "numeric_date"), (claim, value))?;
    write_value(out, &seconds, 1)
}

/// Writes a dict as a JSON object; if `claims` (the claims object itself), a datetime `exp`, `nbf`
/// or `iat` as a `NumericDate`.
fn write_members(
    out: &mut Vec<u8>,
    dict: &Bound<'_, PyDict>,
    depth: u32,
    claims: bool,
) -> PyResult<()> {
    out.push(b'{');
    for (i, (key, value)) in dict.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        let key = match key.cast::<PyString>() {
            Ok(key) => key.to_str()?,
            Err(_) => {
                return Err(PyTypeError::new_err(format!(
                    "Object member names must be str, got {}",
                    key.get_type().name()?
                )));
            }
        };
        write_str(out, key);
        out.push(b':');
        // Datetimes are checked for only once the plain types are ruled out: free for the rest.
        if !write_plain(out, &value, depth + 1)? {
            if claims
                && matches!(key, "exp" | "nbf" | "iat")
                && value.is_instance_of::<PyDateTime>()
            {
                write_numeric_date(out, key, &value)?;
            } else {
                return Err(not_serializable(&value));
            }
        }
    }
    out.push(b'}');
    Ok(())
}

/// Writes the claims dict as a JSON object, with a datetime `exp`, `nbf` or `iat` as a
/// `NumericDate`.
pub fn write_claims(out: &mut Vec<u8>, claims: &Bound<'_, PyDict>) -> PyResult<()> {
    write_members(out, claims, 0, true)
}

/// Writes any other dict (e.g. a JWKS document) as a JSON object: datetimes aren't JSON.
pub fn write_object(out: &mut Vec<u8>, dict: &Bound<'_, PyDict>) -> PyResult<()> {
    write_members(out, dict, 0, false)
}
