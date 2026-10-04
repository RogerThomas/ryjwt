//! Compact JSON serialisation of plain Python values (dict/list/tuple/str/int/float/bool/None).

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

const MAX_DEPTH: u32 = 255;

/// Whether any byte needs escaping in a JSON string (`"`, `\\`, or a control character). Branch-free
/// per chunk so it vectorises.
fn needs_escape(bytes: &[u8]) -> bool {
    let flag = |acc: bool, &b: &u8| acc | (b < 0x20) | (b == b'"') | (b == b'\\');
    let mut chunks = bytes.chunks_exact(16);
    for chunk in &mut chunks {
        if chunk.iter().fold(false, flag) {
            return true;
        }
    }
    chunks.remainder().iter().fold(false, flag)
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

pub fn write_value(out: &mut Vec<u8>, value: &Bound<'_, PyAny>, depth: u32) -> PyResult<()> {
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
        match i.extract::<i64>() {
            Ok(i) => out.extend_from_slice(itoa::Buffer::new().format(i).as_bytes()),
            Err(_) => out.extend_from_slice(i.str()?.to_str()?.as_bytes()),
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
        write_object(out, dict, depth)?;
    } else if let Ok(list) = value.cast::<PyList>() {
        write_array(out, list.iter(), depth)?;
    } else if let Ok(tuple) = value.cast::<PyTuple>() {
        write_array(out, tuple.iter(), depth)?;
    } else {
        return Err(PyTypeError::new_err(format!(
            "Object of type {} is not JSON serializable",
            value.get_type().name()?
        )));
    }
    Ok(())
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

pub fn write_object(out: &mut Vec<u8>, dict: &Bound<'_, PyDict>, depth: u32) -> PyResult<()> {
    out.push(b'{');
    for (i, (key, value)) in dict.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        let key = key
            .cast::<PyString>()
            .map_err(|_| PyTypeError::new_err("Claim names must be str"))?;
        write_str(out, key.to_str()?);
        out.push(b':');
        write_value(out, &value, depth + 1)?;
    }
    out.push(b'}');
    Ok(())
}
