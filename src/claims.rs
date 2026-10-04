//! Registered-claim validation (`exp`, `nbf`, `aud`, `iss`), on either a decoded dict or the raw
//! payload bytes (for typed decoding, where the payload is never built into a dict).

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use jiter::{Jiter, JsonValue};
use pyo3::exceptions::PyTypeError;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDelta, PyDeltaAccess, PyDict, PyFloat, PyInt, PyList, PyString};

use crate::errors::{
    DecodeError, ExpiredSignatureError, ImmatureSignatureError, InvalidAudienceError, InvalidIssuerError,
};

/// A registered claim's value, as far as validation cares.
#[derive(Default)]
pub enum Claim<'a> {
    #[default]
    Absent,
    Number(f64),
    Str(Cow<'a, str>),
    StrList(Vec<Cow<'a, str>>),
    Other,
}

#[derive(Default)]
pub struct Registered<'a> {
    exp: Claim<'a>,
    nbf: Claim<'a>,
    aud: Claim<'a>,
    iss: Claim<'a>,
}

impl<'a> Claim<'a> {
    fn from_json(value: JsonValue<'a>) -> Self {
        match value {
            #[allow(clippy::cast_precision_loss)] // timestamps are far below 2^53
            JsonValue::Int(i) => Self::Number(i as f64),
            JsonValue::BigInt(i) => Self::Number(if i.sign() == num_bigint::Sign::Minus {
                f64::MIN
            } else {
                f64::MAX
            }),
            JsonValue::Float(f) => Self::Number(f),
            JsonValue::Str(s) => Self::Str(s),
            JsonValue::Array(items) => items
                .iter()
                .map(|i| {
                    if let JsonValue::Str(s) = i {
                        Some(Cow::Owned(s.to_string()))
                    } else {
                        None
                    }
                })
                .collect::<Option<_>>()
                .map_or(Self::Other, Self::StrList),
            _ => Self::Other,
        }
    }

    fn from_py(value: &'a Bound<'_, PyAny>) -> Self {
        if value.is_instance_of::<PyBool>() {
            Self::Other
        } else if let Ok(i) = value.cast::<PyInt>() {
            #[allow(clippy::cast_precision_loss)] // timestamps are far below 2^53
            i.extract::<i64>().map_or_else(
                |_| {
                    Self::Number(if i.lt(0).unwrap_or(false) {
                        f64::MIN
                    } else {
                        f64::MAX
                    })
                },
                |i| Self::Number(i as f64),
            )
        } else if let Ok(f) = value.cast::<PyFloat>() {
            Self::Number(f.value())
        } else if let Ok(s) = value.cast::<PyString>() {
            s.to_str().map_or(Self::Other, |s| Self::Str(Cow::Borrowed(s)))
        } else if let Ok(list) = value.cast::<PyList>() {
            list.iter()
                .map(|i| {
                    i.cast::<PyString>()
                        .ok()
                        .and_then(|s| s.to_str().ok().map(|s| Cow::Owned(s.to_owned())))
                })
                .collect::<Option<_>>()
                .map_or(Self::Other, Self::StrList)
        } else {
            Self::Other
        }
    }
}

fn json_error(e: impl std::fmt::Display) -> PyErr {
    DecodeError::new_err(format!("Invalid payload JSON: {e}"))
}

fn slot_index(key: &str) -> Option<usize> {
    ["exp", "nbf", "aud", "iss"].iter().position(|k| *k == key)
}

/// Reads just the registered claims from a payload, skipping (but still syntax-checking) the rest.
/// Like a dict, a repeated claim takes its last value.
pub fn scan(payload: &[u8]) -> PyResult<Registered<'_>> {
    // Skipped values aren't UTF-8 checked, and the type's parser may ignore them too.
    std::str::from_utf8(payload).map_err(json_error)?;
    let mut jiter = Jiter::new(payload);
    let mut claims = Registered::default();
    let mut key = jiter.next_object().map_err(json_error)?.map(slot_index);
    while let Some(slot) = key {
        if let Some(i) = slot {
            let claim = Claim::from_json(jiter.next_value().map_err(json_error)?);
            *[&mut claims.exp, &mut claims.nbf, &mut claims.aud, &mut claims.iss][i] = claim;
        } else {
            jiter.next_skip().map_err(json_error)?;
        }
        key = jiter.next_key().map_err(json_error)?.map(slot_index);
    }
    jiter.finish().map_err(json_error)?;
    Ok(claims)
}

fn claim<'a>(value: Option<&'a Bound<'_, PyAny>>) -> Claim<'a> {
    value.map_or(Claim::Absent, Claim::from_py)
}

/// Validates the registered claims of a decoded payload dict.
pub fn validate_dict(payload: &Bound<'_, PyDict>, checks: &Checks) -> PyResult<()> {
    let py = payload.py();
    let exp = payload.get_item(intern!(py, "exp"))?;
    let nbf = payload.get_item(intern!(py, "nbf"))?;
    let aud = payload.get_item(intern!(py, "aud"))?;
    let iss = payload.get_item(intern!(py, "iss"))?;
    checks.validate(&Registered {
        exp: claim(exp.as_ref()),
        nbf: claim(nbf.as_ref()),
        aud: claim(aud.as_ref()),
        iss: claim(iss.as_ref()),
    })
}

/// What `decode` checks the registered claims against.
pub struct Checks<'a> {
    now: f64,
    leeway: f64,
    audience: Expected<'a>,
    issuer: Expected<'a>,
}

/// An expected `aud`/`iss`: not checked, one str (borrowed from the caller's `str`, no copy), or
/// any of several.
enum Expected<'a> {
    Unchecked,
    One(&'a str),
    AnyOf(Vec<String>),
}

impl Expected<'_> {
    fn is_unchecked(&self) -> bool {
        matches!(self, Self::Unchecked)
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Self::Unchecked => true,
            Self::One(expected) => *expected == value,
            Self::AnyOf(expected) => expected.iter().any(|e| e == value),
        }
    }
}

fn strings<'a>(value: Option<&'a Bound<'_, PyAny>>, name: &str) -> PyResult<Expected<'a>> {
    let Some(value) = value.filter(|v| !v.is_none()) else {
        return Ok(Expected::Unchecked);
    };
    if let Ok(s) = value.cast::<PyString>() {
        return Ok(Expected::One(s.to_str()?));
    }
    let error = || PyTypeError::new_err(format!("{name} must be a str or an iterable of str"));
    let mut out = Vec::new();
    for item in value.try_iter().map_err(|_| error())? {
        out.push(
            item?
                .cast::<PyString>()
                .map_err(|_| error())?
                .to_str()?
                .to_owned(),
        );
    }
    Ok(Expected::AnyOf(out))
}

fn leeway_seconds(leeway: Option<&Bound<'_, PyAny>>) -> PyResult<f64> {
    let error = || PyTypeError::new_err("leeway must be a number of seconds or a timedelta");
    let Some(leeway) = leeway else { return Ok(0.0) };
    if leeway.is_instance_of::<PyBool>() {
        return Err(error());
    }
    if let Ok(d) = leeway.cast::<PyDelta>() {
        let micros = f64::from(d.get_microseconds()) / 1e6;
        return Ok(f64::from(d.get_days()) * 86_400.0 + f64::from(d.get_seconds()) + micros);
    }
    leeway.extract::<f64>().map_err(|_| error())
}

impl<'a> Checks<'a> {
    pub fn new(
        audience: Option<&'a Bound<'_, PyAny>>,
        issuer: Option<&'a Bound<'_, PyAny>>,
        leeway: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Ok(Self {
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64()),
            leeway: leeway_seconds(leeway)?,
            audience: strings(audience, "audience")?,
            issuer: strings(issuer, "issuer")?,
        })
    }

    pub fn validate(&self, claims: &Registered<'_>) -> PyResult<()> {
        match claims.exp {
            Claim::Absent => {}
            Claim::Number(exp) if exp <= self.now - self.leeway => {
                return Err(ExpiredSignatureError::new_err("Signature has expired"));
            }
            Claim::Number(_) => {}
            _ => {
                return Err(DecodeError::new_err(
                    "Expiration Time claim (exp) must be a number",
                ));
            }
        }
        match claims.nbf {
            Claim::Absent => {}
            Claim::Number(nbf) if nbf > self.now + self.leeway => {
                return Err(ImmatureSignatureError::new_err(
                    "The token is not yet valid (nbf)",
                ));
            }
            Claim::Number(_) => {}
            _ => return Err(DecodeError::new_err("Not Before claim (nbf) must be a number")),
        }
        let token_audiences: &[Cow<'_, str>] = match &claims.aud {
            Claim::Absent => &[],
            Claim::Str(s) => std::slice::from_ref(s),
            Claim::StrList(list) => list,
            _ => {
                return Err(InvalidAudienceError::new_err(
                    "Audience (aud) must be a string or list of strings",
                ));
            }
        };
        match (self.audience.is_unchecked(), &claims.aud) {
            (true, Claim::Absent) => {}
            (true, _) => {
                return Err(InvalidAudienceError::new_err(
                    "Token has an aud claim but no audience was given",
                ));
            }
            (false, Claim::Absent) => {
                return Err(InvalidAudienceError::new_err("Token is missing the aud claim"));
            }
            (false, _) => {
                if !token_audiences.iter().any(|a| self.audience.matches(a)) {
                    return Err(InvalidAudienceError::new_err("Audience doesn't match"));
                }
            }
        }
        if !self.issuer.is_unchecked() {
            match &claims.iss {
                Claim::Absent => return Err(InvalidIssuerError::new_err("Token is missing the iss claim")),
                Claim::Str(iss) if self.issuer.matches(iss) => {}
                Claim::Str(_) => return Err(InvalidIssuerError::new_err("Issuer doesn't match")),
                _ => return Err(InvalidIssuerError::new_err("Issuer (iss) must be a string")),
            }
        }
        Ok(())
    }
}
