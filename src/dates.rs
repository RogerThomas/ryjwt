//! `NumericDate` claims (`exp`, `nbf`, `iat`) for a msgspec Struct or pydantic `BaseModel` that
//! declares them as datetimes: msgspec's (strict) decoder takes a datetime only as an RFC 3339
//! string, and pydantic would take a number from 2e10 on as milliseconds, so the payload is copied
//! with their numbers as datetime strings, for the library to decode in one pass. This is
//! `ryjwt._types._parse_with_dates` (for a Struct) and `_validate_with_dates` (for a `BaseModel`),
//! for the common case only: whole seconds from 1970 on, and a plain payload (no escaped or
//! repeated member names). For anything else those slower paths run.

use std::ops::Range;

use jiter::{Jiter, JsonValue, NumberAny, NumberInt};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

use crate::claims::{Claim, Registered};

/// The `NumericDate` claims, in `DateClaims` bit order.
const NUMERIC_DATE_CLAIMS: [&[u8]; 3] = [b"exp", b"nbf", b"iat"];

/// The latest `NumericDate` msgspec converts to a datetime: 9999-12-31T23:59:59Z.
const MAX_SECONDS: i64 = 253_402_300_799;

/// How the datetime strings are written: as each library writes a whole-second UTC datetime.
#[derive(Clone, Copy)]
pub enum Format {
    /// `"YYYY-MM-DDTHH:MM:SSZ"`, as msgspec encodes it.
    Msgspec,
    /// `"YYYY-MM-DDTHH:MM:SS+00:00"`, as `datetime.isoformat` writes it, which is what
    /// `_validate_with_dates` gives pydantic (and so what its errors quote).
    Isoformat,
}

impl Format {
    /// The JSON string of 0000-00-00T00:00:00, quotes included, to write the digits into.
    const fn template(self) -> &'static [u8] {
        match self {
            Self::Msgspec => b"\"0000-00-00T00:00:00Z\"",
            Self::Isoformat => b"\"0000-00-00T00:00:00+00:00\"",
        }
    }
}

/// The `NumericDate` claims a type declares as datetimes, one bit each.
#[derive(Clone, Copy)]
pub struct DateClaims(u8);

impl DateClaims {
    /// The claims named (by their JSON names, from `ryjwt._types.date_decoder`); other names are
    /// ignored.
    pub fn new(names: &[Bound<'_, PyString>]) -> PyResult<Self> {
        let mut bits = 0;
        for name in names {
            let name = name.to_str()?.as_bytes();
            if let Some(i) = NUMERIC_DATE_CLAIMS.iter().position(|c| *c == name) {
                bits |= 1 << i;
            }
        }
        Ok(Self(bits))
    }

    fn contains(self, key: &[u8]) -> bool {
        NUMERIC_DATE_CLAIMS
            .iter()
            .enumerate()
            .any(|(i, c)| self.0 & (1 << i) != 0 && *c == key)
    }
}

/// A date claim's number to rewrite: its value's span in the payload, and its seconds.
#[derive(Clone, Copy, Default)]
struct Rewrite {
    start: usize,
    end: usize,
    seconds: i64,
}

/// The members to rewrite: one per claim at most, as a payload with a repeated member is left to
/// the slower path.
#[derive(Default)]
struct Rewrites {
    items: [Rewrite; NUMERIC_DATE_CLAIMS.len()],
    len: usize,
}

impl Rewrites {
    fn as_slice(&self) -> &[Rewrite] {
        &self.items[..self.len]
    }
}

/// What to decode a payload as.
pub enum Rewritten<'py> {
    /// The payload as it is: none of the claims holds a number.
    Unchanged,
    /// The payload with the claims' numbers as datetime strings.
    Payload(Bound<'py, PyBytes>),
    /// Not a payload this handles (see the module docs): the slower path's to decode.
    Unsupported,
}

/// Payloads with more members than this are left to the slower path, so that checking for repeated
/// members stays cheap.
const MAX_MEMBERS: usize = 32;

/// Where `part`, a part of `payload`, is in it.
fn span(payload: &[u8], part: &[u8]) -> Range<usize> {
    let start = part.as_ptr() as usize - payload.as_ptr() as usize;
    start..start + part.len()
}

/// The members to rewrite, if `payload` is a plain JSON object (no escaped or repeated member
/// names, at most `MAX_MEMBERS` members) whose `claims` members are each whole seconds from 1970
/// on, or not a number at all; None otherwise. With `registered`, its registered claims are read
/// into that too, as `claims::scan` reads them from such a payload (if it's valid UTF-8, which
/// isn't checked here).
fn rewrites<'a>(
    payload: &'a [u8],
    claims: DateClaims,
    mut registered: Option<&mut Registered<'a>>,
) -> Option<Rewrites> {
    let mut jiter = Jiter::new(payload);
    let mut rewrites = Rewrites::default();
    // A repeated member would take its last value in the slower path (which decodes the payload
    // to a dict first), but each of its values would be decoded here.
    let mut names: [&[u8]; MAX_MEMBERS] = [&[]; MAX_MEMBERS];
    let mut count = 0;
    let mut key = jiter.next_object_bytes().ok()?.map(|k| span(payload, k));
    while let Some(range) = key {
        let name = &payload[range];
        if count == MAX_MEMBERS
            || memchr::memchr(b'\\', name).is_some()
            || names[..count].contains(&name)
        {
            return None;
        }
        names[count] = name;
        count += 1;
        let start = jiter.current_index();
        let peek = jiter.peek().ok()?;
        let claim = registered.as_deref_mut().and_then(|r| r.claim_mut(name));
        if claims.contains(name) && peek.is_num() {
            let NumberAny::Int(NumberInt::Int(seconds)) = jiter.known_number(peek).ok()? else {
                return None;
            };
            if !(0..=MAX_SECONDS).contains(&seconds) {
                return None;
            }
            if let Some(claim) = claim {
                *claim = Claim::from_json(JsonValue::Int(seconds));
            }
            let end = jiter.current_index();
            rewrites.items[rewrites.len] = Rewrite {
                start,
                end,
                seconds,
            };
            rewrites.len += 1;
        } else if let Some(claim) = claim {
            *claim = Claim::from_json(jiter.known_value(peek).ok()?);
        } else {
            jiter.known_skip(peek).ok()?;
        }
        key = jiter.next_key_bytes().ok()?.map(|k| span(payload, k));
    }
    jiter.finish().ok()?;
    Some(rewrites)
}

/// Writes `value` as `out.len()` decimal digits, zero-padded.
fn write_digits(out: &mut [u8], mut value: i64) {
    for digit in out.iter_mut().rev() {
        // `value` is non-negative, so each remainder is a digit.
        *digit = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
    }
}

/// Writes the UTC datetime `seconds` (0 to `MAX_SECONDS`) after the epoch as a JSON string, as
/// `format` says (`out` is its template's length).
fn write_datetime(out: &mut [u8], seconds: i64, format: Format) {
    // Howard Hinnant's `civil_from_days`, for days from 1970-01-01 on.
    let (days, time) = (seconds / 86_400, seconds % 86_400);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    out.copy_from_slice(format.template());
    write_digits(&mut out[1..5], year);
    write_digits(&mut out[6..8], month);
    write_digits(&mut out[9..11], day);
    write_digits(&mut out[12..14], time / 3_600);
    write_digits(&mut out[15..17], time / 60 % 60);
    write_digits(&mut out[18..20], time % 60);
}

/// `payload` with `rewrites` applied.
fn apply<'py>(
    payload: &Bound<'py, PyBytes>,
    rewrites: &Rewrites,
    format: Format,
) -> PyResult<Rewritten<'py>> {
    let bytes = payload.as_bytes();
    let rewrites = rewrites.as_slice();
    if rewrites.is_empty() {
        return Ok(Rewritten::Unchanged);
    }
    let width = format.template().len();
    let removed: usize = rewrites.iter().map(|r| r.end - r.start).sum();
    let len = bytes.len() - removed + rewrites.len() * width;
    let rewritten = PyBytes::new_with(payload.py(), len, |out| {
        let (mut read, mut written) = (0, 0);
        for r in rewrites {
            let kept = r.start - read;
            out[written..written + kept].copy_from_slice(&bytes[read..r.start]);
            written += kept;
            write_datetime(&mut out[written..written + width], r.seconds, format);
            written += width;
            read = r.end;
        }
        out[written..].copy_from_slice(&bytes[read..]);
        Ok(())
    })?;
    Ok(Rewritten::Payload(rewritten))
}

/// The payload to decode an instance of a type declaring `claims` as datetimes from.
pub fn rewrite<'py>(
    payload: &Bound<'py, PyBytes>,
    claims: DateClaims,
    format: Format,
) -> PyResult<Rewritten<'py>> {
    match rewrites(payload.as_bytes(), claims, None) {
        Some(rewrites) => apply(payload, &rewrites, format),
        None => Ok(Rewritten::Unsupported),
    }
}

/// `claims::scan` and `rewrite` in one pass: the registered claims, and the payload to decode
/// (never `Unsupported`). None for a payload that isn't plain (see the module docs) or isn't
/// valid UTF-8: then those two must run, and report what's wrong with it as they would.
pub fn scan_and_rewrite<'py, 'a>(
    payload: &'a Bound<'py, PyBytes>,
    claims: DateClaims,
    format: Format,
) -> PyResult<Option<(Registered<'a>, Rewritten<'py>)>> {
    let bytes = payload.as_bytes();
    // `scan` rejects a payload that isn't, wherever it isn't.
    if std::str::from_utf8(bytes).is_err() {
        return Ok(None);
    }
    let mut registered = Registered::default();
    let Some(rewrites) = rewrites(bytes, claims, Some(&mut registered)) else {
        return Ok(None);
    };
    Ok(Some((registered, apply(payload, &rewrites, format)?)))
}
