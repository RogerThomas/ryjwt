//! `NumericDate` claims (`exp`, `nbf`, `iat`) for a msgspec Struct that declares them as datetimes:
//! msgspec's (strict) decoder takes a datetime only as an RFC 3339 string, so the payload is copied
//! with their numbers as such strings, for msgspec to decode in one pass. This is
//! `ryjwt._types._parse_with_dates`, for the common case only: whole seconds from 1970 on, and a
//! plain payload (no escaped or repeated member names). For anything else that slower path runs.

use std::ops::Range;

use jiter::{Jiter, NumberAny, NumberInt};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

/// The `NumericDate` claims, in `DateClaims` bit order.
const NUMERIC_DATE_CLAIMS: [&[u8]; 3] = [b"exp", b"nbf", b"iat"];

/// The latest `NumericDate` msgspec converts to a datetime: 9999-12-31T23:59:59Z.
const MAX_SECONDS: i64 = 253_402_300_799;

/// `"YYYY-MM-DDTHH:MM:SSZ"`, quotes included.
const RFC3339_LEN: usize = 22;

/// The `NumericDate` claims a Struct declares as datetimes, one bit each.
#[derive(Clone, Copy)]
pub struct DateClaims(u8);

impl DateClaims {
    /// The claims named (by their JSON names, from `ryjwt._types.struct_date_decoder`); other
    /// names are ignored.
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
/// `_parse_with_dates`.
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
    /// The payload with the claims' numbers as RFC 3339 strings.
    Payload(Bound<'py, PyBytes>),
    /// Not a payload this handles (see the module docs): `_parse_with_dates`'s to decode.
    Unsupported,
}

/// Payloads with more members than this are left to `_parse_with_dates`, so that checking for
/// repeated members stays cheap.
const MAX_MEMBERS: usize = 32;

/// Where `part`, a part of `payload`, is in it.
fn span(payload: &[u8], part: &[u8]) -> Range<usize> {
    let start = part.as_ptr() as usize - payload.as_ptr() as usize;
    start..start + part.len()
}

/// The members to rewrite, if `payload` is a plain JSON object (no escaped or repeated member
/// names, at most `MAX_MEMBERS` members) whose `claims` members are each whole seconds from 1970
/// on, or not a number at all; None otherwise.
fn rewrites(payload: &[u8], claims: DateClaims) -> Option<Rewrites> {
    let mut jiter = Jiter::new(payload);
    let mut rewrites = Rewrites::default();
    // A repeated member would take its last value in `_parse_with_dates` (which decodes the
    // payload to a dict first), but each of its values would be decoded here.
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
        if claims.contains(name) && peek.is_num() {
            let NumberAny::Int(NumberInt::Int(seconds)) = jiter.known_number(peek).ok()? else {
                return None;
            };
            if !(0..=MAX_SECONDS).contains(&seconds) {
                return None;
            }
            let end = jiter.current_index();
            rewrites.items[rewrites.len] = Rewrite {
                start,
                end,
                seconds,
            };
            rewrites.len += 1;
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

/// Writes the UTC datetime `seconds` (0 to `MAX_SECONDS`) after the epoch as an RFC 3339 JSON
/// string, `RFC3339_LEN` bytes long, as msgspec encodes a datetime.
fn write_rfc3339(out: &mut [u8], seconds: i64) {
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

    out.copy_from_slice(b"\"0000-00-00T00:00:00Z\"");
    write_digits(&mut out[1..5], year);
    write_digits(&mut out[6..8], month);
    write_digits(&mut out[9..11], day);
    write_digits(&mut out[12..14], time / 3_600);
    write_digits(&mut out[15..17], time / 60 % 60);
    write_digits(&mut out[18..20], time % 60);
}

/// The payload to decode an instance of a Struct declaring `claims` as datetimes from.
pub fn rewrite<'py>(payload: &Bound<'py, PyBytes>, claims: DateClaims) -> PyResult<Rewritten<'py>> {
    let bytes = payload.as_bytes();
    let Some(rewrites) = rewrites(bytes, claims) else {
        return Ok(Rewritten::Unsupported);
    };
    let rewrites = rewrites.as_slice();
    if rewrites.is_empty() {
        return Ok(Rewritten::Unchanged);
    }
    let removed: usize = rewrites.iter().map(|r| r.end - r.start).sum();
    let len = bytes.len() - removed + rewrites.len() * RFC3339_LEN;
    let rewritten = PyBytes::new_with(payload.py(), len, |out| {
        let (mut read, mut written) = (0, 0);
        for r in rewrites {
            let kept = r.start - read;
            out[written..written + kept].copy_from_slice(&bytes[read..r.start]);
            written += kept;
            write_rfc3339(&mut out[written..written + RFC3339_LEN], r.seconds);
            written += RFC3339_LEN;
            read = r.end;
        }
        out[written..].copy_from_slice(&bytes[read..]);
        Ok(())
    })?;
    Ok(Rewritten::Payload(rewritten))
}
