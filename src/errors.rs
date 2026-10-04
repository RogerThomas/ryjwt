//! ryjwt's exception hierarchy.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(ryjwt, RYJWTError, PyException, "Base class for all ryjwt errors.");
create_exception!(
    ryjwt,
    InvalidKeyError,
    RYJWTError,
    "The key can't be used: unparseable, unsupported, or wrong for the configured algorithms."
);
create_exception!(
    ryjwt,
    InvalidTokenError,
    RYJWTError,
    "Base class for every reason a token is rejected."
);
create_exception!(
    ryjwt,
    DecodeError,
    InvalidTokenError,
    "The token is malformed: segments, base64url, or header/payload JSON."
);
create_exception!(
    ryjwt,
    InvalidSignatureError,
    DecodeError,
    "The signature doesn't match."
);
create_exception!(
    ryjwt,
    InvalidAlgorithmError,
    InvalidTokenError,
    "The header's `alg` is missing or not one of the configured algorithms."
);
create_exception!(
    ryjwt,
    ExpiredSignatureError,
    InvalidTokenError,
    "The `exp` claim is in the past."
);
create_exception!(
    ryjwt,
    ImmatureSignatureError,
    InvalidTokenError,
    "The `nbf` claim is in the future."
);
create_exception!(
    ryjwt,
    InvalidAudienceError,
    InvalidTokenError,
    "The `aud` claim is missing, malformed, unexpected, or doesn't match."
);
create_exception!(
    ryjwt,
    InvalidIssuerError,
    InvalidTokenError,
    "The `iss` claim is missing, malformed, or doesn't match."
);

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("RYJWTError", py.get_type::<RYJWTError>())?;
    m.add("InvalidKeyError", py.get_type::<InvalidKeyError>())?;
    m.add("InvalidTokenError", py.get_type::<InvalidTokenError>())?;
    m.add("DecodeError", py.get_type::<DecodeError>())?;
    m.add("InvalidSignatureError", py.get_type::<InvalidSignatureError>())?;
    m.add("InvalidAlgorithmError", py.get_type::<InvalidAlgorithmError>())?;
    m.add("ExpiredSignatureError", py.get_type::<ExpiredSignatureError>())?;
    m.add("ImmatureSignatureError", py.get_type::<ImmatureSignatureError>())?;
    m.add("InvalidAudienceError", py.get_type::<InvalidAudienceError>())?;
    m.add("InvalidIssuerError", py.get_type::<InvalidIssuerError>())?;
    Ok(())
}
