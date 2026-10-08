//! HMAC-SHA2 (RFC 2104) from precomputed inner/outer hash states.
//!
//! `aws_lc_rs::hmac` copies, moves and cleanses a ~1.2 KB `HMAC_CTX` on every call, which costs
//! about as much as hashing a small token. Here the key is absorbed once into the inner
//! (`K ^ ipad`) and outer (`K ^ opad`) SHA-2 states, and each MAC just copies those (~112/216 bytes)
//! and hashes the message: the same construction, with aws-lc's SHA-2 doing the hashing.

use aws_lc_sys as sys;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

#[derive(Clone, Copy)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// The tag size in bytes, which RFC 7518 §3.2 also makes the minimum key size.
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Clone)]
enum States {
    Sha256 {
        inner: sys::SHA256_CTX,
        outer: sys::SHA256_CTX,
    },
    Sha384 {
        inner: sys::SHA512_CTX,
        outer: sys::SHA512_CTX,
    },
    Sha512 {
        inner: sys::SHA512_CTX,
        outer: sys::SHA512_CTX,
    },
}

#[derive(Clone)]
pub struct HmacKey(States);

/// Largest tag (SHA-512).
pub const MAX_TAG_LEN: usize = 64;

fn cleanse<T>(value: &mut T) {
    // SAFETY: overwrites `size_of::<T>()` bytes of a value we own; T is plain old data.
    unsafe { sys::OPENSSL_cleanse(std::ptr::from_mut(value).cast(), size_of::<T>()) }
}

/// The two padded key blocks for a hash with `BLOCK`-byte blocks; `digest` hashes over-long keys.
fn pads<const BLOCK: usize>(
    key: &[u8],
    digest: impl FnOnce(&[u8], &mut [u8; 64]) -> usize,
) -> ([u8; BLOCK], [u8; BLOCK]) {
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut hashed = [0u8; 64];
        let len = digest(key, &mut hashed);
        block[..len].copy_from_slice(&hashed[..len]);
        cleanse(&mut hashed);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let (mut inner, mut outer) = ([0u8; BLOCK], [0u8; BLOCK]);
    for i in 0..BLOCK {
        inner[i] = block[i] ^ IPAD;
        outer[i] = block[i] ^ OPAD;
    }
    cleanse(&mut block);
    (inner, outer)
}

macro_rules! sha2_states {
    ($ctx:ty, $init:ident, $update:ident, $oneshot:ident, $len:expr, $block:expr, $key:expr) => {{
        // SAFETY: the aws-lc SHA-2 functions only read/write the buffers we pass, with their lengths.
        unsafe {
            let (mut ipad, mut opad) = pads::<$block>($key, |key, out| {
                sys::$oneshot(key.as_ptr(), key.len(), out.as_mut_ptr());
                $len
            });
            let mut inner: $ctx = std::mem::zeroed();
            let mut outer: $ctx = std::mem::zeroed();
            sys::$init(&mut inner);
            sys::$init(&mut outer);
            sys::$update(&mut inner, ipad.as_ptr().cast(), $block);
            sys::$update(&mut outer, opad.as_ptr().cast(), $block);
            cleanse(&mut ipad);
            cleanse(&mut opad);
            (inner, outer)
        }
    }};
}

macro_rules! sha2_mac {
    ($inner:expr, $outer:expr, $update:ident, $final:ident, $len:expr, $msg:expr, $out:expr) => {{
        // SAFETY: as above; `$out` has room for the largest digest.
        unsafe {
            let mut inner = $inner.clone();
            sys::$update(&mut inner, $msg.as_ptr().cast(), $msg.len());
            sys::$final($out.as_mut_ptr(), &mut inner);
            let mut outer = $outer.clone();
            sys::$update(&mut outer, $out.as_ptr().cast(), $len);
            sys::$final($out.as_mut_ptr(), &mut outer);
            cleanse(&mut inner);
            cleanse(&mut outer);
            &$out[..$len]
        }
    }};
}

impl HmacKey {
    pub fn new(hash: Hash, key: &[u8]) -> Self {
        Self(match hash {
            Hash::Sha256 => {
                let (inner, outer) = sha2_states!(
                    sys::SHA256_CTX,
                    SHA256_Init,
                    SHA256_Update,
                    SHA256,
                    32,
                    64,
                    key
                );
                States::Sha256 { inner, outer }
            }
            Hash::Sha384 => {
                let (inner, outer) = sha2_states!(
                    sys::SHA512_CTX,
                    SHA384_Init,
                    SHA384_Update,
                    SHA384,
                    48,
                    128,
                    key
                );
                States::Sha384 { inner, outer }
            }
            Hash::Sha512 => {
                let (inner, outer) = sha2_states!(
                    sys::SHA512_CTX,
                    SHA512_Init,
                    SHA512_Update,
                    SHA512,
                    64,
                    128,
                    key
                );
                States::Sha512 { inner, outer }
            }
        })
    }

    /// The tag of `msg`, written to the start of `out`.
    pub fn sign<'o>(&self, msg: &[u8], out: &'o mut [u8; MAX_TAG_LEN]) -> &'o [u8] {
        match &self.0 {
            States::Sha256 { inner, outer } => {
                sha2_mac!(inner, outer, SHA256_Update, SHA256_Final, 32, msg, out)
            }
            States::Sha384 { inner, outer } => {
                sha2_mac!(inner, outer, SHA384_Update, SHA384_Final, 48, msg, out)
            }
            States::Sha512 { inner, outer } => {
                sha2_mac!(inner, outer, SHA512_Update, SHA512_Final, 64, msg, out)
            }
        }
    }

    /// Whether `tag` is the tag of `msg`, compared in constant time.
    pub fn verify(&self, msg: &[u8], tag: &[u8]) -> bool {
        let mut out = [0u8; MAX_TAG_LEN];
        let expected = self.sign(msg, &mut out);
        // SAFETY: both buffers are `expected.len()` bytes long.
        expected.len() == tag.len()
            && unsafe {
                sys::CRYPTO_memcmp(expected.as_ptr().cast(), tag.as_ptr().cast(), tag.len())
            } == 0
    }
}

impl Drop for HmacKey {
    fn drop(&mut self) {
        match &mut self.0 {
            States::Sha256 { inner, outer } => {
                cleanse(inner);
                cleanse(outer);
            }
            States::Sha384 { inner, outer } | States::Sha512 { inner, outer } => {
                cleanse(inner);
                cleanse(outer);
            }
        }
    }
}
