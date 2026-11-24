//! Crypto type declarations, kept apart from the logic in `tls13crypto`
//! and from `backend` to avoid F* module cycles and isolate derived instances.

use crate::tls13utils::Bytes;
#[cfg(feature = "hax-pv")]
use hax_lib::proverif;

/// Bertie hash algorithms.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
}

/// Bertie KEM schemes.
///
/// This includes ECDH curves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KemScheme {
    X25519,
    Secp256r1,
    X448,
    Secp384r1,
    Secp521r1,
    X25519MlKem768,
}

/// An RSA public key.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "hax-pv", hax_lib::opaque)]
pub struct RsaVerificationKey {
    pub modulus: Bytes,
    pub exponent: Bytes,
}

/// Bertie public verification keys.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "hax-pv",
    proverif::replace(
        "type $:{PublicVerificationKey}.

fun $:{PublicVerificationKey}_to_bitstring(
      $:{PublicVerificationKey}
    )
    : bitstring [typeConverter].
fun $:{PublicVerificationKey}_from_bitstring(bitstring)
    : $:{PublicVerificationKey} [typeConverter].
const $:{PublicVerificationKey}_default_value: $:{PublicVerificationKey}.
letfun $:{PublicVerificationKey}_default() =
       $:{PublicVerificationKey}_default_value.
letfun $:{PublicVerificationKey}_err() =
       let x = construct_fail() in $:{PublicVerificationKey}_default_value.
fun ${PublicVerificationKey::EcDsa}($:{Bytes}
    )
    : $:{PublicVerificationKey} [data].

fun ${PublicVerificationKey::Rsa}(
      $:{RsaVerificationKey}
    )
    : $:{PublicVerificationKey} [data].
"
    )
)]
pub enum PublicVerificationKey {
    EcDsa(Bytes),            // Uncompressed point 0x04...
    Rsa(RsaVerificationKey), // N, e
}

/// AEAD Algorithms for Bertie
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum AeadAlgorithm {
    Chacha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

/// Signature schemes for Bertie.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SignatureScheme {
    RsaPssRsaSha256,
    EcdsaSecp256r1Sha256,
    ED25519,
}

/// The algorithms for Bertie.
///
/// Note that this is more than the TLS 1.3 ciphersuite. It contains all
/// necessary cryptographic algorithms and options.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Algorithms {
    pub(crate) hash: HashAlgorithm,
    pub(crate) aead: AeadAlgorithm,
    pub(crate) signature: SignatureScheme,
    pub(crate) kem: KemScheme,
    pub(crate) psk_mode: bool,
    pub(crate) zero_rtt: bool,
}
