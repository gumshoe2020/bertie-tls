//! Declaration-only algorithm enums, kept apart from the logic in `tls13crypto`
//! and from `backend` so neither depends on the other's module in F*.

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
