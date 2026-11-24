//! The libcrux trust boundary.
//!
//! Every call into a libcrux crate made by `tls13crypto` lives here, one small
//! function per operation. Signatures use only std and Bertie types. This
//! module is extracted interface-only for F*: its signatures carry no
//! contracts, so nothing is assumed about libcrux beyond the types.

#[cfg(feature = "chacha20poly1305")]
use libcrux_chacha20poly1305::{decrypt_detached, encrypt_detached, TAG_LEN};
#[cfg(feature = "ecdsa-p256")]
use libcrux_ecdsa::DigestAlgorithm as EcDsaDigestAlgorithm;
use libcrux_hkdf::{expand, extract};
use libcrux_hmac::hmac;
use libcrux_kem::{Ct, PrivateKey, PublicKey};
#[cfg(feature = "rsa")]
use libcrux_rsa::{
    sign_varlen, verify_varlen, DigestAlgorithm as RsaDigestAlgorithm, VarLenPrivateKey,
    VarLenPublicKey,
};
use rand::CryptoRng;

use super::algorithm_types::{HashAlgorithm, KemScheme};
use crate::std::vec::Vec;
use crate::tls13utils::{
    tlserr, TLSError, CRYPTO_ERROR, INCORRECT_ARRAY_LENGTH, INVALID_SIGNATURE,
};
use std::vec;

/// SHA-2 digest of `data`.
pub(super) fn sha2_digest(alg: &HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, TLSError> {
    let hasher = non_hax::sha2_algorithm(alg)?;
    let mut digest = vec![0u8; hasher.hash_len()];
    hasher.hash(data, &mut digest);
    Ok(digest)
}

/// HMAC tag of `data` under `key`.
pub(super) fn hmac_compute(
    alg: &HashAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, TLSError> {
    Ok(hmac(non_hax::hmac_algorithm(alg)?, key, data, None))
}

/// HKDF-Extract.
pub(super) fn hkdf_extract_prk(
    alg: &HashAlgorithm,
    salt: &[u8],
    ikm: &[u8],
) -> Result<Vec<u8>, TLSError> {
    extract(non_hax::hkdf_algorithm(alg)?, salt, ikm).map_err(|_| CRYPTO_ERROR)
}

/// HKDF-Expand to `len` bytes.
pub(super) fn hkdf_expand_okm(
    alg: &HashAlgorithm,
    prk: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, TLSError> {
    match expand(non_hax::hkdf_algorithm(alg)?, prk, info, len) {
        Ok(okm) => Ok(okm),
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// ChaCha20-Poly1305 encryption, returning the ciphertext and the detached tag.
#[cfg(feature = "chacha20poly1305")]
pub(super) fn chacha20poly1305_seal(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), TLSError> {
    let mut ctxt = vec![0u8; plain.len()];
    let mut tag = [0u8; TAG_LEN];
    match encrypt_detached(key, plain, &mut ctxt, &mut tag, aad, iv) {
        Ok(_) => Ok((ctxt, tag)),
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// ChaCha20-Poly1305 decryption of `ctxt` with the detached `tag`.
#[cfg(feature = "chacha20poly1305")]
pub(super) fn chacha20poly1305_open(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ctxt: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, TLSError> {
    let mut ptxt = vec![0u8; ctxt.len()];
    match decrypt_detached(key, &mut ptxt, ctxt, tag, aad, iv) {
        Ok(plain) => Ok(plain.to_vec()),
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// ECDSA P-256/SHA-256 signature, returned as `r || s`.
#[cfg(feature = "ecdsa-p256")]
pub(super) fn ecdsa_p256_sha256_sign(
    input: &[u8],
    sk: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Vec<u8>, TLSError> {
    let sk = libcrux_ecdsa::p256::PrivateKey::try_from(sk).map_err(|_| INCORRECT_ARRAY_LENGTH)?;
    libcrux_ecdsa::p256::rand::sign(EcDsaDigestAlgorithm::Sha256, input, &sk, rng)
        .map_err(|_| CRYPTO_ERROR)
        .map(|s| {
            let (r, s) = s.as_bytes();
            let mut out = r.to_vec();
            out.extend_from_slice(s);
            out
        })
}

/// ECDSA P-256/SHA-256 verification of an `r || s` signature.
#[cfg(feature = "ecdsa-p256")]
pub(super) fn ecdsa_p256_sha256_verify(
    input: &[u8],
    sig: [u8; 64],
    pk: &[u8; 64],
) -> Result<(), TLSError> {
    libcrux_ecdsa::p256::verify(
        EcDsaDigestAlgorithm::Sha256,
        input,
        &libcrux_ecdsa::p256::Signature::from_bytes(sig),
        &libcrux_ecdsa::p256::PublicKey::try_from(pk).map_err(|_| CRYPTO_ERROR)?,
    )
    .map_err(|_| INVALID_SIGNATURE)
}

/// Ed25519 signature.
#[cfg(feature = "ed25519")]
pub(super) fn ed25519_sign(input: &[u8], sk: &[u8; 32]) -> Result<Vec<u8>, TLSError> {
    libcrux_ed25519::sign(input, sk)
        .map_err(|_| CRYPTO_ERROR)
        .map(|s| s.into())
}

/// Ed25519 verification.
#[cfg(feature = "ed25519")]
pub(super) fn ed25519_verify(input: &[u8], pk: &[u8; 32], sig: &[u8; 64]) -> Result<(), TLSError> {
    libcrux_ed25519::verify(input, pk, sig).map_err(|_| INVALID_SIGNATURE)
}

/// RSA-PSS/SHA-256 signature. `modulus` carries the leading zero byte of the
/// DER integer, and the salt has the digest length.
#[cfg(feature = "rsa")]
pub(super) fn rsa_pss_sha256_sign(
    modulus: &[u8],
    sk: &[u8],
    msg: &[u8],
    salt: &[u8; 32],
) -> Result<Vec<u8>, TLSError> {
    // The public key is only checked for well-formedness.
    VarLenPublicKey::try_from(&modulus[1..]).map_err(|_| INCORRECT_ARRAY_LENGTH)?;
    let sk =
        VarLenPrivateKey::from_components(&modulus[1..], sk).map_err(|_| INCORRECT_ARRAY_LENGTH)?;
    // XXX: hard coded length because of bad libcrux API
    let mut signature = [0u8; 512];
    sign_varlen(RsaDigestAlgorithm::Sha2_256, &sk, msg, salt, &mut signature)
        .map_err(|_| CRYPTO_ERROR)?;
    Ok(signature.to_vec())
}

/// RSA-PSS/SHA-256 verification. `modulus` carries the leading zero byte.
#[cfg(feature = "rsa")]
pub(super) fn rsa_pss_sha256_verify(
    modulus: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), TLSError> {
    let pk = VarLenPublicKey::try_from(&modulus[1..]).map_err(|_| INCORRECT_ARRAY_LENGTH)?;
    verify_varlen(
        RsaDigestAlgorithm::Sha2_256,
        &pk,
        msg,
        32, // salt must be same length as digest ouput length
        sig,
    )
    .map_err(|_| CRYPTO_ERROR)
}

/// Generate a KEM key pair, returning the encoded `(sk, pk)`.
pub(super) fn kem_generate(
    alg: KemScheme,
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), TLSError> {
    match non_hax::key_gen(non_hax::kem_algorithm(alg)?, rng) {
        Ok((sk, pk)) => Ok((sk.encode(), pk.encode())),
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// KEM encapsulation to the raw public key `pk`, returning `(shared_secret, ciphertext)`.
pub(super) fn kem_encapsulate(
    alg: KemScheme,
    pk: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), TLSError> {
    let pk = PublicKey::decode(non_hax::kem_algorithm(alg)?, pk).map_err(|_| CRYPTO_ERROR)?;
    match non_hax::encapsulate(&pk, rng) {
        Ok((shared_secret, ct)) => Ok((shared_secret.encode(), ct.encode())),
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// KEM decapsulation of the raw ciphertext `ct` with the secret key `sk`.
pub(super) fn kem_decapsulate(alg: KemScheme, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>, TLSError> {
    let algorithm = non_hax::kem_algorithm(alg)?;
    let sk = PrivateKey::decode(algorithm, sk).map_err(|_| CRYPTO_ERROR)?;
    let ct = Ct::decode(algorithm, ct).map_err(|_| CRYPTO_ERROR)?;
    match ct.decapsulate(&sk) {
        Ok(shared_secret) => Ok(shared_secret.encode()),
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

// Implementation glue, outside the existing abstract cryptographic proof interface.
mod non_hax {
    use super::{HashAlgorithm, KemScheme};
    use crate::tls13utils::{tlserr, TLSError, UNSUPPORTED_ALGORITHM};
    use libcrux_hkdf::Algorithm as HkdfAlgorithm;
    use libcrux_hmac::Algorithm as HmacAlgorithm;
    use libcrux_sha2::Algorithm as Sha2Algorithm;
    use rand::CryptoRng;

    pub(super) fn sha2_algorithm(alg: &HashAlgorithm) -> Result<Sha2Algorithm, TLSError> {
        match alg {
            #[cfg(feature = "sha256")]
            HashAlgorithm::SHA256 => Ok(Sha2Algorithm::Sha256),
            #[cfg(feature = "sha384")]
            HashAlgorithm::SHA384 => Ok(Sha2Algorithm::Sha384),
            #[cfg(feature = "sha512")]
            HashAlgorithm::SHA512 => Ok(Sha2Algorithm::Sha512),
            #[cfg(not(all(feature = "sha256", feature = "sha384", feature = "sha512")))]
            _ => tlserr(UNSUPPORTED_ALGORITHM),
        }
    }

    pub(super) fn hmac_algorithm(alg: &HashAlgorithm) -> Result<HmacAlgorithm, TLSError> {
        match alg {
            #[cfg(feature = "sha256")]
            HashAlgorithm::SHA256 => Ok(HmacAlgorithm::Sha256),
            #[cfg(feature = "sha384")]
            HashAlgorithm::SHA384 => Ok(HmacAlgorithm::Sha384),
            #[cfg(feature = "sha512")]
            HashAlgorithm::SHA512 => Ok(HmacAlgorithm::Sha512),
            #[cfg(not(all(feature = "sha256", feature = "sha384", feature = "sha512")))]
            _ => tlserr(UNSUPPORTED_ALGORITHM),
        }
    }

    pub(super) fn hkdf_algorithm(alg: &HashAlgorithm) -> Result<HkdfAlgorithm, TLSError> {
        match alg {
            #[cfg(feature = "sha256")]
            HashAlgorithm::SHA256 => Ok(HkdfAlgorithm::Sha256),
            #[cfg(feature = "sha384")]
            HashAlgorithm::SHA384 => Ok(HkdfAlgorithm::Sha384),
            #[cfg(feature = "sha512")]
            HashAlgorithm::SHA512 => Ok(HkdfAlgorithm::Sha512),
            #[cfg(not(all(feature = "sha256", feature = "sha384", feature = "sha512")))]
            _ => tlserr(UNSUPPORTED_ALGORITHM),
        }
    }

    pub(super) fn kem_algorithm(alg: KemScheme) -> Result<libcrux_kem::Algorithm, TLSError> {
        match alg {
            #[cfg(feature = "x25519")]
            KemScheme::X25519 => Ok(libcrux_kem::Algorithm::X25519),
            #[cfg(feature = "p256")]
            KemScheme::Secp256r1 => Ok(libcrux_kem::Algorithm::Secp256r1),
            #[cfg(feature = "mlkem768")]
            KemScheme::X25519MlKem768 => Ok(libcrux_kem::Algorithm::X25519MlKem768Draft00),
            _ => tlserr(UNSUPPORTED_ALGORITHM),
        }
    }

    // Bridge the KEM's rand_core 0.10 API to Bertie's existing caller RNG.
    pub(super) struct KemRng<'a, R: CryptoRng>(pub(super) &'a mut R);

    impl<R: CryptoRng> rand_core::TryRng for KemRng<'_, R> {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.0.next_u32())
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.0.next_u64())
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            self.0.fill_bytes(dest);
            Ok(())
        }
    }
    impl<R: CryptoRng> rand_core::TryCryptoRng for KemRng<'_, R> {}

    pub(super) fn key_gen(
        alg: libcrux_kem::Algorithm,
        rng: &mut impl CryptoRng,
    ) -> Result<(libcrux_kem::PrivateKey, libcrux_kem::PublicKey), libcrux_kem::Error> {
        libcrux_kem::key_gen(alg, &mut KemRng(rng))
    }

    pub(super) fn encapsulate(
        pk: &libcrux_kem::PublicKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(libcrux_kem::Ss, libcrux_kem::Ct), libcrux_kem::Error> {
        pk.encapsulate(&mut KemRng(rng))
    }
}
