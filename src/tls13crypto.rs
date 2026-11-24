use std::vec;

#[cfg(feature = "hax-pv")]
use hax_lib::{proverif, pv_constructor};

#[cfg(feature = "chacha20poly1305")]
use libcrux_chacha20poly1305::{decrypt_detached, encrypt_detached};
#[cfg(feature = "ecdsa-p256")]
use libcrux_ecdsa::DigestAlgorithm as EcDsaDigestAlgorithm;
use libcrux_hkdf::{expand, extract, Algorithm as HkdfAlgorithm};
use libcrux_hmac::{hmac, Algorithm as HmacAlgorithm};

use libcrux_kem::{Ct, PrivateKey, PublicKey};
#[cfg(feature = "rsa")]
use libcrux_rsa::{
    sign_varlen, verify_varlen, DigestAlgorithm as RsaDigestAlgorithm, VarLenPrivateKey,
    VarLenPublicKey,
};
use libcrux_sha2::Algorithm as Sha2Algorithm;

use rand::CryptoRng;

use crate::std::{fmt::Display, format, vec::Vec};

use crate::tls13utils::{
    check_mem, eq, length_u16_encoded, tlserr, Bytes, Error, TLSError, CRYPTO_ERROR,
    INCORRECT_ARRAY_LENGTH, INVALID_SIGNATURE, U8, UNSUPPORTED_ALGORITHM,
};

pub(crate) type Random = Bytes;
pub type SignatureKey = Bytes;
pub(crate) type Psk = Bytes;
pub(crate) type Key = Bytes;
pub(crate) type MacKey = Bytes;
pub(crate) type KemPk = Bytes;
pub(crate) type KemSk = Bytes;
pub(crate) type Hmac = Bytes;
pub(crate) type Digest = Bytes;
pub(crate) type AeadIV = Bytes;
pub(crate) type VerificationKey = Bytes;

/// An AEAD key and iv package.
pub(crate) struct AeadKeyIV {
    pub(crate) key: AeadKey,
    pub(crate) iv: Bytes,
}

impl AeadKeyIV {
    /// Create a new [`AeadKeyIV`].
    pub(crate) fn new(key: AeadKey, iv: Bytes) -> Self {
        Self { key, iv }
    }
}

/// An AEAD key.
pub(crate) struct AeadKey {
    bytes: Bytes,
    _alg: AeadAlgorithm,
}

impl AeadKey {
    /// Create a new AEAD key from the raw bytes and the algorithm.
    pub(crate) fn new(bytes: Bytes, _alg: AeadAlgorithm) -> Self {
        Self { bytes, _alg }
    }

    /// Get the raw bytes of the key.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &Bytes {
        &self.bytes
    }
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
    EcDsa(VerificationKey),  // Uncompressed point 0x04...
    Rsa(RsaVerificationKey), // N, e
}

/// Bertie hash algorithms.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
}

/// Hash `data` with the given `algorithm`.
///
/// Returns the digest or an [`TLSError`].
#[cfg_attr(feature = "hax-pv", pv_constructor)]
pub(crate) fn hash(ha: &HashAlgorithm, data: &Bytes) -> Result<Bytes, TLSError> {
    let hasher = ha.libcrux_algorithm()?;

    let mut digest = vec![0u8; hasher.hash_len()];
    hasher.hash(&data.declassify(), &mut digest);

    Ok(digest.into())
}

#[hax_lib::attributes]
impl HashAlgorithm {
    /// Get the libcrux hash algorithm
    fn libcrux_algorithm(&self) -> Result<Sha2Algorithm, TLSError> {
        match self {
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

    /// Get the size of the hash digest.
    #[hax_lib::ensures(|result| result <= 64)]
    #[cfg_attr(feature = "hax-pv", proverif::replace_body("0"))]
    pub(crate) fn hash_len(&self) -> usize {
        match self {
            HashAlgorithm::SHA256 => Sha2Algorithm::Sha256.hash_len(),
            HashAlgorithm::SHA384 => Sha2Algorithm::Sha384.hash_len(),
            HashAlgorithm::SHA512 => Sha2Algorithm::Sha512.hash_len(),
        }
    }

    /// Get the libcrux hmac algorithm.
    fn hmac_algorithm(&self) -> Result<HmacAlgorithm, TLSError> {
        match self {
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

    /// Get the size of the hmac tag.
    #[cfg_attr(feature = "hax-pv", hax_lib::proverif::replace_body("0"))]
    pub(crate) fn hmac_tag_len(&self) -> usize {
        self.hash_len()
    }
}

/// Compute the HMAC tag.
///
/// Returns the tag [`Hmac`] or a [`TLSError`].
#[hax_lib::pv_constructor]
pub(crate) fn hmac_tag(alg: &HashAlgorithm, mk: &MacKey, input: &Bytes) -> Result<Hmac, TLSError> {
    Ok(hmac(
        alg.hmac_algorithm()?,
        &mk.declassify(),
        &input.declassify(),
        None,
    )
    .into())
}

/// Verify a given HMAC `tag`.
///
/// Returns `()` if successful or a [`TLSError`].
#[cfg_attr(
    feature = "hax-pv",
    proverif::replace(
        "
reduc
  forall
        alg : $:{HashAlgorithm},
         mk : $:{Bytes},
      input : $:{Bytes};
        ${hmac_verify}(
            alg,
            mk,
            input,
            ${hmac_tag}(alg, mk, input)
         ) = ()."
    )
)]
pub(crate) fn hmac_verify(
    alg: &HashAlgorithm,
    mk: &MacKey,
    input: &Bytes,
    tag: &Bytes,
) -> Result<(), TLSError> {
    if eq(&hmac_tag(alg, mk, input)?, tag) {
        Ok(())
    } else {
        tlserr(CRYPTO_ERROR)
    }
}

/// Get the libcrux HKDF algorithm.
fn hkdf_algorithm(alg: &HashAlgorithm) -> Result<HkdfAlgorithm, TLSError> {
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

/// HKDF Extract.
///
/// Returns the result as [`Bytes`] or a [`TLSError`].
#[hax_lib::pv_constructor]
pub(crate) fn hkdf_extract(
    alg: &HashAlgorithm,
    ikm: &Bytes,
    salt: &Bytes,
) -> Result<Bytes, TLSError> {
    extract(hkdf_algorithm(alg)?, salt.declassify(), ikm.declassify())
        .map(|bytes| bytes.into())
        .map_err(|_| CRYPTO_ERROR)
}

/// HKDF Expand.
///
/// Returns the result as [`Bytes`] or a [`TLSError`].
#[hax_lib::pv_constructor]
pub(crate) fn hkdf_expand(
    alg: &HashAlgorithm,
    prk: &Bytes,
    info: &Bytes,
    len: usize,
) -> Result<Bytes, TLSError> {
    match expand(
        hkdf_algorithm(alg)?,
        prk.declassify(),
        info.declassify(),
        len,
    ) {
        Ok(x) => Ok(x.into()),
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// AEAD Algorithms for Bertie
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum AeadAlgorithm {
    Chacha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

impl AeadAlgorithm {
    /// Get the key length of the AEAD algorithm in bytes.
    #[cfg_attr(feature = "hax-pv", proverif::replace_body("0"))]
    pub(crate) fn key_len(&self) -> usize {
        match self {
            AeadAlgorithm::Chacha20Poly1305 => 32,
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => 32,
        }
    }

    /// Get the length of the IV for this algorithm.
    #[cfg_attr(feature = "hax-pv", proverif::replace_body("0"))]
    pub(crate) fn iv_len(self) -> usize {
        match self {
            AeadAlgorithm::Chacha20Poly1305 => 12,
            AeadAlgorithm::Aes128Gcm => 12,
            AeadAlgorithm::Aes256Gcm => 12,
        }
    }
}

/// AEAD encrypt
#[cfg(feature = "chacha20poly1305")]
pub(crate) fn aead_encrypt(
    k: &AeadKey,
    iv: &AeadIV,
    plain: &Bytes,
    aad: &Bytes,
) -> Result<Bytes, TLSError> {
    // We only support Chacha20Poly1305 right now.
    let key = k
        .bytes
        .declassify_array()
        .map_err(|_| INCORRECT_ARRAY_LENGTH)?;

    let mut ctxt = vec![0u8; plain.len()];
    let mut tag = [0u8; libcrux_chacha20poly1305::TAG_LEN];
    let result = encrypt_detached(
        &key,
        &plain.declassify(),
        &mut ctxt,
        &mut tag,
        &aad.declassify(),
        &iv.declassify_array()?,
    );

    match result {
        Ok(_) => {
            let cipby: Bytes = ctxt.into();
            let tagby: Bytes = tag.as_ref().into();
            Ok(cipby.concat(tagby))
        }
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// AEAD decrypt.
#[cfg(feature = "chacha20poly1305")]
pub(crate) fn aead_decrypt(
    k: &AeadKey,
    iv: &AeadIV,
    cip: &Bytes,
    aad: &Bytes,
) -> Result<Bytes, TLSError> {
    // event!(Level::DEBUG, "AEAD decrypt with {:?}", k.alg);

    if cip.len() < 16 {
        return tlserr(CRYPTO_ERROR);
    }

    let tag = cip.slice(cip.len() - 16, 16);
    let ctxt = cip.slice(0, cip.len() - 16);
    let tag: [u8; 16] = tag.declassify_array()?;
    let key = k
        .bytes
        .declassify_array()
        .map_err(|_| INCORRECT_ARRAY_LENGTH)?;
    let mut ptxt = vec![0u8; ctxt.len()];

    let result = decrypt_detached(
        &key,
        &mut ptxt,
        &ctxt.declassify(),
        &tag,
        &aad.declassify(),
        &iv.declassify_array()?,
    );

    match result {
        Ok(plain) => Ok(plain.into()),
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// Signature schemes for Bertie.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SignatureScheme {
    RsaPssRsaSha256,
    EcdsaSecp256r1Sha256,
    ED25519,
}

/// Sign the `input` with the provided RSA key.
#[cfg(feature = "rsa")]
pub(crate) fn sign_rsa(
    sk: &Bytes,
    pk_modulus: &Bytes,
    pk_exponent: &Bytes,
    cert_scheme: SignatureScheme,
    input: &Bytes,
    rng: &mut impl CryptoRng,
) -> Result<Bytes, TLSError> {
    // salt must be same length as digest output length
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    if !matches!(cert_scheme, SignatureScheme::RsaPssRsaSha256) {
        return tlserr(CRYPTO_ERROR); // XXX: Right error type?
    }

    if !valid_rsa_exponent(pk_exponent.declassify()) {
        return tlserr(UNSUPPORTED_ALGORITHM);
    }

    supported_rsa_key_size(pk_modulus)?;
    let pk = VarLenPublicKey::try_from(&pk_modulus.declassify()[1..])
        .map_err(|_| INCORRECT_ARRAY_LENGTH)?;

    let pk_modulus_vec = pk_modulus.declassify();
    let sk_vec = sk.declassify();
    let sk = VarLenPrivateKey::from_components(&pk_modulus_vec[1..], &sk_vec)
        .map_err(|_| INCORRECT_ARRAY_LENGTH)?;

    let msg = &input.declassify();
    // XXX: hard coded length because of bad libcrux API
    let mut signature = [0u8; 512];
    sign_varlen(
        RsaDigestAlgorithm::Sha2_256,
        &sk,
        msg,
        &salt,
        &mut signature,
    )
    .map_err(|_| CRYPTO_ERROR)?;

    Ok(signature.into())
}

/// Sign the bytes in `input` with the signature key `sk` and `algorithm`.
#[cfg_attr(
    feature = "hax-pv",
    proverif::before(
        "fun extern__sign_inner(
         $:{SignatureScheme},
         $:{Bytes}, (* sk *)
         $:{Bytes}  (* input *)
     )
     : $:{Bytes}."
    )
)]
#[cfg_attr(
    feature = "hax-pv",
    proverif::replace_body(
        "(extern__sign_inner(
              algorithm,
              sk,
              input
          )
       )"
    )
)]
pub(crate) fn sign(
    algorithm: &SignatureScheme,
    sk: &Bytes,
    input: &Bytes,
    rng: &mut impl CryptoRng,
) -> Result<Bytes, TLSError> {
    match algorithm {
        #[cfg(feature = "ecdsa-p256")]
        SignatureScheme::EcdsaSecp256r1Sha256 => libcrux_ecdsa::p256::rand::sign(
            EcDsaDigestAlgorithm::Sha256,
            &input.declassify(),
            &sk.declassify()
                .as_slice()
                .try_into()
                .map_err(|_| INCORRECT_ARRAY_LENGTH)?,
            rng,
        )
        .map_err(|_| CRYPTO_ERROR)
        .map(|s| {
            let (r, s) = s.as_bytes();
            Bytes::from(r).concat(Bytes::from(s))
        }),

        #[cfg(feature = "ed25519")]
        SignatureScheme::ED25519 => libcrux_ed25519::sign(
            &input.declassify(),
            &sk.declassify()
                .try_into()
                .map_err(|_| INCORRECT_ARRAY_LENGTH)?,
        )
        .map_err(|_| CRYPTO_ERROR)
        .map(|s| s.into()),

        _ => tlserr(UNSUPPORTED_ALGORITHM),
    }
}

/// Verify the `input` bytes against the provided `signature`.
///
/// Return `Ok(())` if the verification succeeds, and a [`TLSError`] otherwise.
#[cfg_attr(
    feature = "hax-pv",
    proverif::replace(
        "
fun extern__vk_from_sk($:{Bytes}): $:{PublicVerificationKey}.

fun extern__sign_inner_rsa(
                 $:{Bytes}, (* sk *)
                 $:{Bytes}  (* input *)
             )
             : $:{Bytes}.

fun ${verify}(
            $:{SignatureScheme}, 
            $:{PublicVerificationKey},
            $:{Bytes}, (* input *)
            $:{Bytes}  (* sig *)
        )
    : bitstring

  reduc forall
                     sk: $:{Bytes},
                  input: $:{Bytes};

        ${verify}(
            ${SignatureScheme::RsaPssRsaSha256},
            extern__vk_from_sk(sk),
            input,
            extern__sign_inner_rsa(
                sk,
                input
            )
        )
        = ()

  otherwise forall
                sk                   : $:{Bytes},
                input                : $:{Bytes};

        ${verify}(
            ${SignatureScheme::EcdsaSecp256r1Sha256},
            extern__vk_from_sk(sk),
            input,
            extern__sign_inner(
                ${SignatureScheme::EcdsaSecp256r1Sha256},
                sk,
                input
            )
        )
        = ()."
    )
)]
pub(crate) fn verify(
    alg: &SignatureScheme,
    pk: &PublicVerificationKey,
    input: &Bytes,
    sig: &Bytes,
) -> Result<(), TLSError> {
    match (alg, pk) {
        #[cfg(feature = "ecdsa-p256")]
        (SignatureScheme::EcdsaSecp256r1Sha256, PublicVerificationKey::EcDsa(pk)) => {
            libcrux_ecdsa::p256::verify(
                EcDsaDigestAlgorithm::Sha256,
                &input.declassify(),
                &libcrux_ecdsa::p256::Signature::from_bytes(sig.declassify_array()?),
                &libcrux_ecdsa::p256::PublicKey::try_from(&pk.declassify_array()?)
                    .map_err(|_| CRYPTO_ERROR)?,
            )
            .map_err(|_| INVALID_SIGNATURE)
        }

        #[cfg(feature = "ed25519")]
        (SignatureScheme::ED25519, PublicVerificationKey::EcDsa(pk)) => libcrux_ed25519::verify(
            &input.declassify(),
            &pk.declassify()
                .try_into()
                .map_err(|_| INCORRECT_ARRAY_LENGTH)?,
            &sig.declassify_array()?,
        )
        .map_err(|_| INVALID_SIGNATURE),

        #[cfg(feature = "rsa")]
        (
            SignatureScheme::RsaPssRsaSha256,
            PublicVerificationKey::Rsa(RsaVerificationKey {
                modulus: n,
                exponent: e,
            }),
        ) => {
            if !valid_rsa_exponent(e.declassify()) {
                tlserr(UNSUPPORTED_ALGORITHM)
            } else {
                supported_rsa_key_size(n)?;
                let n_vec = n.declassify();
                let pk =
                    VarLenPublicKey::try_from(&n_vec[1..]).map_err(|_| INCORRECT_ARRAY_LENGTH)?;

                verify_varlen(
                    RsaDigestAlgorithm::Sha2_256,
                    &pk,
                    &input.declassify(),
                    32, // salt must be same length as digest ouput length
                    &sig.declassify(),
                )
                .map_err(|_| CRYPTO_ERROR)
            }
        }
        _ => tlserr(UNSUPPORTED_ALGORITHM),
    }
}

/// Determine if given modulus conforms to one of the key sizes supported by
/// `libcrux`.
#[cfg(feature = "rsa")]
fn supported_rsa_key_size(n: &Bytes) -> Result<(), u8> {
    match n.len() as u16 {
        // The format includes an extra 0-byte in front to disambiguate from negative numbers
        257 | 385 | 513 | 769 | 1025 => Ok(()),
        _ => tlserr(UNSUPPORTED_ALGORITHM),
    }
}

/// Determine if given public exponent is supported by `libcrux`, i.e. whether
///  `e == 0x010001`.
#[cfg(feature = "rsa")]
fn valid_rsa_exponent(e: Vec<u8>) -> bool {
    e.len() == 3 && e[0] == 0x1 && e[1] == 0x0 && e[2] == 0x1
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

impl KemScheme {
    /// Get the libcrux algorithm for this [`KemScheme`].
    fn libcrux_kem_algorithm(self) -> Result<libcrux_kem::Algorithm, TLSError> {
        match self {
            #[cfg(feature = "x25519")]
            KemScheme::X25519 => Ok(libcrux_kem::Algorithm::X25519),
            #[cfg(feature = "p256")]
            KemScheme::Secp256r1 => Ok(libcrux_kem::Algorithm::Secp256r1),
            #[cfg(feature = "mlkem768")]
            KemScheme::X25519MlKem768 => Ok(libcrux_kem::Algorithm::X25519MlKem768Draft00),
            _ => tlserr(UNSUPPORTED_ALGORITHM),
        }
    }
}

// Implementation glue, outside the existing abstract cryptographic proof interface.
mod non_hax {
    use super::CryptoRng;
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

/// Generate a new KEM key pair.
#[cfg_attr(
    feature = "hax-pv",
    proverif::before("fun extern__kem_pk_from_sk($:{Bytes}): $:{Bytes}.")
)]
#[cfg_attr(
    feature = "hax-pv",
    proverif::replace_body(
        "(new kem_sk: $:{Bytes};
       let kem_pk = extern__kem_pk_from_sk(kem_sk) in
       (kem_sk, kem_pk))"
    )
)]
pub(crate) fn kem_keygen(
    alg: KemScheme,
    rng: &mut impl CryptoRng,
) -> Result<(KemSk, KemPk), TLSError> {
    let res = non_hax::key_gen(alg.libcrux_kem_algorithm()?, rng);
    match res {
        Ok((sk, pk)) => {
            // event!(
            //     Level::TRACE,
            //     "Generated KEM public key: {}",
            //     Bytes::from(pk.encode()).as_hex()
            // );
            Ok((
                Bytes::from(sk.encode()),
                encoding_prefix(alg).concat(Bytes::from(pk.encode())),
            ))
        }
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// Note that the `encode` in libcrux currently returns the raw
/// concatenation of bytes. We have to prepend the 0x04 for
/// uncompressed points on NIST curves.
fn encoding_prefix(alg: KemScheme) -> Bytes {
    if alg == KemScheme::Secp256r1 || alg == KemScheme::Secp384r1 || alg == KemScheme::Secp521r1 {
        Bytes::from([0x04])
    } else {
        Bytes::new()
    }
}

/// Note that the `encode` in libcrux operates on the raw
/// concatenation of bytes. We have to work with uncompressed NIST points here.
fn into_raw(alg: KemScheme, point: Bytes) -> Bytes {
    if alg == KemScheme::Secp256r1 || alg == KemScheme::Secp384r1 || alg == KemScheme::Secp521r1 {
        point.slice_range(1..point.len())
    } else {
        point
    }
}

/// KEM encapsulation
#[cfg_attr(
    feature = "hax-pv",
    proverif::before("fun extern__kem_encapsulation($:{Bytes}, $:{Bytes}): $:{Bytes}.")
)]
#[cfg_attr(
    feature = "hax-pv",
    proverif::replace_body(
        "(new shared_secret: $:{Bytes};
          let ct = extern__kem_encapsulation(pk, shared_secret) in
          (shared_secret, ct))"
    )
)]
pub(crate) fn kem_encap(
    alg: KemScheme,
    pk: &Bytes,
    rng: &mut impl CryptoRng,
) -> Result<(Bytes, Bytes), TLSError> {
    // event!(Level::DEBUG, "KEM Encaps with {alg:?}");
    // event!(Level::TRACE, "  pk:  {}", pk.as_hex());

    let pk = into_raw(alg, pk.clone());
    let pk = PublicKey::decode(alg.libcrux_kem_algorithm()?, &pk.declassify())
        .map_err(|_| CRYPTO_ERROR)?;
    let res = non_hax::encapsulate(&pk, rng);
    match res {
        Ok((shared_secret, ct)) => {
            let ct = encoding_prefix(alg).concat(Bytes::from(ct.encode()));
            let shared_secret = to_shared_secret(alg, Bytes::from(shared_secret.encode()));

            // event!(Level::TRACE, "  output ciphertext: {}", ct.as_hex());
            Ok((shared_secret, ct))
        }
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// We only want the X coordinate for points on NIST curves.
fn to_shared_secret(alg: KemScheme, shared_secret: Bytes) -> Bytes {
    if alg == KemScheme::Secp256r1 {
        shared_secret.slice_range(0..32)
    } else if alg == KemScheme::Secp384r1 || alg == KemScheme::Secp521r1 {
        unimplemented!("not supported yet");
    } else {
        shared_secret
    }
}

/// KEM decapsulation
#[cfg_attr(
    feature = "hax-pv",
    proverif::replace(
        "reduc forall alg: $:{KemScheme}, kem_sk: $:{Bytes}, shared_secret: $:{Bytes};
     ${kem_decap}(
     alg, extern__kem_encapsulation(extern__kem_pk_from_sk(kem_sk), shared_secret), kem_sk
     ) = shared_secret."
    )
)]
pub(crate) fn kem_decap(alg: KemScheme, ct: &Bytes, sk: &Bytes) -> Result<Bytes, TLSError> {
    // event!(Level::DEBUG, "KEM Decaps with {alg:?}");
    // event!(Level::TRACE, "  with ciphertext: {}", ct.as_hex());

    let librux_algorithm = alg.libcrux_kem_algorithm()?;
    let sk = PrivateKey::decode(librux_algorithm, &sk.declassify()).map_err(|_| CRYPTO_ERROR)?;
    let ct = into_raw(alg, ct.clone()).declassify();
    let ct = Ct::decode(librux_algorithm, &ct).map_err(|_| CRYPTO_ERROR)?;
    let res = ct.decapsulate(&sk);
    match res {
        Ok(shared_secret) => {
            let shared_secret: Bytes = shared_secret.encode().into();
            // event!(Level::TRACE, "  shared secret: {}", shared_secret.as_hex());
            let shared_secret = to_shared_secret(alg, shared_secret);
            Ok(shared_secret)
        }
        Err(_) => tlserr(CRYPTO_ERROR),
    }
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

#[hax_lib::attributes]
impl Algorithms {
    /// Create a new [`Algorithms`] object for the TLS 1.3 ciphersuite.
    pub const fn new(
        hash: HashAlgorithm,
        aead: AeadAlgorithm,
        sig: SignatureScheme,
        kem: KemScheme,
        psk: bool,
        zero_rtt: bool,
    ) -> Self {
        Self {
            hash,
            aead,
            signature: sig,
            kem,
            psk_mode: psk,
            zero_rtt,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), TLSError> {
        if self.hash != HashAlgorithm::SHA256
            || self.aead != AeadAlgorithm::Chacha20Poly1305
            || (self.signature != SignatureScheme::EcdsaSecp256r1Sha256
                && !(cfg!(feature = "rsa") && self.signature == SignatureScheme::RsaPssRsaSha256))
            || !matches!(
                self.kem,
                KemScheme::X25519 | KemScheme::Secp256r1 | KemScheme::X25519MlKem768
            )
            || self.psk_mode
            || self.zero_rtt
        {
            return tlserr(UNSUPPORTED_ALGORITHM);
        }
        #[cfg(not(all(
            feature = "sha256",
            feature = "chacha20poly1305",
            feature = "ecdsa-p256",
            feature = "x25519",
            feature = "p256",
            feature = "mlkem768"
        )))]
        {
            let signature_enabled = match self.signature {
                SignatureScheme::EcdsaSecp256r1Sha256 => cfg!(feature = "ecdsa-p256"),
                SignatureScheme::RsaPssRsaSha256 => cfg!(feature = "rsa"),
                SignatureScheme::ED25519 => false,
            };
            let kem_enabled = (self.kem == KemScheme::X25519 && cfg!(feature = "x25519"))
                || (self.kem == KemScheme::Secp256r1 && cfg!(feature = "p256"))
                || (self.kem == KemScheme::X25519MlKem768 && cfg!(feature = "mlkem768"));
            if !cfg!(feature = "sha256")
                || !cfg!(feature = "chacha20poly1305")
                || !signature_enabled
                || !kem_enabled
            {
                return tlserr(UNSUPPORTED_ALGORITHM);
            }
        }
        Ok(())
    }

    /// Get the [`HashAlgorithm`].
    pub fn hash(&self) -> HashAlgorithm {
        self.hash
    }

    /// Get the [`AeadAlgorithm`].
    pub fn aead(&self) -> AeadAlgorithm {
        self.aead
    }

    /// Get the [`SignatureAlgorithm`].
    pub fn signature(&self) -> SignatureScheme {
        self.signature
    }

    /// Get the [`KemScheme`].
    pub fn kem(&self) -> KemScheme {
        self.kem
    }

    /// Returns `true` when using the PSK mode and `false` otherwise.
    pub fn psk_mode(&self) -> bool {
        self.psk_mode
    }

    /// Returns `true` when using zero rtt and `false` otherwise.
    pub fn zero_rtt(&self) -> bool {
        self.zero_rtt
    }

    /// Returns the TLS ciphersuite for the given algorithm when it is supported, or
    /// a [`TLSError`] otherwise.
    #[hax_lib::ensures(|result| match result {
                                    Ok(b) => b.len() == 2,
                                    Err(_) => true})]
    pub(crate) fn ciphersuite(&self) -> Result<Bytes, TLSError> {
        match (self.hash, self.aead) {
            (HashAlgorithm::SHA256, AeadAlgorithm::Aes128Gcm) => Ok([0x13, 0x01].into()),
            (HashAlgorithm::SHA384, AeadAlgorithm::Aes256Gcm) => Ok([0x13, 0x02].into()),
            (HashAlgorithm::SHA256, AeadAlgorithm::Chacha20Poly1305) => Ok([0x13, 0x03].into()),
            _ => tlserr(UNSUPPORTED_ALGORITHM),
        }
    }

    /// Returns the curve id for the given algorithm when it is supported, or a [`TLSError`]
    /// otherwise.
    #[inline(always)]
    #[hax_lib::ensures(|result| match result {
        Ok(b) => b.len() == 2,
        Err(_) => true})]
    pub(crate) fn supported_group(&self) -> Result<Bytes, TLSError> {
        match self.kem() {
            KemScheme::X25519 => Ok([0x00, 0x1D].into()),
            KemScheme::Secp256r1 => Ok([0x00, 0x17].into()),
            KemScheme::X448 => tlserr(UNSUPPORTED_ALGORITHM),
            KemScheme::Secp384r1 => tlserr(UNSUPPORTED_ALGORITHM),
            KemScheme::Secp521r1 => tlserr(UNSUPPORTED_ALGORITHM),
            KemScheme::X25519MlKem768 => Ok([0x11, 0xec].into()), // cf. https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/
        }
    }

    /// Returns the signature id for the given algorithm when it is supported, or a
    ///  [`TLSError`] otherwise.
    #[hax_lib::ensures(|result| match result {
        Ok(b) => b.len() == 2,
        Err(_) => true})]
    pub(crate) fn signature_algorithm(&self) -> Result<Bytes, TLSError> {
        match self.signature() {
            SignatureScheme::RsaPssRsaSha256 => Ok([0x08, 0x04].into()),
            SignatureScheme::EcdsaSecp256r1Sha256 => Ok([0x04, 0x03].into()),
            SignatureScheme::ED25519 => tlserr(UNSUPPORTED_ALGORITHM),
        }
    }

    /// Check the ciphersuite in `bytes` against this ciphersuite.
    #[hax_lib::ensures(|result| match result {
                                    Result::Ok(len) => bytes.len() >= len && len < 65538,
                                    _ => true
                                })]
    pub(crate) fn check(&self, bytes: &[U8]) -> Result<usize, TLSError> {
        let len = length_u16_encoded(bytes)?;
        let cs = self.ciphersuite()?;
        let csl = &bytes[2..2 + len];
        check_mem(cs.as_raw(), csl)?;
        Ok(len + 2)
    }
}

#[hax_lib::opaque]
impl TryFrom<&str> for Algorithms {
    type Error = Error;

    /// Get the ciphersuite from a string description.
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            #[cfg(feature = "rsa")]
            "SHA256_Chacha20Poly1305_RsaPssRsaSha256_P256" => {
                Ok(SHA256_Chacha20Poly1305_RsaPssRsaSha256_P256)
            }
            #[cfg(feature = "rsa")]
            "SHA256_Chacha20Poly1305_RsaPssRsaSha256_X25519" => {
                Ok(SHA256_Chacha20Poly1305_RsaPssRsaSha256_X25519)
            }
            "SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519" => {
                Ok(SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519)
            }
            "SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_P256" => {
                Ok(SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_P256)
            }
            "SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519MLKEM768" => {
                Ok(SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519MlKem768)
            }
            _ => Err(Error::UnknownCiphersuite(format!(
                "Invalid ciphersuite description: {}",
                s
            ))),
        }
    }
}

impl Display for Algorithms {
    fn fmt(&self, f: &mut crate::std::fmt::Formatter<'_>) -> crate::std::fmt::Result {
        write!(
            f,
            "TLS_{:?}_{:?} w/ {:?} | {:?}",
            self.aead, self.hash, self.signature, self.kem
        )
    }
}

/// `TLS_CHACHA20_POLY1305_SHA256`
/// with
/// * x25519 for key exchange
/// * EcDSA P256 SHA256 for signatures
pub const SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519: Algorithms = Algorithms::new(
    HashAlgorithm::SHA256,
    AeadAlgorithm::Chacha20Poly1305,
    SignatureScheme::EcdsaSecp256r1Sha256,
    KemScheme::X25519,
    false,
    false,
);

/// `TLS_CHACHA20_POLY1305_SHA256`
/// with
/// * X25519MlKem768 for key exchange (cf. https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/)
/// * EcDSA P256 SHA256 for signatures
pub const SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519MlKem768: Algorithms = Algorithms::new(
    HashAlgorithm::SHA256,
    AeadAlgorithm::Chacha20Poly1305,
    SignatureScheme::EcdsaSecp256r1Sha256,
    KemScheme::X25519MlKem768,
    false,
    false,
);

/// `TLS_CHACHA20_POLY1305_SHA256`
/// with
/// * P256 for key exchange
/// * EcDSA P256 SHA256 for signatures
pub const SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_P256: Algorithms = Algorithms::new(
    HashAlgorithm::SHA256,
    AeadAlgorithm::Chacha20Poly1305,
    SignatureScheme::EcdsaSecp256r1Sha256,
    KemScheme::Secp256r1,
    false,
    false,
);

#[cfg(test)]
mod maintained_kem_tests {
    use super::*;

    #[test]
    fn supported_groups_keep_wire_sizes_and_shared_secrets() {
        let mut rng = rand::rng();
        for (algs, group, pk_len, ct_len, ss_len) in [
            (
                SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519MlKem768,
                [0x11, 0xec],
                1216,
                1120,
                64,
            ),
            (
                SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519,
                [0, 0x1d],
                32,
                32,
                32,
            ),
            (
                SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_P256,
                [0, 0x17],
                65,
                65,
                32,
            ),
        ] {
            assert_eq!(algs.supported_group().unwrap().declassify(), group);
            let enabled = match algs.kem() {
                KemScheme::X25519 => cfg!(feature = "x25519"),
                KemScheme::Secp256r1 => cfg!(feature = "p256"),
                KemScheme::X25519MlKem768 => cfg!(feature = "mlkem768"),
                _ => unreachable!(),
            };
            if !enabled {
                assert!(kem_keygen(algs.kem(), &mut rng).is_err());
                continue;
            }
            let (sk, pk) = kem_keygen(algs.kem(), &mut rng).unwrap();
            assert_eq!(pk.len(), pk_len);
            let (ss, ct) = kem_encap(algs.kem(), &pk, &mut rng).unwrap();
            assert_eq!(ct.len(), ct_len);
            assert_eq!(ss.len(), ss_len);
            assert_eq!(
                ss.declassify(),
                kem_decap(algs.kem(), &ct, &sk).unwrap().declassify()
            );
        }
    }
}

#[cfg(all(test, feature = "chacha20poly1305"))]
mod malformed_aead_tests {
    use super::*;

    #[test]
    fn decrypt_rejects_ciphertext_shorter_than_tag() {
        let key = AeadKey::new(Bytes::from([0u8; 32]), AeadAlgorithm::Chacha20Poly1305);
        let iv = Bytes::from([0u8; 12]);
        let aad = Bytes::new();
        for len in 0..16 {
            let ciphertext = Bytes::from(vec![0u8; len]);
            assert!(aead_decrypt(&key, &iv, &ciphertext, &aad).is_err());
        }
    }
}

#[cfg(not(feature = "chacha20poly1305"))]
pub(crate) fn aead_encrypt(
    _: &AeadKey,
    _: &AeadIV,
    _: &Bytes,
    _: &Bytes,
) -> Result<Bytes, TLSError> {
    tlserr(UNSUPPORTED_ALGORITHM)
}
#[cfg(not(feature = "chacha20poly1305"))]
pub(crate) fn aead_decrypt(
    _: &AeadKey,
    _: &AeadIV,
    _: &Bytes,
    _: &Bytes,
) -> Result<Bytes, TLSError> {
    tlserr(UNSUPPORTED_ALGORITHM)
}

#[cfg(feature = "rsa")]
pub const SHA256_Chacha20Poly1305_RsaPssRsaSha256_X25519: Algorithms = Algorithms::new(
    HashAlgorithm::SHA256,
    AeadAlgorithm::Chacha20Poly1305,
    SignatureScheme::RsaPssRsaSha256,
    KemScheme::X25519,
    false,
    false,
);

#[cfg(feature = "rsa")]
pub const SHA256_Chacha20Poly1305_RsaPssRsaSha256_P256: Algorithms = Algorithms::new(
    HashAlgorithm::SHA256,
    AeadAlgorithm::Chacha20Poly1305,
    SignatureScheme::RsaPssRsaSha256,
    KemScheme::Secp256r1,
    false,
    false,
);
