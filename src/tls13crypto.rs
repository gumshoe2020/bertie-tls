#[cfg(feature = "hax-pv")]
use hax_lib::{proverif, pv_constructor};

mod algorithm_types;
mod backend;

pub use algorithm_types::{
    AeadAlgorithm, Algorithms, HashAlgorithm, KemScheme, PublicVerificationKey, RsaVerificationKey,
    SignatureScheme,
};

use rand::CryptoRng;

use crate::std::{fmt::Display, format, vec::Vec};

use crate::tls13utils::{
    check_mem, eq, length_u16_encoded, tlserr, Bytes, Error, TLSError, CRYPTO_ERROR,
    INCORRECT_ARRAY_LENGTH, U8, UNSUPPORTED_ALGORITHM,
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

/// Hash `data` with the given `algorithm`.
///
/// Returns the digest or an [`TLSError`].
#[cfg_attr(feature = "hax-pv", pv_constructor)]
pub(crate) fn hash(ha: &HashAlgorithm, data: &Bytes) -> Result<Bytes, TLSError> {
    Ok(backend::sha2_digest(ha, &data.declassify())?.into())
}

#[hax_lib::attributes]
impl HashAlgorithm {
    /// Get the size of the hash digest.
    #[hax_lib::ensures(|result| result <= 64)]
    #[cfg_attr(feature = "hax-pv", proverif::replace_body("0"))]
    pub(crate) fn hash_len(&self) -> usize {
        match self {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA384 => 48,
            HashAlgorithm::SHA512 => 64,
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
    Ok(backend::hmac_compute(alg, &mk.declassify(), &input.declassify())?.into())
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

/// HKDF Extract.
///
/// Returns the result as [`Bytes`] or a [`TLSError`].
#[hax_lib::pv_constructor]
pub(crate) fn hkdf_extract(
    alg: &HashAlgorithm,
    ikm: &Bytes,
    salt: &Bytes,
) -> Result<Bytes, TLSError> {
    Ok(backend::hkdf_extract_prk(alg, &salt.declassify(), &ikm.declassify())?.into())
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
    Ok(backend::hkdf_expand_okm(alg, &prk.declassify(), &info.declassify(), len)?.into())
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

    let iv = iv.declassify_array()?;
    let (ctxt, tag) =
        backend::chacha20poly1305_seal(&key, &iv, &aad.declassify(), &plain.declassify())?;
    let cipby: Bytes = ctxt.into();
    let tagby: Bytes = tag.as_ref().into();
    // The backend gives no length facts; this rules out overflow when appending the tag.
    if cipby.len() > usize::MAX - tagby.len() {
        return tlserr(CRYPTO_ERROR);
    }
    Ok(cipby.concat(tagby))
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
    let iv = iv.declassify_array()?;
    Ok(
        backend::chacha20poly1305_open(&key, &iv, &aad.declassify(), &ctxt.declassify(), &tag)?
            .into(),
    )
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
    Ok(backend::rsa_pss_sha256_sign(
        &pk_modulus.declassify(),
        &sk.declassify(),
        &input.declassify(),
        &salt,
    )?
    .into())
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
        SignatureScheme::EcdsaSecp256r1Sha256 => {
            Ok(backend::ecdsa_p256_sha256_sign(&input.declassify(), &sk.declassify(), rng)?.into())
        }

        #[cfg(feature = "ed25519")]
        SignatureScheme::ED25519 => {
            let sk = sk
                .declassify()
                .try_into()
                .map_err(|_| INCORRECT_ARRAY_LENGTH)?;
            Ok(backend::ed25519_sign(&input.declassify(), &sk)?.into())
        }

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
            backend::ecdsa_p256_sha256_verify(
                &input.declassify(),
                sig.declassify_array()?,
                &pk.declassify_array()?,
            )
        }

        #[cfg(feature = "ed25519")]
        (SignatureScheme::ED25519, PublicVerificationKey::EcDsa(pk)) => {
            let pk = pk
                .declassify()
                .try_into()
                .map_err(|_| INCORRECT_ARRAY_LENGTH)?;
            backend::ed25519_verify(&input.declassify(), &pk, &sig.declassify_array()?)
        }

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
                backend::rsa_pss_sha256_verify(
                    &n.declassify(),
                    &input.declassify(),
                    &sig.declassify(),
                )
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
    match backend::kem_generate(alg, rng) {
        Ok((sk, pk)) => {
            // event!(
            //     Level::TRACE,
            //     "Generated KEM public key: {}",
            //     Bytes::from(pk.encode()).as_hex()
            // );
            let prefix = encoding_prefix(alg);
            let pk = Bytes::from(pk);
            if pk.len() > usize::MAX - prefix.len() {
                return tlserr(CRYPTO_ERROR);
            }
            Ok((Bytes::from(sk), prefix.concat(pk)))
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
fn into_raw(alg: KemScheme, point: Bytes) -> Result<Bytes, TLSError> {
    if alg == KemScheme::Secp256r1 || alg == KemScheme::Secp384r1 || alg == KemScheme::Secp521r1 {
        if point.len() == 0 || point[0] != U8(0x04) {
            return tlserr(CRYPTO_ERROR);
        }
        Ok(point.slice_range(1..point.len()))
    } else {
        Ok(point)
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

    let pk = into_raw(alg, pk.clone())?;
    match backend::kem_encapsulate(alg, &pk.declassify(), rng) {
        Ok((shared_secret, ct)) => {
            let prefix = encoding_prefix(alg);
            let ct = Bytes::from(ct);
            if ct.len() > usize::MAX - prefix.len() {
                return tlserr(CRYPTO_ERROR);
            }
            let ct = prefix.concat(ct);
            let shared_secret = to_shared_secret(alg, Bytes::from(shared_secret))?;

            // event!(Level::TRACE, "  output ciphertext: {}", ct.as_hex());
            Ok((shared_secret, ct))
        }
        Err(_) => tlserr(CRYPTO_ERROR),
    }
}

/// We only want the X coordinate for points on NIST curves.
fn to_shared_secret(alg: KemScheme, shared_secret: Bytes) -> Result<Bytes, TLSError> {
    if alg == KemScheme::Secp256r1 {
        if shared_secret.len() < 32 {
            return tlserr(CRYPTO_ERROR);
        }
        Ok(shared_secret.slice_range(0..32))
    } else if alg == KemScheme::Secp384r1 || alg == KemScheme::Secp521r1 {
        tlserr(CRYPTO_ERROR)
    } else {
        Ok(shared_secret)
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

    let ct = into_raw(alg, ct.clone())?.declassify();
    match backend::kem_decapsulate(alg, &ct, &sk.declassify()) {
        Ok(shared_secret) => {
            // event!(Level::TRACE, "  shared secret: {}", shared_secret.as_hex());
            let shared_secret = to_shared_secret(alg, shared_secret.into())?;
            Ok(shared_secret)
        }
        Err(_) => tlserr(CRYPTO_ERROR),
    }
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
            (HashAlgorithm::SHA256, AeadAlgorithm::Aes128Gcm) => {
                Ok(Bytes::from_slice(&[0x13, 0x01]))
            }
            (HashAlgorithm::SHA384, AeadAlgorithm::Aes256Gcm) => {
                Ok(Bytes::from_slice(&[0x13, 0x02]))
            }
            (HashAlgorithm::SHA256, AeadAlgorithm::Chacha20Poly1305) => {
                Ok(Bytes::from_slice(&[0x13, 0x03]))
            }
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
            KemScheme::X25519 => Ok(Bytes::from_slice(&[0x00, 0x1D])),
            KemScheme::Secp256r1 => Ok(Bytes::from_slice(&[0x00, 0x17])),
            KemScheme::X448 => tlserr(UNSUPPORTED_ALGORITHM),
            KemScheme::Secp384r1 => tlserr(UNSUPPORTED_ALGORITHM),
            KemScheme::Secp521r1 => tlserr(UNSUPPORTED_ALGORITHM),
            KemScheme::X25519MlKem768 => Ok(Bytes::from_slice(&[0x11, 0xec])), // cf. https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/
        }
    }

    /// Returns the signature id for the given algorithm when it is supported, or a
    ///  [`TLSError`] otherwise.
    #[hax_lib::ensures(|result| match result {
        Ok(b) => b.len() == 2,
        Err(_) => true})]
    pub(crate) fn signature_algorithm(&self) -> Result<Bytes, TLSError> {
        match self.signature() {
            SignatureScheme::RsaPssRsaSha256 => Ok(Bytes::from_slice(&[0x08, 0x04])),
            SignatureScheme::EcdsaSecp256r1Sha256 => Ok(Bytes::from_slice(&[0x04, 0x03])),
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

#[cfg(not(hax))]
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

#[cfg(test)]
mod malformed_kem_input_tests {
    use super::*;
    use std::vec;

    #[test]
    fn nist_shares_require_uncompressed_prefix() {
        let mut rng = rand::rng();
        let sk = Bytes::from([1u8; 32]);
        for alg in [
            KemScheme::Secp256r1,
            KemScheme::Secp384r1,
            KemScheme::Secp521r1,
        ] {
            for point in [
                Bytes::new(),
                Bytes::from([0x00]),
                Bytes::from([0x02; 65]),
                Bytes::from([0x03; 65]),
            ] {
                assert_eq!(into_raw(alg, point.clone()), Err(CRYPTO_ERROR));
                assert_eq!(kem_encap(alg, &point, &mut rng), Err(CRYPTO_ERROR));
                assert_eq!(kem_decap(alg, &point, &sk), Err(CRYPTO_ERROR));
            }
            let point = Bytes::from([0x04, 1, 2]);
            assert_eq!(into_raw(alg, point), Ok(Bytes::from([1, 2])));
        }
    }

    #[test]
    fn shared_secret_checks_bounds_and_unsupported_curves() {
        for len in 0..32 {
            assert_eq!(
                to_shared_secret(KemScheme::Secp256r1, Bytes::from(vec![0; len])),
                Err(CRYPTO_ERROR)
            );
        }
        let secret = Bytes::from([7; 64]);
        assert_eq!(
            to_shared_secret(KemScheme::Secp256r1, secret.clone()),
            Ok(Bytes::from([7; 32]))
        );
        for alg in [KemScheme::Secp384r1, KemScheme::Secp521r1] {
            assert_eq!(to_shared_secret(alg, secret.clone()), Err(CRYPTO_ERROR));
        }
        for alg in [KemScheme::X25519, KemScheme::X25519MlKem768] {
            assert_eq!(into_raw(alg, secret.clone()), Ok(secret.clone()));
            assert_eq!(to_shared_secret(alg, secret.clone()), Ok(secret.clone()));
        }
    }

    #[test]
    fn encap_rejects_empty_nist_public_key() {
        let mut rng = rand::rng();
        assert!(kem_encap(KemScheme::Secp256r1, &Bytes::new(), &mut rng).is_err());
    }

    #[test]
    fn decap_rejects_empty_nist_ciphertext() {
        let sk = Bytes::from([1u8; 32]);
        assert!(kem_decap(KemScheme::Secp256r1, &Bytes::new(), &sk).is_err());
    }
}

#[cfg(all(test, feature = "chacha20poly1305"))]
mod malformed_aead_tests {
    use super::*;
    use std::vec;

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
