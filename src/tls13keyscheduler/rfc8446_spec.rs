//! RFC 8446 §§7.1, 7.3 specification for full (EC)DHE handshakes without PSK.
//! PSK, binder, 0-RTT, early exporters and ticket PSK derivation are excluded:
//! see TRUSTED.md, "Known defects in unreachable PSK code". KeyUpdate has only
//! a wire enum/conversion in bertie, no implemented transition; §7.2 is excluded.
//!
//! Ported structure: miTLS commit 9a75fa8c46e50897b1f43002885d25a34dfa929a
//! (all miTLS citations below use this commit). No upstream proof assumptions
//! or ghost identities are ported. Client and server secrets stay distinct;
//! ticket nonce provenance is outside this specification (no ticket derivation).
//! RFC line numbers refer to the SHA-256-pinned rfc8446.txt in the P0 survey.
//! HKDF calls share bertie's opaque crypto boundary. Their intended mathematical
//! meaning is HACL* Spec.Agile.HKDF (see TRUSTED.md); no backend equality is proved.

use crate::{
    tls13crypto::{hash, hkdf_expand, hkdf_extract, Digest, HashAlgorithm, Key},
    tls13utils::{Bytes, TLSError, PAYLOAD_TOO_LONG},
};

/// miTLS src/parsers/MiTLS.Parsers.HKDF.rfc:1–5 and src/tls/MiTLS.HKDF.fst:188,216.
/// RFC 8446:5053–5066. Correct final minimum 7 and lowercase six-byte prefix;
/// reject an empty Label instead of importing miTLS's assumed minimum bound.
pub(super) fn hkdf_label(label: &Bytes, context: &Bytes, len: usize) -> Result<Bytes, TLSError> {
    if len > 65535 || label.len() == 0 || label.len() > 249 || context.len() > 255 {
        return Err(PAYLOAD_TOO_LONG);
    }
    let length = Bytes::from_slice(&[(len >> 8) as u8, len as u8]);
    let prefixed = Bytes::from_slice(b"tls13 ").concat(label.clone());
    Ok(length
        .concat(Bytes::from_slice(&[prefixed.len() as u8]))
        .concat(prefixed)
        .concat(Bytes::from_slice(&[context.len() as u8]))
        .concat(context.clone()))
}

/// RFC 8446:5053–5054; miTLS src/tls/MiTLS.HKDF.fst:230–232.
pub(super) fn expand_label(
    ha: &HashAlgorithm,
    secret: &Key,
    label: &Bytes,
    context: &Bytes,
    len: usize,
) -> Result<Key, TLSError> {
    hkdf_expand(ha, secret, &hkdf_label(label, context, len)?, len)
}

/// RFC 8446:5064–5074; miTLS src/tls/MiTLS.HKDF.fst:241.
/// Like miTLS, this entry takes an already computed transcript hash. Callers
/// must select CH..SH, CH..server Finished, or CH..client Finished respectively.
pub(super) fn derive_secret_hash(
    ha: &HashAlgorithm,
    secret: &Key,
    label: &Bytes,
    transcript_hash: &Digest,
) -> Result<Key, TLSError> {
    expand_label(ha, secret, label, transcript_hash, ha.hash_len())
}

/// RFC 8446:5064–5074: Messages includes handshake headers, excludes record headers.
pub(super) fn derive_secret(
    ha: &HashAlgorithm,
    secret: &Key,
    label: &Bytes,
    messages: &Bytes,
) -> Result<Key, TLSError> {
    derive_secret_hash(ha, secret, label, &hash(ha, messages)?)
}

/// RFC 8446:5130,5150–5154,5220–5224; miTLS Old.KeySchedule.fst:155.
/// bertie's hkdf_extract takes IKM before salt (opposite RFC notation).
pub(super) fn early_secret(ha: &HashAlgorithm) -> Result<Key, TLSError> {
    let zero = Bytes::zeroes(ha.hash_len());
    hkdf_extract(ha, &zero, &zero)
}

/// RFC 8446:5165,5181; miTLS Old.KeySchedule.fst:160,265.
pub(super) fn derived(ha: &HashAlgorithm, secret: &Key) -> Result<Key, TLSError> {
    derive_secret(ha, secret, &Bytes::from_slice(b"derived"), &Bytes::new())
}

/// RFC 8446:5165–5169; miTLS Old.KeySchedule.fst:160,168,172 (DHE branch).
pub(super) fn handshake_secret(ha: &HashAlgorithm, dhe: &Key) -> Result<Key, TLSError> {
    hkdf_extract(ha, dhe, &derived(ha, &early_secret(ha)?)?)
}

/// RFC 8446:5181–5185; miTLS Old.KeySchedule.fst:265–270.
pub(super) fn master_secret(ha: &HashAlgorithm, handshake: &Key) -> Result<Key, TLSError> {
    hkdf_extract(ha, &Bytes::zeroes(ha.hash_len()), &derived(ha, handshake)?)
}

/// RFC 8446:5171–5177; miTLS Old.KeySchedule.fst:234,236.
pub(super) fn handshake_traffic(
    ha: &HashAlgorithm,
    handshake: &Key,
    through_server_hello: &Digest,
) -> Result<(Key, Key), TLSError> {
    Ok((
        derive_secret_hash(
            ha,
            handshake,
            &Bytes::from_slice(b"c hs traffic"),
            through_server_hello,
        )?,
        derive_secret_hash(
            ha,
            handshake,
            &Bytes::from_slice(b"s hs traffic"),
            through_server_hello,
        )?,
    ))
}

/// RFC 8446:5187–5197; miTLS Old.KeySchedule.fst:458,460,463.
/// Correct the both-client ghost identities at :455–456 by using separate values.
pub(super) fn application_traffic(
    ha: &HashAlgorithm,
    master: &Key,
    through_server_finished: &Digest,
) -> Result<(Key, Key, Key), TLSError> {
    Ok((
        derive_secret_hash(
            ha,
            master,
            &Bytes::from_slice(b"c ap traffic"),
            through_server_finished,
        )?,
        derive_secret_hash(
            ha,
            master,
            &Bytes::from_slice(b"s ap traffic"),
            through_server_finished,
        )?,
        derive_secret_hash(
            ha,
            master,
            &Bytes::from_slice(b"exp master"),
            through_server_finished,
        )?,
    ))
}

/// RFC 8446:5199–5201; miTLS Old.KeySchedule.fst:549,573.
pub(super) fn resumption_master(
    ha: &HashAlgorithm,
    master: &Key,
    through_client_finished: &Digest,
) -> Result<Key, TLSError> {
    derive_secret_hash(
        ha,
        master,
        &Bytes::from_slice(b"res master"),
        through_client_finished,
    )
}

/// RFC 8446:3987–3989 (§4.4.4); miTLS Old.KeySchedule.fsti:267–268.
pub(super) fn finished_key(ha: &HashAlgorithm, traffic: &Key) -> Result<Key, TLSError> {
    expand_label(
        ha,
        traffic,
        &Bytes::from_slice(b"finished"),
        &Bytes::new(),
        ha.hash_len(),
    )
}

/// RFC 8446:5285–5286 (§7.3); miTLS Old.KeySchedule.fsti:255–261, TLS branch only.
pub(super) fn write_key_iv(
    ha: &HashAlgorithm,
    traffic: &Key,
    key_len: usize,
    iv_len: usize,
) -> Result<(Key, Bytes), TLSError> {
    Ok((
        expand_label(
            ha,
            traffic,
            &Bytes::from_slice(b"key"),
            &Bytes::new(),
            key_len,
        )?,
        expand_label(
            ha,
            traffic,
            &Bytes::from_slice(b"iv"),
            &Bytes::new(),
            iv_len,
        )?,
    ))
}
