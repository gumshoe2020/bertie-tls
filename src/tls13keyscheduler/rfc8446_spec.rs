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

pub(super) const LABEL_DERIVED: &[u8; 7] = b"derived";
pub(super) const LABEL_CHT: &[u8; 12] = b"c hs traffic";
pub(super) const LABEL_SHT: &[u8; 12] = b"s hs traffic";
pub(super) const LABEL_CAT: &[u8; 12] = b"c ap traffic";
pub(super) const LABEL_SAT: &[u8; 12] = b"s ap traffic";
pub(super) const LABEL_EAM: &[u8; 10] = b"exp master";
pub(super) const LABEL_RM: &[u8; 10] = b"res master";
#[cfg(hax)]
pub(super) const LABEL_CET: &[u8; 11] = b"c e traffic";
#[cfg(hax)]
pub(super) const LABEL_EEM: &[u8; 12] = b"e exp master";

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
    derive_secret(ha, secret, &Bytes::from_slice(LABEL_DERIVED), &Bytes::new())
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
            &Bytes::from_slice(LABEL_CHT),
            through_server_hello,
        )?,
        derive_secret_hash(
            ha,
            handshake,
            &Bytes::from_slice(LABEL_SHT),
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
            &Bytes::from_slice(LABEL_CAT),
            through_server_finished,
        )?,
        derive_secret_hash(
            ha,
            master,
            &Bytes::from_slice(LABEL_SAT),
            through_server_finished,
        )?,
        derive_secret_hash(
            ha,
            master,
            &Bytes::from_slice(LABEL_EAM),
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
        &Bytes::from_slice(LABEL_RM),
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
#[cfg_attr(hax, hax_lib::fstar::after(r#"
// Proof support (F* only, nothing executable): the composition of §7.1 that
// derive_hk_handles computes, and the same composition in its step order.
let rbind (r:Core_models.Result.t_Result 'a u8) (f:'a -> Core_models.Result.t_Result 'b u8) : Core_models.Result.t_Result 'b u8 =
  match r with | Core_models.Result.Result_Ok v -> f v | Core_models.Result.Result_Err e -> Core_models.Result.Result_Err e

let hk_expected (ha:Bertie_tls.Tls13crypto.Algorithm_types.t_HashAlgorithm) (dhe th:Bertie_tls.Tls13utils.Byte_types.t_Bytes) =
  rbind (handshake_secret ha dhe) (fun hs ->
  rbind (handshake_traffic ha hs th) (fun cs ->
  rbind (master_secret ha hs) (fun ms -> Core_models.Result.Result_Ok (cs._1, cs._2, ms))))

let hk_steps (ha:Bertie_tls.Tls13crypto.Algorithm_types.t_HashAlgorithm) (dhe th:Bertie_tls.Tls13utils.Byte_types.t_Bytes) =
  let zeros = Bertie_tls.Tls13utils.impl_17__zeroes (Bertie_tls.Tls13crypto.impl_4__hash_len ha) in
  let derived_label = Bertie_tls.Tls13utils.impl_17__from_slice v_LABEL_DERIVED in
  rbind (Bertie_tls.Tls13crypto.hkdf_extract ha zeros zeros) (fun es ->
  rbind (Bertie_tls.Tls13crypto.hash ha (Bertie_tls.Tls13utils.impl_17__new ())) (fun d ->
  rbind (derive_secret_hash ha es derived_label d) (fun salt ->
  rbind (Bertie_tls.Tls13crypto.hkdf_extract ha dhe salt) (fun hs ->
  rbind (derive_secret_hash ha hs (Bertie_tls.Tls13utils.impl_17__from_slice v_LABEL_CHT) th) (fun c ->
  rbind (derive_secret_hash ha hs (Bertie_tls.Tls13utils.impl_17__from_slice v_LABEL_SHT) th) (fun s ->
  rbind (derive_secret_hash ha hs derived_label d) (fun salt2 ->
  rbind (Bertie_tls.Tls13crypto.hkdf_extract ha zeros salt2) (fun ms ->
  Core_models.Result.Result_Ok (c, s, ms)))))))))

#push-options "--z3rlimit 100"
let hk_steps_is_rfc (ha:Bertie_tls.Tls13crypto.Algorithm_types.t_HashAlgorithm) (dhe th:Bertie_tls.Tls13utils.Byte_types.t_Bytes) :
  Lemma (hk_expected ha dhe th == hk_steps ha dhe th) [SMTPat (hk_expected ha dhe th)] =
  let zeros = Bertie_tls.Tls13utils.impl_17__zeroes (Bertie_tls.Tls13crypto.impl_4__hash_len ha) in
  let derived_label = Bertie_tls.Tls13utils.impl_17__from_slice v_LABEL_DERIVED in
  assert (early_secret ha == Bertie_tls.Tls13crypto.hkdf_extract ha zeros zeros);
  assert (forall sec. derived ha sec == derive_secret ha sec derived_label (Bertie_tls.Tls13utils.impl_17__new ()));
  match Bertie_tls.Tls13crypto.hkdf_extract ha zeros zeros with
  | Core_models.Result.Result_Err e -> assert (handshake_secret ha dhe == Core_models.Result.Result_Err e)
  | Core_models.Result.Result_Ok es ->
  match Bertie_tls.Tls13crypto.hash ha (Bertie_tls.Tls13utils.impl_17__new ()) with
  | Core_models.Result.Result_Err e ->
    assert (derived ha es == Core_models.Result.Result_Err e);
    assert (handshake_secret ha dhe == Core_models.Result.Result_Err e)
  | Core_models.Result.Result_Ok d ->
  assert (forall sec. derived ha sec == derive_secret_hash ha sec derived_label d);
  match derive_secret_hash ha es derived_label d with
  | Core_models.Result.Result_Err e -> assert (handshake_secret ha dhe == Core_models.Result.Result_Err e)
  | Core_models.Result.Result_Ok salt ->
  assert (handshake_secret ha dhe == Bertie_tls.Tls13crypto.hkdf_extract ha dhe salt);
  match Bertie_tls.Tls13crypto.hkdf_extract ha dhe salt with
  | Core_models.Result.Result_Err e -> ()
  | Core_models.Result.Result_Ok hs ->
  match derive_secret_hash ha hs (Bertie_tls.Tls13utils.impl_17__from_slice v_LABEL_CHT) th with
  | Core_models.Result.Result_Err e -> assert (handshake_traffic ha hs th == Core_models.Result.Result_Err e)
  | Core_models.Result.Result_Ok c ->
  match derive_secret_hash ha hs (Bertie_tls.Tls13utils.impl_17__from_slice v_LABEL_SHT) th with
  | Core_models.Result.Result_Err e -> assert (handshake_traffic ha hs th == Core_models.Result.Result_Err e)
  | Core_models.Result.Result_Ok s ->
    assert (handshake_traffic ha hs th == Core_models.Result.Result_Ok (c, s));
    assert (derived ha hs == derive_secret ha hs derived_label (Bertie_tls.Tls13utils.impl_17__new ()));
    assert (derive_secret ha hs derived_label (Bertie_tls.Tls13utils.impl_17__new ()) == derive_secret_hash ha hs derived_label d);
    match derive_secret_hash ha hs derived_label d with
    | Core_models.Result.Result_Err e -> assert (master_secret ha hs == Core_models.Result.Result_Err e)
    | Core_models.Result.Result_Ok salt2 -> assert (master_secret ha hs == Bertie_tls.Tls13crypto.hkdf_extract ha zeros salt2)
#pop-options
"#))]
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
