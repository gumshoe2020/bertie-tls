pub(crate) mod key_names;
pub(crate) mod key_schedule;
// Used outside hax only by the sha256-gated RFC 8448 test; ungated, single-feature builds warn dead_code.
#[cfg(any(all(test, feature = "sha256"), hax))]
mod rfc8446_spec;
// RFC 8448 §3 uses SHA-256; HKDF over it needs the sha256 feature.
#[cfg(all(test, feature = "sha256"))]
mod test_rfc8448_vectors;

use crate::{
    tls13crypto::{hash, AeadAlgorithm, AeadKey, AeadKeyIV, Digest, HashAlgorithm, MacKey},
    tls13formats::*,
    tls13utils::*,
};
use key_schedule::{TLSnames::*, *};

/// Get the hash of an empty byte slice.
#[cfg_attr(feature = "hax-pv", hax_lib::pv_constructor)]
#[cfg_attr(hax, hax_lib::fstar::before(interface, r#"
module Store = Bertie_tls.Tls13keyscheduler.Key_schedule
module Spec = Bertie_tls.Tls13keyscheduler.Rfc8446_spec
module Names = Bertie_tls.Tls13keyscheduler.Key_names
module Crypto = Bertie_tls.Tls13crypto
module Bytes = Bertie_tls.Tls13utils
module Res = Core_models.Result
module Opt = Core_models.Option

let bind (r:Res.t_Result 'a u8) (f:'a -> Res.t_Result 'b u8) =
  match r with | Res.Result_Ok v -> f v | Res.Result_Err e -> Res.Result_Err e

let handle n a l : Store.t_Handle = { Store.f_name=n; Store.f_alg=a; Store.f_level=l }

let three_stored s result h1 h2 h3 (expected:Res.t_Result _ u8) : Type0 =
  match expected with
  | Res.Result_Ok (v1,v2,v3) ->
    result == Res.Result_Ok (h1,h2,h3) /\
    Store.at_handle s h1 == Opt.Option_Some v1 /\
    Store.at_handle s h2 == Opt.Option_Some v2 /\
    Store.at_handle s h3 == Opt.Option_Some v3
  | Res.Result_Err e -> result == Res.Result_Err e

// RFC 8446 §7.1 labels of the early traffic secrets (the specification's bytes).
let label_cet : Bertie_tls.Tls13utils.Byte_types.t_Bytes = Bytes.impl_17__from_slice Spec.v_LABEL_CET
let label_eem : Bertie_tls.Tls13utils.Byte_types.t_Bytes = Bytes.impl_17__from_slice Spec.v_LABEL_EEM

let label_derived : Bertie_tls.Tls13utils.Byte_types.t_Bytes = Bytes.impl_17__from_slice Spec.v_LABEL_DERIVED
let label_cht : Bertie_tls.Tls13utils.Byte_types.t_Bytes = Bytes.impl_17__from_slice Spec.v_LABEL_CHT
let label_sht : Bertie_tls.Tls13utils.Byte_types.t_Bytes = Bytes.impl_17__from_slice Spec.v_LABEL_SHT

// Slots whose name is not one of the given names read the same in new_s as in old_s.
let kept3 old_s new_s (n1 n2 n3:Names.t_TLSnames) : Type0 =
  forall (q:Store.slot). q._1 =!= n1 /\ q._1 =!= n2 /\ q._1 =!= n3 ==>
    Store.impl_TLSkeyscheduler__lookup new_s q == Store.impl_TLSkeyscheduler__lookup old_s q

// XPD derives the handshake secrets with the specification's labels.
let handshake_labels () : Lemma
  (Store.rfc_label Names.TLSnames_CHT == Some label_cht /\
   Store.rfc_label Names.TLSnames_SHT == Some label_sht /\
   Store.rfc_label Names.TLSnames_HSalt == Some label_derived /\
   Store.rfc_label Names.TLSnames_ESalt == Some label_derived) =
  assert_norm (Store.rfc_label Names.TLSnames_CHT == Some label_cht);
  assert_norm (Store.rfc_label Names.TLSnames_SHT == Some label_sht);
  assert_norm (Store.rfc_label Names.TLSnames_HSalt == Some label_derived);
  assert_norm (Store.rfc_label Names.TLSnames_ESalt == Some label_derived)

let label_cat : Bertie_tls.Tls13utils.Byte_types.t_Bytes = Bytes.impl_17__from_slice Spec.v_LABEL_CAT
let label_sat : Bertie_tls.Tls13utils.Byte_types.t_Bytes = Bytes.impl_17__from_slice Spec.v_LABEL_SAT
let label_eam : Bertie_tls.Tls13utils.Byte_types.t_Bytes = Bytes.impl_17__from_slice Spec.v_LABEL_EAM
let label_rm : Bertie_tls.Tls13utils.Byte_types.t_Bytes = Bytes.impl_17__from_slice Spec.v_LABEL_RM

// XPD derives the application secrets and the resumption master secret with
// the specification's labels, and the specification computes them with these.
let app_labels (ha:Bertie_tls.Tls13crypto.Algorithm_types.t_HashAlgorithm) (ms th:Bertie_tls.Tls13utils.Byte_types.t_Bytes) : Lemma
  (Store.rfc_label Names.TLSnames_CAT == Some label_cat /\
   Store.rfc_label Names.TLSnames_SAT == Some label_sat /\
   Store.rfc_label Names.TLSnames_EAM == Some label_eam /\
   Store.rfc_label Names.TLSnames_RM == Some label_rm /\
   Spec.resumption_master ha ms th == Spec.derive_secret_hash ha ms label_rm th /\
   Spec.application_traffic ha ms th ==
     bind (Spec.derive_secret_hash ha ms label_cat th) (fun c ->
     bind (Spec.derive_secret_hash ha ms label_sat th) (fun s ->
     bind (Spec.derive_secret_hash ha ms label_eam th) (fun e -> Res.Result_Ok (c, s, e))))) =
  assert_norm (Store.rfc_label Names.TLSnames_CAT == Some label_cat);
  assert_norm (Store.rfc_label Names.TLSnames_SAT == Some label_sat);
  assert_norm (Store.rfc_label Names.TLSnames_EAM == Some label_eam);
  assert_norm (Store.rfc_label Names.TLSnames_RM == Some label_rm)

// XPD derives CET and EEM with exactly these labels.
let early_labels () : Lemma
  (Store.rfc_label Names.TLSnames_CET == Some label_cet /\
   Store.rfc_label Names.TLSnames_EEM == Some label_eem) =
  assert_norm (Store.rfc_label Names.TLSnames_CET == Some label_cet);
  assert_norm (Store.rfc_label Names.TLSnames_EEM == Some label_eem)

// The input of next_keys_c_2 is a PSK handle of the given hash.
let psk_handle_of ha (handle:Store.t_Handle) : Type0 =
  handle.Store.f_name == Names.TLSnames_PSK /\ handle.Store.f_alg == ha

// RFC 8446 §7.1 Early Secret from the PSK ikm (Hash.length zero salt).
let early_from ha ikm =
  Crypto.hkdf_extract ha ikm (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha))

let rfc_write ha ae key =
  match Spec.write_key_iv ha key (Crypto.impl_2__key_len ae) (Crypto.impl_2__iv_len ae) with
  | Res.Result_Ok (k, iv) -> Res.Result_Ok (Crypto.impl_AeadKeyIV__new (Crypto.impl_AeadKey__new k ae) iv)
  | Res.Result_Err e -> Res.Result_Err e
"#))]
#[hax_lib::ensures(|result| fstar!(r#"result == Crypto.hash algorithm (Bytes.impl_17__new ())"#))]
fn hash_empty(algorithm: &HashAlgorithm) -> Result<Digest, TLSError> {
    hash(algorithm, &Bytes::new())
}

#[cfg_attr(feature = "hax-pv", hax_lib::pv_constructor)]
pub fn derive_binder_key(
    ha: &HashAlgorithm,
    handle: &Handle,
    ks: &mut TLSkeyscheduler,
) -> Result<Handle, TLSError> {
    let zero_salt_handle = zero_salt(ks, ha);
    let early_secret = XTR(ks, 0, ES, handle, &zero_salt_handle)?;
    XPD(ks, Bind, 0, &early_secret, true, &hash_empty(ha)?) // res or ext? or is a bit needed to determine this?
}

/// Derive an AEAD key and iv.
#[allow(clippy::assign_op_pattern)]
#[cfg_attr(
    feature = "hax-pv",
    hax_lib::proverif::before(
        "fun extern__derive_aead_key_iv(
    $:{HashAlgorithm},
    $:{AeadAlgorithm},
    $:{Handle},
    $:{TLSkeyscheduler}
         )
     : $:{AeadKeyIV}."
    )
)]
#[cfg_attr(
    feature = "hax-pv",
    hax_lib::proverif::replace_body(
        "(extern__derive_aead_key_iv(
            hash_algorithm,
            aead_algorithm,
            handle,
            ks
          )
       )"
    )
)]
/// Proved (P2 M2): the RFC 8446 §7.3 specification's `write_key_iv` of the
/// secret stored under `handle`, wrapped as an [`AeadKeyIV`].
#[hax_lib::ensures(|result| fstar!(r#"ks_future == ks /\ (match Bertie_tls.Tls13keyscheduler.Key_schedule.tagkey_from_handle ks handle with
  | Core_models.Result.Result_Ok k ->
    result ==
    (match Bertie_tls.Tls13keyscheduler.Rfc8446_spec.write_key_iv hash_algorithm
        k.Bertie_tls.Tls13keyscheduler.Key_schedule.f_val
        (Bertie_tls.Tls13crypto.impl_2__key_len aead_algorithm)
        (Bertie_tls.Tls13crypto.impl_2__iv_len aead_algorithm) with
     | Core_models.Result.Result_Ok (key, iv) ->
       Core_models.Result.Result_Ok
         (Bertie_tls.Tls13crypto.impl_AeadKeyIV__new
           (Bertie_tls.Tls13crypto.impl_AeadKey__new key aead_algorithm) iv)
     | Core_models.Result.Result_Err e -> Core_models.Result.Result_Err e)
  | Core_models.Result.Result_Err e -> result == Core_models.Result.Result_Err e)"#))]
#[hax_lib::fstar::options("--z3rlimit 100 --split_queries always")]
pub(crate) fn derive_aead_key_iv(
    hash_algorithm: &HashAlgorithm,
    aead_algorithm: &AeadAlgorithm,
    handle: &Handle,
    ks: &mut TLSkeyscheduler,
) -> Result<AeadKeyIV, TLSError> {
    let key = tagkey_from_handle(ks, handle)?.val;
    let sender_write_key = hkdf_expand_label(
        hash_algorithm,
        &key,
        bytes(&LABEL_KEY),
        &Bytes::new(),
        aead_algorithm.key_len(),
    )?;
    let sender_write_iv = hkdf_expand_label(
        hash_algorithm,
        &key,
        bytes(&LABEL_IV),
        &Bytes::new(),
        aead_algorithm.iv_len(),
    )?;
    Ok(AeadKeyIV::new(
        AeadKey::new(sender_write_key, *aead_algorithm),
        sender_write_iv,
    ))
}

#[hax_lib::ensures(|result| fstar!(r#"let open Names in
  handle.Store.f_name == TLSnames_PSK /\ handle.Store.f_alg == hash_algorithm ==>
  (match Store.at_handle ks handle with
   | Opt.Option_Some ikm ->
     let ha = hash_algorithm in
     three_stored ks_future result {handle with Store.f_name=TLSnames_EEM}
       {handle with Store.f_name=TLSnames_CET} {handle with Store.f_name=TLSnames_ESalt}
       (bind (Crypto.hkdf_extract ha ikm (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha))) (fun es ->
        bind (Spec.derived ha es) (fun derived ->
        bind (Spec.derive_secret_hash ha es label_cet tx) (fun cet ->
        bind (Spec.derive_secret_hash ha es label_eem tx) (fun eem ->
        Res.Result_Ok (eem,cet,derived))))))
   | _ -> True)"#))]
#[hax_lib::fstar::options("--z3rlimit 400 --split_queries always")]
pub(crate) fn next_keys_c_2(
    hash_algorithm: &HashAlgorithm,
    handle: &Handle,
    tx: &Digest,
    ks: &mut TLSkeyscheduler,
) -> Result<(Handle, Handle, Handle), TLSError> {
    #[cfg(hax)]
    hax_lib::fstar!("early_labels ()");
    // Proof only: the PSK as stored on entry.
    #[cfg(hax)]
    let ikm_in = get_by_handle(ks, handle);
    let zero_salt_handle = zero_salt(ks, hash_algorithm);
    let early_secret = XTR(ks, 0, ES, handle, &zero_salt_handle)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (psk_handle_of hash_algorithm handle ==>
  (match ikm_in with
   | Res.Result_Ok ikm ->
     (match early_from hash_algorithm ikm with
      | Res.Result_Ok es ->
        early_secret == {handle with Store.f_name = Names.TLSnames_ES} /\
        Store.at_handle ks early_secret == Opt.Option_Some es
      | _ -> False)
   | _ -> True))"#
    );
    let digest_emp = hash_empty(hash_algorithm)?;
    let derived_secret = XPD(ks, ESalt, 0, &early_secret, true, &digest_emp)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (psk_handle_of hash_algorithm handle ==>
  (match ikm_in with
   | Res.Result_Ok ikm ->
     (match early_from hash_algorithm ikm with
      | Res.Result_Ok es ->
        derived_secret == {handle with Store.f_name = Names.TLSnames_ESalt} /\
        Store.at_handle ks early_secret == Opt.Option_Some es /\
        (match Spec.derived hash_algorithm es with
         | Res.Result_Ok d -> Store.at_handle ks derived_secret == Opt.Option_Some d
         | _ -> False)
      | _ -> False)
   | _ -> True))"#
    );
    let client_early_traffic_secret = XPD(ks, CET, 0, &early_secret, true, tx)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (psk_handle_of hash_algorithm handle ==>
  (match ikm_in with
   | Res.Result_Ok ikm ->
     (match early_from hash_algorithm ikm with
      | Res.Result_Ok es ->
        client_early_traffic_secret == {handle with Store.f_name = Names.TLSnames_CET} /\
        Store.at_handle ks early_secret == Opt.Option_Some es /\
        (match Spec.derived hash_algorithm es with
         | Res.Result_Ok d -> Store.at_handle ks derived_secret == Opt.Option_Some d
         | _ -> False) /\
        (match Spec.derive_secret_hash hash_algorithm es label_cet tx with
         | Res.Result_Ok c -> Store.at_handle ks client_early_traffic_secret == Opt.Option_Some c
         | _ -> False)
      | _ -> False)
   | _ -> True))"#
    );
    let early_exporter_master_secret = XPD(ks, EEM, 0, &early_secret, true, tx)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (psk_handle_of hash_algorithm handle ==>
  (match ikm_in with
   | Res.Result_Ok ikm ->
     (match early_from hash_algorithm ikm with
      | Res.Result_Ok es ->
        early_exporter_master_secret == {handle with Store.f_name = Names.TLSnames_EEM} /\
        (match Spec.derived hash_algorithm es with
         | Res.Result_Ok d -> Store.at_handle ks derived_secret == Opt.Option_Some d
         | _ -> False) /\
        (match Spec.derive_secret_hash hash_algorithm es label_cet tx with
         | Res.Result_Ok c -> Store.at_handle ks client_early_traffic_secret == Opt.Option_Some c
         | _ -> False) /\
        (match Spec.derive_secret_hash hash_algorithm es label_eem tx with
         | Res.Result_Ok e -> Store.at_handle ks early_exporter_master_secret == Opt.Option_Some e
         | _ -> False)
      | _ -> False)
   | _ -> True))"#
    );

    Ok((
        early_exporter_master_secret,
        client_early_traffic_secret,
        derived_secret,
    ))
}

/// Derive 0-RTT AEAD keys.
#[cfg_attr(feature = "hax-pv", hax_lib::pv_constructor)]
pub(crate) fn derive_0rtt_keys(
    hash_algorithm: &HashAlgorithm,
    aead_algorithm: &AeadAlgorithm,
    handle: &Handle,
    tx: &Digest,
    ks: &mut TLSkeyscheduler,
) -> Result<(AeadKeyIV, Handle), TLSError> {
    let (early_exporter_master_secret, client_early_traffic_secret, derived_secret) =
        next_keys_c_2(hash_algorithm, handle, tx, ks)?;
    let sender_write_key_iv = derive_aead_key_iv(
        hash_algorithm,
        aead_algorithm,
        &client_early_traffic_secret,
        ks,
    )?;
    Ok((sender_write_key_iv, early_exporter_master_secret))
}

#[cfg_attr(
    feature = "hax-pv",
    hax_lib::proverif::before(
        "fun extern__derive_finished_key(
                $:{HashAlgorithm},
                $:{Handle},
                $:{TLSkeyscheduler}
         )
     : $:{MacKey}."
    )
)]
#[cfg_attr(
    feature = "hax-pv",
    hax_lib::proverif::replace_body(
        "(extern__derive_finished_key(
              ha,
              handle,
              ks
          )
       )"
    )
)]
/// Proved (P2 M2): the RFC 8446 §4.4.4 specification's `finished_key` of the
/// secret stored under `handle`.
#[hax_lib::ensures(|result| fstar!(r#"ks_future == ks /\ (match Bertie_tls.Tls13keyscheduler.Key_schedule.tagkey_from_handle ks handle with
  | Core_models.Result.Result_Ok k ->
    result == Bertie_tls.Tls13keyscheduler.Rfc8446_spec.finished_key ha
      k.Bertie_tls.Tls13keyscheduler.Key_schedule.f_val
  | Core_models.Result.Result_Err e -> result == Core_models.Result.Result_Err e)"#))]
pub fn derive_finished_key(
    ha: &HashAlgorithm,
    handle: &Handle,
    ks: &mut TLSkeyscheduler,
) -> Result<MacKey, TLSError> {
    let k = tagkey_from_handle(ks, handle)?;
    hkdf_expand_label(
        ha,
        &k.val,
        bytes(&LABEL_FINISHED),
        &Bytes::new(),
        ha.hmac_tag_len(),
    )
}

/// RFC 8446 §7.1: Early Secret from the PSK under `psk` (Hash.length zero salt)
/// and the salt Derive-Secret(., "derived", "") for the Handshake Secret.
#[hax_lib::fstar::options("--z3rlimit 200 --split_queries always")]
#[hax_lib::ensures(|result| fstar!(r#"psk.Store.f_name == Names.TLSnames_PSK /\ psk.Store.f_alg == ha ==>
  (match Store.at_handle ks psk with
   | Opt.Option_Some ikm ->
     (match Crypto.hkdf_extract ha ikm (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha)) with
      | Res.Result_Ok es ->
        (match Crypto.hash ha (Bytes.impl_17__new ()) with
         | Res.Result_Ok d ->
           (match Spec.derive_secret_hash ha es label_derived d with
            | Res.Result_Ok salt ->
              result == Res.Result_Ok ({psk with Store.f_name = Names.TLSnames_ES},
                {psk with Store.f_name = Names.TLSnames_ESalt}, d) /\
              Store.at_handle ks_future {psk with Store.f_name = Names.TLSnames_ES} == Opt.Option_Some es /\
              Store.at_handle ks_future {psk with Store.f_name = Names.TLSnames_ESalt} == Opt.Option_Some salt /\
              kept3 ks ks_future Names.TLSnames_ZeroSalt Names.TLSnames_ES Names.TLSnames_ESalt
            | Res.Result_Err e -> result == Res.Result_Err e)
         | Res.Result_Err e -> result == Res.Result_Err e)
      | Res.Result_Err e -> result == Res.Result_Err e)
   | _ -> True)"#))]
fn derive_early_salt(
    ha: &HashAlgorithm,
    psk: &Handle,
    ks: &mut TLSkeyscheduler,
) -> Result<(Handle, Handle, Digest), TLSError> {
    #[cfg(hax)]
    hax_lib::fstar!("handshake_labels ()");
    let zero_salt_handle = zero_salt(ks, ha);
    let early_secret = XTR(ks, 0, ES, psk, &zero_salt_handle)?;
    let digest_emp = hash_empty(ha)?;
    let derived_secret = XPD(ks, ESalt, 0, &early_secret, true, &digest_emp)?;
    Ok((early_secret, derived_secret, digest_emp))
}

/// RFC 8446 §7.1: Handshake Secret from the (EC)DHE secret under `shared_secret`
/// and the salt under `salt`, the two handshake traffic secrets, and the salt
/// Derive-Secret(., "derived", "") for the Master Secret (`digest_emp` is the
/// hash of the empty string).
#[hax_lib::fstar::options("--z3rlimit 400 --split_queries always")]
#[hax_lib::ensures(|result| fstar!(r#"shared_secret.Store.f_name == Names.TLSnames_KEM /\ shared_secret.Store.f_alg == ha /\
  salt.Store.f_name == Names.TLSnames_ESalt ==>
  (match Store.at_handle ks shared_secret with
   | Opt.Option_Some dhe ->
     (match Store.at_handle ks salt with
      | Opt.Option_Some sv ->
        (match Crypto.hkdf_extract ha dhe sv with
         | Res.Result_Ok hs ->
           (match Spec.derive_secret_hash ha hs label_cht transcript_hash with
            | Res.Result_Ok c ->
              (match Spec.derive_secret_hash ha hs label_sht transcript_hash with
               | Res.Result_Ok s ->
                 (match Spec.derive_secret_hash ha hs label_derived digest_emp with
                  | Res.Result_Ok salt2 ->
                    result == Res.Result_Ok ({shared_secret with Store.f_name = Names.TLSnames_CHT},
                      {shared_secret with Store.f_name = Names.TLSnames_SHT},
                      {shared_secret with Store.f_name = Names.TLSnames_HSalt}) /\
                    Store.at_handle ks_future {shared_secret with Store.f_name = Names.TLSnames_CHT} == Opt.Option_Some c /\
                    Store.at_handle ks_future {shared_secret with Store.f_name = Names.TLSnames_SHT} == Opt.Option_Some s /\
                    Store.at_handle ks_future {shared_secret with Store.f_name = Names.TLSnames_HSalt} == Opt.Option_Some salt2
                  | Res.Result_Err e -> result == Res.Result_Err e)
               | Res.Result_Err e -> result == Res.Result_Err e)
            | Res.Result_Err e -> result == Res.Result_Err e)
         | Res.Result_Err e -> result == Res.Result_Err e)
      | _ -> True)
   | _ -> True)"#))]
fn derive_handshake_secrets(
    ha: &HashAlgorithm,
    shared_secret: &Handle,
    salt: &Handle,
    digest_emp: &Digest,
    transcript_hash: &Digest,
    ks: &mut TLSkeyscheduler,
) -> Result<(Handle, Handle, Handle), TLSError> {
    #[cfg(hax)]
    hax_lib::fstar!("handshake_labels ()");
    // Proof only: the inputs as stored on entry.
    #[cfg(hax)]
    let dhe_in = get_by_handle(ks, shared_secret);
    #[cfg(hax)]
    let sv_in = get_by_handle(ks, salt);
    let handshake_secret = XTR(ks, 0, HS, shared_secret, salt)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (shared_secret.Store.f_name == Names.TLSnames_KEM /\ shared_secret.Store.f_alg == ha /\
  salt.Store.f_name == Names.TLSnames_ESalt ==>
  (match dhe_in with
   | Res.Result_Ok dhe ->
   (match sv_in with
   | Res.Result_Ok sv ->
(match Crypto.hkdf_extract ha dhe sv with
 | Res.Result_Ok hs ->
handshake_secret == {shared_secret with Store.f_name = Names.TLSnames_HS} /\
Store.at_handle ks handshake_secret == Opt.Option_Some hs
 | _ -> False)
   | _ -> True)
   | _ -> True))"#
    );
    let client_handshake_traffic_secret =
        XPD(ks, CHT, 0, &handshake_secret, true, transcript_hash)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (shared_secret.Store.f_name == Names.TLSnames_KEM /\ shared_secret.Store.f_alg == ha /\
  salt.Store.f_name == Names.TLSnames_ESalt ==>
  (match dhe_in with
   | Res.Result_Ok dhe ->
   (match sv_in with
   | Res.Result_Ok sv ->
(match Crypto.hkdf_extract ha dhe sv with
 | Res.Result_Ok hs ->
(match Spec.derive_secret_hash ha hs label_cht transcript_hash with
 | Res.Result_Ok c ->
Store.at_handle ks handshake_secret == Opt.Option_Some hs /\
Store.at_handle ks client_handshake_traffic_secret == Opt.Option_Some c
 | _ -> False)
 | _ -> False)
   | _ -> True)
   | _ -> True))"#
    );
    let server_handshake_traffic_secret =
        XPD(ks, SHT, 0, &handshake_secret, true, transcript_hash)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (shared_secret.Store.f_name == Names.TLSnames_KEM /\ shared_secret.Store.f_alg == ha /\
  salt.Store.f_name == Names.TLSnames_ESalt ==>
  (match dhe_in with
   | Res.Result_Ok dhe ->
   (match sv_in with
   | Res.Result_Ok sv ->
(match Crypto.hkdf_extract ha dhe sv with
 | Res.Result_Ok hs ->
(match Spec.derive_secret_hash ha hs label_cht transcript_hash with
 | Res.Result_Ok c ->
(match Spec.derive_secret_hash ha hs label_sht transcript_hash with
 | Res.Result_Ok s ->
Store.at_handle ks handshake_secret == Opt.Option_Some hs /\
Store.at_handle ks client_handshake_traffic_secret == Opt.Option_Some c /\
Store.at_handle ks server_handshake_traffic_secret == Opt.Option_Some s
 | _ -> False)
 | _ -> False)
 | _ -> False)
   | _ -> True)
   | _ -> True))"#
    );
    let master_secret_ = XPD(ks, HSalt, 0, &handshake_secret, true, digest_emp)?;
    Ok((
        client_handshake_traffic_secret,
        server_handshake_traffic_secret,
        master_secret_,
    ))
}

/// Derive the handshake keys and master secret.
#[hax_lib::ensures(|result| fstar!(r#"let open Names in
  psko == Opt.Option_None /\ shared_secret == handle TLSnames_KEM ha (mk_u8 0) ==>
  (match Store.at_handle ks shared_secret with
   | Opt.Option_Some dhe ->
     three_stored ks_future result (handle TLSnames_CHT ha (mk_u8 0))
       (handle TLSnames_SHT ha (mk_u8 0)) (handle TLSnames_AS ha (mk_u8 0))
       (Spec.hk_expected ha dhe transcript_hash)
   | _ -> True)"#))]
#[hax_lib::fstar::options("--z3rlimit 400 --split_queries always")]
pub(crate) fn derive_hk_handles(
    ha: &HashAlgorithm,
    shared_secret: &Handle,
    psko: &Option<Handle>,
    transcript_hash: &Digest,
    ks: &mut TLSkeyscheduler,
) -> Result<(Handle, Handle, Handle), TLSError> {
    // Proof only: the (EC)DHE secret as stored on entry.
    #[cfg(hax)]
    let dhe_in = get_by_handle(ks, shared_secret);
    let psk_handle = if let Some(k) = psko {
        &k.clone()
    } else {
        &no_psk(ks, ha)
    };
    let (_early_secret, derived_secret, digest_emp) = derive_early_salt(ha, psk_handle, ks)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (psko == Opt.Option_None /\ shared_secret == handle Names.TLSnames_KEM ha (mk_u8 0) ==>
  (match dhe_in with
   | Res.Result_Ok dhe ->
(match Crypto.hkdf_extract ha (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha)) (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha)) with
 | Res.Result_Ok es ->
(match Crypto.hash ha (Bytes.impl_17__new ()) with
 | Res.Result_Ok d ->
(match Spec.derive_secret_hash ha es label_derived d with
 | Res.Result_Ok salt ->
digest_emp == d /\
derived_secret == handle Names.TLSnames_ESalt ha (mk_u8 0) /\
Store.at_handle ks shared_secret == Opt.Option_Some dhe /\
Store.at_handle ks derived_secret == Opt.Option_Some salt
 | _ -> False)
 | _ -> False)
 | _ -> False)
   | _ -> True))"#
    );
    let (client_handshake_traffic_secret, server_handshake_traffic_secret, master_secret_) =
        derive_handshake_secrets(
            ha,
            shared_secret,
            &derived_secret,
            &digest_emp,
            transcript_hash,
            ks,
        )?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (psko == Opt.Option_None /\ shared_secret == handle Names.TLSnames_KEM ha (mk_u8 0) ==>
  (match dhe_in with
   | Res.Result_Ok dhe ->
(match Crypto.hkdf_extract ha (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha)) (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha)) with
 | Res.Result_Ok es ->
(match Crypto.hash ha (Bytes.impl_17__new ()) with
 | Res.Result_Ok d ->
(match Spec.derive_secret_hash ha es label_derived d with
 | Res.Result_Ok salt ->
(match Crypto.hkdf_extract ha dhe salt with
 | Res.Result_Ok hs ->
(match Spec.derive_secret_hash ha hs label_cht transcript_hash with
 | Res.Result_Ok c ->
(match Spec.derive_secret_hash ha hs label_sht transcript_hash with
 | Res.Result_Ok s ->
(match Spec.derive_secret_hash ha hs label_derived d with
 | Res.Result_Ok salt2 ->
client_handshake_traffic_secret == handle Names.TLSnames_CHT ha (mk_u8 0) /\
server_handshake_traffic_secret == handle Names.TLSnames_SHT ha (mk_u8 0) /\
master_secret_ == handle Names.TLSnames_HSalt ha (mk_u8 0) /\
Store.at_handle ks client_handshake_traffic_secret == Opt.Option_Some c /\
Store.at_handle ks server_handshake_traffic_secret == Opt.Option_Some s /\
Store.at_handle ks master_secret_ == Opt.Option_Some salt2
 | _ -> False)
 | _ -> False)
 | _ -> False)
 | _ -> False)
 | _ -> False)
 | _ -> False)
 | _ -> False)
   | _ -> True))"#
    );
    let zero_ikm_handle = zero_ikm(ks, ha);
    let master_secret = XTR(ks, 0, AS, &zero_ikm_handle, &master_secret_)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (psko == Opt.Option_None /\ shared_secret == handle Names.TLSnames_KEM ha (mk_u8 0) ==>
  (match dhe_in with
   | Res.Result_Ok dhe ->
(match Crypto.hkdf_extract ha (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha)) (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha)) with
 | Res.Result_Ok es ->
(match Crypto.hash ha (Bytes.impl_17__new ()) with
 | Res.Result_Ok d ->
(match Spec.derive_secret_hash ha es label_derived d with
 | Res.Result_Ok salt ->
(match Crypto.hkdf_extract ha dhe salt with
 | Res.Result_Ok hs ->
(match Spec.derive_secret_hash ha hs label_cht transcript_hash with
 | Res.Result_Ok c ->
(match Spec.derive_secret_hash ha hs label_sht transcript_hash with
 | Res.Result_Ok s ->
(match Spec.derive_secret_hash ha hs label_derived d with
 | Res.Result_Ok salt2 ->
(match Crypto.hkdf_extract ha (Bytes.impl_17__zeroes (Crypto.impl_4__hash_len ha)) salt2 with
 | Res.Result_Ok ms ->
master_secret == handle Names.TLSnames_AS ha (mk_u8 0) /\
Store.at_handle ks client_handshake_traffic_secret == Opt.Option_Some c /\
Store.at_handle ks server_handshake_traffic_secret == Opt.Option_Some s /\
Store.at_handle ks master_secret == Opt.Option_Some ms /\
Spec.hk_steps ha dhe transcript_hash == Res.Result_Ok (c, s, ms)
 | _ -> False)
 | _ -> False)
 | _ -> False)
 | _ -> False)
 | _ -> False)
 | _ -> False)
 | _ -> False)
 | _ -> False)
   | _ -> True))"#
    );
    Ok((
        client_handshake_traffic_secret,
        server_handshake_traffic_secret,
        master_secret,
    ))
}

#[hax_lib::ensures(|result| fstar!(r#"match Store.at_handle ks client_handshake_traffic_secret, Store.at_handle ks server_handshake_traffic_secret with
  | Opt.Option_Some c, Opt.Option_Some s ->
    result == bind (Spec.finished_key ha c) (fun cf ->
      bind (Spec.finished_key ha s) (fun sf -> bind (rfc_write ha ae c) (fun cw ->
      bind (rfc_write ha ae s) (fun sw -> Res.Result_Ok (cw,sw,cf,sf)))))
  | _ -> True"#))]
pub(crate) fn derive_hk_ms(
    ha: &HashAlgorithm,
    ae: &AeadAlgorithm,
    client_handshake_traffic_secret: &Handle,
    server_handshake_traffic_secret: &Handle,
    ks: &mut TLSkeyscheduler,
) -> Result<(AeadKeyIV, AeadKeyIV, MacKey, MacKey), TLSError> {
    let client_finished_key = derive_finished_key(ha, client_handshake_traffic_secret, ks)?;
    let server_finished_key = derive_finished_key(ha, server_handshake_traffic_secret, ks)?;
    let client_write_key_iv = derive_aead_key_iv(ha, ae, client_handshake_traffic_secret, ks)?;
    let server_write_key_iv = derive_aead_key_iv(ha, ae, server_handshake_traffic_secret, ks)?;

    Ok((
        client_write_key_iv,
        server_write_key_iv,
        client_finished_key,
        server_finished_key,
    ))
}

/// Derive the application keys and master secret.
#[hax_lib::ensures(|result| fstar!(r#"let open Names in
  master_secret.Store.f_alg == ha /\ master_secret.Store.f_name == TLSnames_AS ==>
  (match Store.at_handle ks master_secret with
   | Opt.Option_Some ms ->
     let l = master_secret.Store.f_level in
     three_stored ks_future result (handle TLSnames_CAT ha l) (handle TLSnames_SAT ha l)
       (handle TLSnames_EAM ha l) (Spec.application_traffic ha ms tx)
   | _ -> True)"#))]
#[hax_lib::fstar::options("--z3rlimit 400 --split_queries always")]
pub(crate) fn derive_app_handles(
    ha: &HashAlgorithm,
    master_secret: &Handle,
    tx: &Digest,
    ks: &mut TLSkeyscheduler,
) -> Result<(Handle, Handle, Handle), TLSError> {
    // Proof only: the master secret as stored on entry.
    #[cfg(hax)]
    let ms_in = get_by_handle(ks, master_secret);
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"match ms_in with
  | Res.Result_Ok ms -> app_labels ha ms tx
  | _ -> ()"#
    );
    let client_application_traffic_secret_0 = XPD(ks, CAT, 0, master_secret, true, tx)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (master_secret.Store.f_alg == ha /\ master_secret.Store.f_name == Names.TLSnames_AS ==>
  (match ms_in with
   | Res.Result_Ok ms ->
     Store.at_handle ks master_secret == Opt.Option_Some ms /\
     (match Spec.derive_secret_hash ha ms label_cat tx with
      | Res.Result_Ok c -> client_application_traffic_secret_0_ == {master_secret with Store.f_name = Names.TLSnames_CAT} /\ Store.at_handle ks client_application_traffic_secret_0_ == Opt.Option_Some c
      | _ -> False)
   | _ -> True))"#
    );
    let server_application_traffic_secret_0 = XPD(ks, SAT, 0, master_secret, true, tx)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (master_secret.Store.f_alg == ha /\ master_secret.Store.f_name == Names.TLSnames_AS ==>
  (match ms_in with
   | Res.Result_Ok ms ->
     Store.at_handle ks master_secret == Opt.Option_Some ms /\
     (match Spec.derive_secret_hash ha ms label_cat tx with
      | Res.Result_Ok c -> client_application_traffic_secret_0_ == {master_secret with Store.f_name = Names.TLSnames_CAT} /\ Store.at_handle ks client_application_traffic_secret_0_ == Opt.Option_Some c
      | _ -> False) /\
     (match Spec.derive_secret_hash ha ms label_sat tx with
      | Res.Result_Ok s -> server_application_traffic_secret_0_ == {master_secret with Store.f_name = Names.TLSnames_SAT} /\ Store.at_handle ks server_application_traffic_secret_0_ == Opt.Option_Some s
      | _ -> False)
   | _ -> True))"#
    );
    let exporter_master_secret = XPD(ks, EAM, 0, master_secret, true, tx)?;
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"assert (master_secret.Store.f_alg == ha /\ master_secret.Store.f_name == Names.TLSnames_AS ==>
  (match ms_in with
   | Res.Result_Ok ms ->
     (match Spec.derive_secret_hash ha ms label_cat tx with
      | Res.Result_Ok c -> client_application_traffic_secret_0_ == {master_secret with Store.f_name = Names.TLSnames_CAT} /\ Store.at_handle ks client_application_traffic_secret_0_ == Opt.Option_Some c
      | _ -> False) /\
     (match Spec.derive_secret_hash ha ms label_sat tx with
      | Res.Result_Ok s -> server_application_traffic_secret_0_ == {master_secret with Store.f_name = Names.TLSnames_SAT} /\ Store.at_handle ks server_application_traffic_secret_0_ == Opt.Option_Some s
      | _ -> False) /\
     (match Spec.derive_secret_hash ha ms label_eam tx with
      | Res.Result_Ok e -> exporter_master_secret == {master_secret with Store.f_name = Names.TLSnames_EAM} /\ Store.at_handle ks exporter_master_secret == Opt.Option_Some e
      | _ -> False)
   | _ -> True))"#
    );

    Ok((
        client_application_traffic_secret_0,
        server_application_traffic_secret_0,
        exporter_master_secret,
    ))
}

#[hax_lib::ensures(|result| fstar!(r#"match Store.at_handle ks client_application_traffic_secret_0_ with
  | Opt.Option_Some c ->
    (match Store.at_handle ks server_application_traffic_secret_0_ with
     | Opt.Option_Some s ->
       result == bind (rfc_write ha ae c) (fun cw ->
         bind (rfc_write ha ae s) (fun sw -> Res.Result_Ok (cw,sw)))
     | _ -> True)
  | _ -> True"#))]
pub(crate) fn derive_app_keys(
    ha: &HashAlgorithm,
    ae: &AeadAlgorithm,
    client_application_traffic_secret_0: &Handle,
    server_application_traffic_secret_0: &Handle,
    ks: &mut TLSkeyscheduler,
) -> Result<(AeadKeyIV, AeadKeyIV), TLSError> {
    let client_write_key_iv = derive_aead_key_iv(ha, ae, client_application_traffic_secret_0, ks)?;
    let server_write_key_iv = derive_aead_key_iv(ha, ae, server_application_traffic_secret_0, ks)?;

    Ok((client_write_key_iv, server_write_key_iv))
}

#[hax_lib::ensures(|result| fstar!(r#"master_secret.Store.f_alg == ha ==>
  (match Store.at_handle ks master_secret with
   | Opt.Option_Some ms ->
     Store.derived_step ks ks_future result {master_secret with Store.f_name=Names.TLSnames_RM}
       (Spec.resumption_master ha ms tx)
   | _ -> True)"#))]
pub(crate) fn derive_rms(
    ha: &HashAlgorithm,
    master_secret: &Handle,
    tx: &Digest,
    ks: &mut TLSkeyscheduler,
) -> Result<Handle, TLSError> {
    #[cfg(hax)]
    hax_lib::fstar!(
        r#"match Store.at_handle ks master_secret with
  | Opt.Option_Some ms -> app_labels ha ms tx
  | _ -> ()"#
    );
    XPD(ks, RM, 0, master_secret, true, tx)
}
