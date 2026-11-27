pub(crate) use super::key_names::Label;
pub use super::key_names::TLSnames;

use crate::{
    tls13crypto::{hkdf_expand, hkdf_extract, hmac_tag, Digest, HashAlgorithm, Key},
    tls13formats::*,
    tls13utils::*,
};
use std::vec;
use std::vec::Vec;

/* TLS 1.3 Key Schedule: See RFC 8446 Section 7 */

/// HKDF expand with a `label`.
///
/// Proved (P2 M2): for a non-empty `label` this is the RFC 8446 §7.1
/// specification's `expand_label`, errors included. The specification rejects an
/// empty Label (RFC 8446 requires at least 7 bytes with the prefix); this
/// function accepts it, so nothing is claimed for that case.
#[cfg_attr(feature = "hax-pv", hax_lib::pv_constructor)]
#[hax_lib::ensures(|result| fstar!(r#"Seq.length label.Bertie_tls.Tls13utils.Byte_types._0._0 > 0 ==>
  result == Bertie_tls.Tls13keyscheduler.Rfc8446_spec.expand_label hash_algorithm key label context len"#))]
pub(crate) fn hkdf_expand_label(
    hash_algorithm: &HashAlgorithm,
    key: &Key,
    label: Bytes,
    context: &Bytes,
    len: usize,
) -> Result<Key, TLSError> {
    if len >= 65536 || label.len() > 255 - LABEL_TLS13.len() {
        Err(PAYLOAD_TOO_LONG)
    } else {
        let lenb = u16_as_be_bytes(U16(len as u16));
        let tls13_label = Bytes::from_slice(&LABEL_TLS13).concat(label);
        let info = encode_length_u8(tls13_label.as_raw())?
            .concat(encode_length_u8(context.as_raw())?)
            .prefix(&lenb);
        #[cfg(hax)]
        hax_lib::fstar!(
            r#"match Bertie_tls.Tls13keyscheduler.Rfc8446_spec.hkdf_label label context len with
  | Core_models.Result.Result_Ok spec_info ->
    assert (Seq.equal info.Bertie_tls.Tls13utils.Byte_types._0._0
      spec_info.Bertie_tls.Tls13utils.Byte_types._0._0)
  | _ -> ()"#
        );
        hkdf_expand(hash_algorithm, key, &info, len)
    }
}

/// Corollary (P2, approved HKDF link): for a non-empty label, a successful
/// `hkdf_expand_label` is RFC 8446 §7.1 HKDF-Expand-Label over HACL*'s
/// `Spec.Agile.HKDF.expand`: its output is HACL*'s expansion of the
/// specification's HkdfLabel bytes, whenever HACL*'s preconditions hold
/// (`Backend.hkdf_expand_is_hacl`). Follows from the M2 equality above and the
/// single assumed postcondition on `backend::hkdf_expand_okm`.
#[cfg(hax)]
#[allow(unused_variables)]
#[hax_lib::ensures(|_| fstar!(r#"Seq.length label.Bertie_tls.Tls13utils.Byte_types._0._0 > 0 ==>
  (match hkdf_expand_label hash_algorithm key label context len with
   | Core_models.Result.Result_Ok okm ->
     (match Bertie_tls.Tls13keyscheduler.Rfc8446_spec.hkdf_label label context len with
      | Core_models.Result.Result_Ok info ->
        Bertie_tls.Tls13crypto.Backend.hkdf_expand_is_hacl hash_algorithm
          key.Bertie_tls.Tls13utils.Byte_types._0._0 info.Bertie_tls.Tls13utils.Byte_types._0._0 len
          okm.Bertie_tls.Tls13utils.Byte_types._0._0
      | _ -> False)
   | _ -> True)"#))]
fn hkdf_expand_label_is_rfc8446_over_hacl(
    hash_algorithm: &HashAlgorithm,
    key: &Key,
    label: Bytes,
    context: &Bytes,
    len: usize,
) {
}

/// Get an empty key of the correct size.
pub(crate) fn zero_salt(ks: &mut TLSkeyscheduler, alg: &HashAlgorithm) -> Handle {
    let handle = Handle {
        name: ZeroSalt,
        alg: *alg,
        level: 0,
    };
    // RFC 8446 §7.1 uses Hash.length zero bytes for the absent salt.
    set_by_handle(ks, &handle, Bytes::zeroes(alg.hash_len()));
    handle
}

/// Get an empty key of the correct size.
pub(crate) fn no_psk(ks: &mut TLSkeyscheduler, alg: &HashAlgorithm) -> Handle // TagKey
{
    let handle = Handle {
        name: PSK,
        alg: *alg,
        level: 0,
    };
    set_by_handle(ks, &handle, Bytes::zeroes(alg.hash_len()));
    handle
}

/// Get an empty key of the correct size.
pub(crate) fn zero_ikm(ks: &mut TLSkeyscheduler, alg: &HashAlgorithm) -> Handle {
    let handle = Handle {
        name: ZeroIKM,
        alg: *alg,
        level: 0,
    };
    set_by_handle(ks, &handle, Bytes::zeroes(alg.hash_len()));
    handle
}

pub trait KeySchedule<N> {
    fn labels(a: N, b: bool) -> Result<Bytes, TLSError>; // Bit string of size 96 (8*12)
    fn prnt_n(a: N) -> (Option<N>, Option<N>);

    // key mapping
    fn get(&self, name: N, level: u8, h: (N, HashAlgorithm, u8)) -> Option<Key>;
    fn set(&mut self, name: N, level: u8, h: (N, HashAlgorithm, u8), k: Key);

    fn hash(d: &Bytes) -> Bytes;
}

#[cfg_attr(
    hax,
    hax_lib::fstar::before(
        interface,
        r#"
module Names = Bertie_tls.Tls13keyscheduler.Key_names
module Algorithms = Bertie_tls.Tls13crypto.Algorithm_types
type slot = Names.t_TLSnames & Algorithms.t_HashAlgorithm & u8
type entry = slot & Bertie_tls.Tls13utils.Byte_types.t_Bytes

let distinct_slots (s:Seq.seq entry) : Type0 =
  forall (i j:nat). i < j /\ j < Seq.length s ==> (Seq.index s i)._1 =!= (Seq.index s j)._1

let name_index (n:Names.t_TLSnames) : FStar.Fin.under 19 =
  let open Names in match n with
  | TLSnames_ES -> 0
  | TLSnames_EEM -> 1
  | TLSnames_CET -> 2
  | TLSnames_Bind -> 3
  | TLSnames_Binder -> 4
  | TLSnames_HS -> 5
  | TLSnames_SHT -> 6
  | TLSnames_CHT -> 7
  | TLSnames_HSalt -> 8
  | TLSnames_AS -> 9
  | TLSnames_RM -> 10
  | TLSnames_CAT -> 11
  | TLSnames_SAT -> 12
  | TLSnames_EAM -> 13
  | TLSnames_PSK -> 14
  | TLSnames_ZeroSalt -> 15
  | TLSnames_ESalt -> 16
  | TLSnames_KEM -> 17
  | TLSnames_ZeroIKM -> 18

let hash_index (a:Algorithms.t_HashAlgorithm) : FStar.Fin.under 3 =
  let open Algorithms in match a with
  | HashAlgorithm_SHA256 -> 0
  | HashAlgorithm_SHA384 -> 1
  | HashAlgorithm_SHA512 -> 2

let slot_index ((n,a,l):slot) : FStar.Fin.under 14592 =
  (name_index n * 3 + hash_index a) * 256 + v l

let index_injective (x y:slot) : Lemma (requires slot_index x == slot_index y) (ensures x == y) =
  assert (v x._3 == v y._3);
  assert (hash_index x._2 == hash_index y._2);
  assert (name_index x._1 == name_index y._1);
  ()

// A new handle can always be appended. There are 19 * 3 * 256 possible slots.
let store_capacity (s:Seq.seq entry{distinct_slots s}) : Lemma (Seq.length s <= 14592) =
  if Seq.length s > 14592 then (
    let at (i:FStar.Fin.under 14593) = slot_index (Seq.index s i)._1 in
    let indices = Seq.init 14593 at in
    let i,j = FStar.Fin.pigeonhole #14592 indices in
    index_injective (Seq.index s i)._1 (Seq.index s j)._1)
"#
    )
)]
#[hax_lib::attributes]
pub struct TLSkeyscheduler {
    #[hax_lib::refine(hax_lib::fstar::prop!("distinct_slots f_keys._0"))]
    keys: Vec<((TLSnames, HashAlgorithm, u8), Key)>,
}

impl Default for TLSkeyscheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[hax_lib::attributes]
impl TLSkeyscheduler {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    #[hax_lib::ensures(|result| fstar!(r#"let s = self.f_keys._0 in
      v result <= Seq.length s /\
      (forall (j:nat). j < v result ==> (Seq.index s j)._1 =!= h) /\
      (v result < Seq.length s ==> (Seq.index s (v result))._1 == h)"#))]
    fn position(&self, h: (TLSnames, HashAlgorithm, u8)) -> usize {
        let mut i = 0;
        while i < self.keys.len() && self.keys[i].0 != h {
            hax_lib::loop_invariant!(fstar!(
                r#"v i <= Seq.length self.f_keys._0 /\
                (forall (j:nat). j < v i ==> (Seq.index self.f_keys._0 j)._1 =!= h)"#
            ));
            hax_lib::loop_decreases!(self.keys.len() - i);
            i += 1;
        }
        i
    }

    #[hax_lib::ensures(|result| fstar!(r#"let s = self.f_keys._0 in
      (forall j. j < Seq.length s /\ (Seq.index s j)._1 == h ==>
        result == Core_models.Option.Option_Some (Seq.index s j)._2) /\
      (match result with
       | Core_models.Option.Option_Some k ->
         exists j. j < Seq.length s /\ Seq.index s j == (h,k)
       | _ -> True)"#))]
    fn lookup(&self, h: (TLSnames, HashAlgorithm, u8)) -> Option<Key> {
        let i = self.position(h);
        if i < self.keys.len() {
            Some(self.keys[i].1.clone())
        } else {
            None
        }
    }

    #[hax_lib::ensures(|_| fstar!(r#"
      impl_TLSkeyscheduler__lookup self_e_future h == Core_models.Option.Option_Some k /\
      (forall q. q =!= h ==>
        impl_TLSkeyscheduler__lookup self_e_future q == impl_TLSkeyscheduler__lookup self q)"#))]
    fn put(&mut self, h: (TLSnames, HashAlgorithm, u8), k: Key) {
        let i = self.position(h);
        if i < self.keys.len() {
            self.keys[i] = (h, k);
        } else {
            #[cfg(hax)]
            hax_lib::fstar!("store_capacity self.f_keys._0");
            self.keys.push((h, k));
        }
    }
}

use TLSnames::*;

impl KeySchedule<TLSnames> for TLSkeyscheduler {
    fn prnt_n(a: TLSnames) -> (Option<TLSnames>, Option<TLSnames>) {
        match a {
            ES => (Some(ZeroSalt), Some(PSK)),
            EEM | CET | Bind => (Some(ES), None),
            Binder => (Some(Bind), None),
            HS => (Some(ESalt), Some(KEM)),
            SHT | CHT | HSalt => (Some(HS), None),
            AS => (Some(HSalt), Some(ZeroIKM)),
            RM | CAT | SAT | EAM => (Some(AS), None),
            PSK => (Some(RM), None),
            ZeroSalt | KEM | ZeroIKM => (None, None),
            ESalt => (Some(ES), None), // (todo!(), None),
        }
    }

    fn labels(a: TLSnames, b: bool) -> Result<Bytes, TLSError> {
        // [u8; 12]
        Ok(label_to_bytes(match a {
            Bind => {
                if b {
                    RES_BINDER__
                } else {
                    EXT_BINDER__
                }
            }
            RM => RES_MASTER__,
            ESalt | HSalt => DERIVED_____,
            EEM => E_EXP_MASTER,
            EAM => EXP_MASTER__,
            CET => C_E_TRAFFIC_,
            Binder => ____________,
            SHT => S_HS_TRAFFIC,
            CHT => C_HS_TRAFFIC,
            CAT => C_AP_TRAFFIC,
            SAT => S_AP_TRAFFIC,
            _ => Err(INCORRECT_STATE)?,
        }))
    }

    fn get(&self, name: TLSnames, level: u8, h: (TLSnames, HashAlgorithm, u8)) -> Option<Key> {
        self.lookup(h)
    }

    fn set(&mut self, name: TLSnames, level: u8, h: (TLSnames, HashAlgorithm, u8), k: Key) {
        self.put(h, k);
    }

    // TODO:
    fn hash(d: &Bytes) -> Bytes {
        d.clone()
    }
}

use Label::*;

fn convert_label(label: Bytes) -> Option<Label> {
    let l = &label.declassify()[..];
    if l == [101, 120, 116, 032, 098, 105, 110, 100, 101, 114] {
        Some(EXT_BINDER__)
    } else if l == [114, 101, 115, 032, 098, 105, 110, 100, 101, 114] {
        Some(RES_BINDER__)
    } else if l == [099, 032, 101, 032, 116, 114, 097, 102, 102, 105, 099] {
        Some(C_E_TRAFFIC_)
    } else if l == [101, 032, 101, 120, 112, 032, 109, 097, 115, 116, 101, 114] {
        Some(E_EXP_MASTER)
    } else if l == [099, 032, 097, 112, 032, 116, 114, 097, 102, 102, 105, 099] {
        Some(C_AP_TRAFFIC)
    } else if l == [115, 032, 097, 112, 032, 116, 114, 097, 102, 102, 105, 099] {
        Some(S_AP_TRAFFIC)
    } else if l == [101, 120, 112, 032, 109, 097, 115, 116, 101, 114] {
        Some(EXP_MASTER__)
    } else if l == [114, 101, 115, 032, 109, 097, 115, 116, 101, 114] {
        Some(RES_MASTER__)
    } else if l == [100, 101, 114, 105, 118, 101, 100] {
        Some(DERIVED_____)
    } else if l == [099, 032, 104, 115, 032, 116, 114, 097, 102, 102, 105, 099] {
        Some(C_HS_TRAFFIC)
    } else if l == [115, 032, 104, 115, 032, 116, 114, 097, 102, 102, 105, 099] {
        Some(S_HS_TRAFFIC)
    } else if l == [82, 69, 83, 85, 77, 80, 84, 73, 79, 78] {
        Some(RESUMPTION__)
    } else if l.is_empty() {
        Some(____________)
    } else {
        None
    }
}

#[allow(clippy::just_underscores_and_digits)]
#[cfg_attr(feature = "hax-pv", hax_lib::pv_constructor)]
fn label_to_bytes(label: Label) -> Bytes {
    match label {
        EXT_BINDER__ => vec![101, 120, 116, 032, 098, 105, 110, 100, 101, 114].into(),
        RES_BINDER__ => vec![114, 101, 115, 032, 098, 105, 110, 100, 101, 114].into(),
        C_E_TRAFFIC_ => vec![099, 032, 101, 032, 116, 114, 097, 102, 102, 105, 099].into(),
        E_EXP_MASTER => vec![101, 032, 101, 120, 112, 032, 109, 097, 115, 116, 101, 114].into(),
        C_AP_TRAFFIC => vec![099, 032, 097, 112, 032, 116, 114, 097, 102, 102, 105, 099].into(),
        S_AP_TRAFFIC => vec![115, 032, 097, 112, 032, 116, 114, 097, 102, 102, 105, 099].into(),
        EXP_MASTER__ => vec![101, 120, 112, 032, 109, 097, 115, 116, 101, 114].into(),
        RES_MASTER__ => vec![114, 101, 115, 032, 109, 097, 115, 116, 101, 114].into(),
        DERIVED_____ => vec![100, 101, 114, 105, 118, 101, 100].into(),
        C_HS_TRAFFIC => vec![099, 032, 104, 115, 032, 116, 114, 097, 102, 102, 105, 099].into(),
        S_HS_TRAFFIC => vec![115, 032, 104, 115, 032, 116, 114, 097, 102, 102, 105, 099].into(),
        RESUMPTION__ => vec![82, 69, 83, 85, 77, 80, 84, 73, 79, 78].into(),
        ____________ => vec::Vec::<u8>::new().into(),
    }
}

#[derive(Clone)]
pub struct TagKey {
    pub alg: HashAlgorithm,
    pub tag: TLSnames,
    pub val: Key,
}

pub(crate) fn xtr_alg(alg: &HashAlgorithm, k1: &Key, k2: &Key) -> Result<Bytes, TLSError> {
    hkdf_extract(alg, k1, k2)
}

pub(crate) fn xpd_alg(
    alg: &HashAlgorithm,
    k1: &Key,
    label: Bytes,
    d: &Digest,
) -> Result<Bytes, TLSError> {
    let kvt = convert_label(label.clone());
    if kvt == Some(____________) {
        hmac_tag(alg, k1, d)
    } else {
        hkdf_expand_label(alg, k1, label, d, alg.hash_len())
    }
}

pub(crate) fn xtr(k1: &TagKey, k2: &TagKey) -> Result<TagKey, TLSError> {
    let val = xtr_alg(&k1.alg, &k1.val, &k2.val)?;

    Ok(TagKey {
        alg: k1.alg,
        tag: k1.tag,
        val,
    })
}

pub(crate) fn xpd(k1: &TagKey, label: Bytes, d: &Digest) -> Result<TagKey, TLSError> {
    let alg = k1.clone().alg;
    let v = k1.clone().val;
    let val = xpd_alg(&alg, &v, label, d)?;

    Ok(TagKey {
        tag: k1.tag,
        alg,
        val,
    })
}

#[derive(Clone)]
#[cfg_attr(not(hax), derive(Debug))]
pub struct Handle {
    pub name: TLSnames,
    pub alg: HashAlgorithm,
    pub level: u8,
}

pub(crate) fn xpd_angle(
    name: TLSnames,
    label: Bytes,
    parrent_handle: &Handle,
    args: &Bytes,
) -> Result<Handle, TLSError> {
    Ok(Handle {
        name,
        alg: parrent_handle.alg,
        level: parrent_handle.level,
    })
}

#[cfg_attr(feature = "hax-pv", hax_lib::pv_constructor)]
pub fn tagkey_from_handle(ks: &TLSkeyscheduler, handle: &Handle) -> Result<TagKey, TLSError> {
    Ok(TagKey {
        alg: handle.alg,
        tag: handle.name,
        val: get_by_handle(ks, handle)?,
    })
}

#[cfg_attr(feature = "hax-pv", hax_lib::pv_constructor)]
#[hax_lib::ensures(|_| fstar!(r#"let h = (handle.f_name, handle.f_alg, handle.f_level) in
  impl_TLSkeyscheduler__lookup ks_future h == Core_models.Option.Option_Some key /\
  (forall q. q =!= h ==> impl_TLSkeyscheduler__lookup ks_future q == impl_TLSkeyscheduler__lookup ks q)"#))]
pub fn set_by_handle(ks: &mut TLSkeyscheduler, handle: &Handle, key: Key) {
    ks.set(
        handle.name,
        handle.level,
        (handle.name, handle.alg, handle.level),
        key,
    );
}

#[cfg_attr(feature = "hax-pv", hax_lib::pv_constructor)]
#[hax_lib::ensures(|result| fstar!(r#"result == (match impl_TLSkeyscheduler__lookup ks
    (handle.f_name, handle.f_alg, handle.f_level) with
  | Core_models.Option.Option_Some k -> Core_models.Result.Result_Ok k
  | _ -> Core_models.Result.Result_Err Bertie_tls.Tls13utils.v_INCORRECT_STATE)"#))]
pub fn get_by_handle(ks: &TLSkeyscheduler, handle: &Handle) -> Result<Key, TLSError> {
    ks.get(
        handle.name,
        handle.level,
        (handle.name, handle.alg, handle.level),
    )
    .ok_or(INCORRECT_STATE)
}

#[allow(non_snake_case)]
#[allow(clippy::assign_op_pattern)]
#[cfg_attr(
    feature = "hax-pv",
    hax_lib::proverif::before(
        "fun extern__XPD(
                $:{TLSnames},
                nat,
                $:{Handle},
                bool,
                $:{Bytes}
         )
     : $:{Handle}."
    )
)]
#[cfg_attr(
    feature = "hax-pv",
    hax_lib::proverif::replace_body(
        "(extern__XPD(
              n,
              l,
              h1,
              r,
              args
          )
       )"
    )
)]
pub fn XPD(
    ks: &mut TLSkeyscheduler,
    n: TLSnames,
    mut l: u8,
    h1: &Handle,
    r: bool,
    args: &Bytes,
) -> Result<Handle, TLSError> {
    let (n1, _) = TLSkeyscheduler::prnt_n(n);
    let label = TLSkeyscheduler::labels(n, r)?;

    let h = xpd_angle(n, label.clone(), h1, args)?;
    let n1_unwrap = n1.ok_or(INCORRECT_STATE)?;
    let k1 = ks
        .get(n1_unwrap, l, (h1.name, h1.alg, h1.level))
        .ok_or(INCORRECT_STATE)?;

    let k: TagKey = if n == PSK {
        l = l + 1;
        xpd(
            &TagKey {
                alg: h1.alg,
                tag: h1.name,
                val: k1,
            },
            label,
            args,
        )?
    } else {
        let d = TLSkeyscheduler::hash(args);
        xpd(
            &TagKey {
                alg: h1.alg,
                tag: h1.name,
                val: k1,
            },
            label,
            &d,
        )?
    };
    ks.set(n, l, (h.name, h.alg, h.level), k.val);

    Ok(h)
}

pub(crate) fn xtr_angle(name: TLSnames, left: Handle, right: Handle) -> Result<Handle, TLSError> {
    Ok(Handle {
        alg: left.alg,
        name,
        level: left.level,
    })
}

#[allow(non_snake_case)]
#[cfg_attr(
    feature = "hax-pv",
    hax_lib::proverif::before(
        "fun extern__XTR(
                nat,
                $:{TLSnames},
                $:{Handle},
                $:{Handle}
         )
     : $:{Handle}."
    )
)]
#[cfg_attr(
    feature = "hax-pv",
    hax_lib::proverif::replace_body(
        "(extern__XTR(
              level,
              name,
              h1,
              h2
          )
       )"
    )
)]
pub(crate) fn XTR(
    ks: &mut TLSkeyscheduler,
    level: u8,
    name: TLSnames,
    h1: &Handle,
    h2: &Handle,
) -> Result<Handle, TLSError> {
    let (n1, n2) = TLSkeyscheduler::prnt_n(name);
    let h = xtr_angle(name, h1.clone(), h2.clone())?;
    let n1_unwrap = n1.ok_or(INCORRECT_STATE)?;
    let n2_unwrap = n2.ok_or(INCORRECT_STATE)?;
    let k1 = ks
        .get(n1_unwrap, level, (h1.name, h1.alg, h1.level))
        .ok_or(INCORRECT_STATE)?;
    let k2 = ks
        .get(n2_unwrap, level, (h2.name, h2.alg, h2.level))
        .ok_or(INCORRECT_STATE)?;
    let k = xtr(
        &TagKey {
            alg: h1.alg,
            tag: h1.name,
            val: k1,
        },
        &TagKey {
            alg: h2.alg,
            tag: h2.name,
            val: k2,
        },
    )?;
    ks.set(name, level, (h.name, h.alg, h.level), k.val);
    Ok(h)
}

#[cfg(all(test, feature = "sha256"))]
mod label_tests {
    use super::*;

    #[test]
    fn hkdf_label_wire_length_bound() {
        let key = Bytes::zeroes(32);
        let context = Bytes::zeroes(32);
        for label in [Bytes::from_slice(b"derived"), Bytes::zeroes(249)] {
            let info = encode_length_u8(
                Bytes::from_slice(&LABEL_TLS13)
                    .concat(label.clone())
                    .as_raw(),
            )
            .unwrap()
            .concat(encode_length_u8(context.as_raw()).unwrap())
            .prefix(&u16_as_be_bytes(U16(32)));
            let expected = hkdf_expand(&HashAlgorithm::SHA256, &key, &info, 32).unwrap();
            assert_eq!(
                hkdf_expand_label(&HashAlgorithm::SHA256, &key, label, &context, 32).unwrap(),
                expected
            );
        }
        assert!(matches!(
            hkdf_expand_label(
                &HashAlgorithm::SHA256,
                &key,
                Bytes::zeroes(250),
                &context,
                32,
            ),
            Err(PAYLOAD_TOO_LONG)
        ));
    }
}
