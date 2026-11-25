//! Public test data from RFC 8448 §3 (not live secrets). No private keys needed.
//! Transcript inputs use the RFC's printed hashes, not reconstructed messages.
//! AES-128-GCM sizes follow the trace; deriving bytes does not enable AES.
use super::{
    derive_app_handles, derive_app_keys, derive_hk_handles, derive_hk_ms, derive_rms,
    key_schedule::{get_by_handle, set_by_handle, Handle, TLSkeyscheduler, TLSnames},
};
use crate::tls13crypto::{AeadAlgorithm, Digest, HashAlgorithm};
use crate::tls13utils::Bytes;
use std::collections::HashMap;
use std::{vec, vec::Vec};

fn inputs() -> (Bytes, Digest, Digest, Digest) {
    (
        Bytes::from_hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"), // RFC 8448:267
        Bytes::from_hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"), // RFC 8448:287
        Bytes::from_hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"), // RFC 8448:537
        Bytes::from_hex("209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"), // RFC 8448:725
    )
}

fn expected() -> Vec<(&'static str, Bytes)> {
    vec![
        (
            "early",
            Bytes::from_hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
        ), // RFC 8448:219
        (
            "early derived",
            Bytes::from_hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"),
        ), // RFC 8448:259
        (
            "handshake",
            Bytes::from_hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"),
        ), // RFC 8448:270
        (
            "client handshake traffic",
            Bytes::from_hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"),
        ), // RFC 8448:294
        (
            "server handshake traffic",
            Bytes::from_hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
        ), // RFC 8448:309
        (
            "handshake derived",
            Bytes::from_hex("43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"),
        ), // RFC 8448:324
        (
            "master",
            Bytes::from_hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"),
        ), // RFC 8448:343
        (
            "client finished key",
            Bytes::from_hex("b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"),
        ), // RFC 8448:684
        (
            "server finished key",
            Bytes::from_hex("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"),
        ), // RFC 8448:433
        (
            "client handshake key",
            Bytes::from_hex("dbfaa693d1762c5b666af5d950258d01"),
        ), // RFC 8448:606
        (
            "client handshake iv",
            Bytes::from_hex("5bd3c71b836e0b76bb73265f"),
        ), // RFC 8448:611
        (
            "server handshake key",
            Bytes::from_hex("3fce516009c21727d0f2e4e86ee403bc"),
        ), // RFC 8448:367
        (
            "server handshake iv",
            Bytes::from_hex("5d313eb2671276ee13000b30"),
        ), // RFC 8448:372
        (
            "client application traffic",
            Bytes::from_hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"),
        ), // RFC 8448:544
        (
            "server application traffic",
            Bytes::from_hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"),
        ), // RFC 8448:567
        (
            "exporter master",
            Bytes::from_hex("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"),
        ), // RFC 8448:582
        (
            "client application key",
            Bytes::from_hex("17422dda596ed5d9acd890e3c63f5051"),
        ), // RFC 8448:713
        (
            "client application iv",
            Bytes::from_hex("5b78923dee08579033e523d9"),
        ), // RFC 8448:718
        (
            "server application key",
            Bytes::from_hex("9f02283b6c9c07efc26bb9f2ac92e356"),
        ), // RFC 8448:592
        (
            "server application iv",
            Bytes::from_hex("cf782b88dd83549aadf1e984"),
        ), // RFC 8448:597
        (
            "resumption master",
            Bytes::from_hex("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"),
        ), // RFC 8448:739
    ]
}

fn implementation() -> Vec<Bytes> {
    let ha = HashAlgorithm::SHA256;
    let ae = AeadAlgorithm::Aes128Gcm;
    let (dhe, sh, sf, cf) = inputs();
    let mut ks = TLSkeyscheduler {
        keys: HashMap::new(),
    };
    let dhe_handle = Handle {
        name: TLSnames::KEM,
        alg: ha,
        level: 0,
    };
    set_by_handle(&mut ks, &dhe_handle, dhe);
    let (cht, sht, ms) = derive_hk_handles(&ha, &dhe_handle, &None, &sh, &mut ks).unwrap();
    let (chk, shk, cfk, sfk) = derive_hk_ms(&ha, &ae, &cht, &sht, &mut ks).unwrap();
    let (cat, sat, exp) = derive_app_handles(&ha, &ms, &sf, &mut ks).unwrap();
    let (cak, sak) = derive_app_keys(&ha, &ae, &cat, &sat, &mut ks).unwrap();
    let rms = derive_rms(&ha, &ms, &cf, &mut ks).unwrap();
    let stored = |name| {
        get_by_handle(
            &ks,
            &Handle {
                name,
                alg: ha,
                level: 0,
            },
        )
        .unwrap()
    };
    vec![
        stored(TLSnames::ES),
        stored(TLSnames::ESalt),
        stored(TLSnames::HS),
        get_by_handle(&ks, &cht).unwrap(),
        get_by_handle(&ks, &sht).unwrap(),
        stored(TLSnames::HSalt),
        get_by_handle(&ks, &ms).unwrap(),
        cfk,
        sfk,
        chk.key.bytes().clone(),
        chk.iv,
        shk.key.bytes().clone(),
        shk.iv,
        get_by_handle(&ks, &cat).unwrap(),
        get_by_handle(&ks, &sat).unwrap(),
        get_by_handle(&ks, &exp).unwrap(),
        cak.key.bytes().clone(),
        cak.iv,
        sak.key.bytes().clone(),
        sak.iv,
        get_by_handle(&ks, &rms).unwrap(),
    ]
}

#[test]
fn rfc8448_section3_implementation() {
    let actual = implementation();
    let expected = expected();
    assert_eq!(actual.len(), expected.len());
    let mismatches: Vec<&str> = expected
        .iter()
        .zip(&actual)
        .filter(|((_, want), actual)| actual != &want)
        .map(|((name, _), _)| *name)
        .collect();
    assert!(
        mismatches.is_empty(),
        "RFC 8448 implementation mismatches: {mismatches:?}"
    );
}
