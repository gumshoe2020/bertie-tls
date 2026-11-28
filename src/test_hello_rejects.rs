//! Receive-path rejects for the RFC 8446 hello deviations found by the P3a audit.
//!
//! Every message is the RFC 8448 §3 ClientHello or ServerHello with one minimal
//! change. Each case is numbered as in NOTES.md; bertie must return `Err`.

use std::{format, vec, vec::Vec};

use crate::tls13crypto::{AeadAlgorithm, Algorithms, HashAlgorithm, KemScheme, SignatureScheme};
use crate::tls13formats::{handshake_data::HandshakeData, parse_client_hello, parse_server_hello};
use crate::tls13utils::{Bytes, PROTOCOL_VERSION_ALERT};

const ALGORITHMS: Algorithms = Algorithms {
    hash: HashAlgorithm::SHA256,
    aead: AeadAlgorithm::Aes128Gcm,
    signature: SignatureScheme::RsaPssRsaSha256,
    kem: KemScheme::X25519,
    psk_mode: false,
    zero_rtt: false,
};

const CLIENT_RANDOM: &str = "cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7";
const SERVER_RANDOM: &str = "a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928";
const CLIENT_SHARE: &str = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c";
const SERVER_SHARE: &str = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
const HELLO_RETRY_REQUEST_RANDOM: &str =
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c";

/// The RFC 8448 §3 ClientHello and ServerHello, byte for byte.
const RFC8448_CLIENT_HELLO: &str = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001";
const RFC8448_SERVER_HELLO: &str = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";

fn hex(s: &str) -> Vec<u8> {
    Bytes::from_hex(s).declassify()
}

fn u16_prefixed(body: &[u8]) -> Vec<u8> {
    let mut out = vec![(body.len() >> 8) as u8, body.len() as u8];
    out.extend_from_slice(body);
    out
}

fn u8_prefixed(body: &[u8]) -> Vec<u8> {
    let mut out = vec![body.len() as u8];
    out.extend_from_slice(body);
    out
}

/// A hello split into its fields, re-encoded with consistent lengths.
#[derive(Clone)]
struct Parts {
    client: bool,
    random: Vec<u8>,
    session: Vec<u8>,
    suites: Vec<u8>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Parts {
    fn encode(&self) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&self.random);
        body.extend(u8_prefixed(&self.session));
        if self.client {
            body.extend(u16_prefixed(&self.suites));
            body.extend(u8_prefixed(&[0]));
        } else {
            body.extend_from_slice(&self.suites);
            body.push(0);
        }
        let mut list = Vec::new();
        for (kind, data) in &self.extensions {
            list.extend_from_slice(&kind.to_be_bytes());
            list.extend(u16_prefixed(data));
        }
        body.extend(u16_prefixed(&list));
        let mut out = vec![if self.client { 1 } else { 2 }];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend(body);
        out
    }

    fn without(mut self, kind: u16) -> Self {
        self.extensions.retain(|(k, _)| *k != kind);
        self
    }

    fn with(mut self, kind: u16, data: &str) -> Self {
        self.extensions.push((kind, hex(data)));
        self
    }

    fn replace(mut self, kind: u16, data: &str) -> Self {
        for ext in self.extensions.iter_mut().filter(|(k, _)| *k == kind) {
            ext.1 = hex(data);
        }
        self
    }
}

fn client() -> Parts {
    Parts {
        client: true,
        random: hex(CLIENT_RANDOM),
        session: Vec::new(),
        suites: hex("130113031302"),
        extensions: vec![
            (0, hex("0009000006736572766572")),
            (0xff01, hex("00")),
            (10, hex("0012001d00170018001901000101010201030104")),
            (35, Vec::new()),
            (51, hex(&format!("0024001d0020{CLIENT_SHARE}"))),
            (43, hex("020304")),
            (
                13,
                hex("001e040305030603020308040805080604010501060102010402050206020202"),
            ),
            (45, hex("0101")),
            (28, hex("4001")),
        ],
    }
}

fn server() -> Parts {
    Parts {
        client: false,
        random: hex(SERVER_RANDOM),
        session: Vec::new(),
        suites: hex("1301"),
        extensions: vec![
            (51, hex(&format!("001d0020{SERVER_SHARE}"))),
            (43, hex("0304")),
        ],
    }
}

fn handshake(wire: &[u8]) -> HandshakeData {
    HandshakeData::from(Bytes::from_slice(wire))
}

macro_rules! rejects {
    ($name:ident, $parts:expr) => {
        #[test]
        fn $name() {
            let parts: Parts = $parts;
            let message = handshake(&parts.encode());
            if parts.client {
                assert!(parse_client_hello(&ALGORITHMS, &message).is_err());
            } else {
                assert!(parse_server_hello(&ALGORITHMS, &message).is_err());
            }
        }
    };
}

// ---- Positive controls: the RFC 8448 hellos parse with the origin/main values ----

#[test]
fn builder_reproduces_rfc8448_hellos() {
    assert_eq!(client().encode(), hex(RFC8448_CLIENT_HELLO));
    assert_eq!(server().encode(), hex(RFC8448_SERVER_HELLO));
}

#[test]
fn rfc8448_client_hello_parses() {
    let message = handshake(&hex(RFC8448_CLIENT_HELLO));
    let (random, sid, name, share, ticket, binder, trunc) =
        parse_client_hello(&ALGORITHMS, &message).unwrap();
    assert_eq!(random.declassify(), hex(CLIENT_RANDOM));
    assert!(sid.declassify().is_empty());
    assert_eq!(name.declassify(), b"server".to_vec());
    assert_eq!(share.declassify(), hex(CLIENT_SHARE));
    assert!(ticket.is_none());
    assert!(binder.is_none());
    assert_eq!(trunc, 0);
}

#[test]
fn rfc8448_server_hello_parses() {
    let message = handshake(&hex(RFC8448_SERVER_HELLO));
    let (random, share) = parse_server_hello(&ALGORITHMS, &message).unwrap();
    assert_eq!(random.declassify(), hex(SERVER_RANDOM));
    assert_eq!(share.declassify(), hex(SERVER_SHARE));
}

// ---- Lengths and grammar (cases 1–6) ----

// 1. RFC 8446:1549 legacy_session_id<0..32>.
rejects!(case01_ch_session_id_33_bytes, {
    let mut p = client();
    p.session = vec![0x11; 33];
    p
});

// 2. RFC 8446:1698 legacy_session_id_echo<0..32>.
rejects!(case02_sh_session_id_33_bytes, {
    let mut p = server();
    p.session = vec![0x11; 33];
    p
});

// 3. RFC 6066 §3 HostName<1..2^16-1>.
rejects!(
    case03_ch_empty_server_name,
    client().replace(0, "0003000000")
);

// 4. RFC 8446:2674 key_exchange<1..2^16-1>.
rejects!(
    case04_ch_key_share_empty_key_exchange,
    client().replace(51, "0004001d0000")
);

// 5. RFC 8446:2699 client_shares holds only KeyShareEntry values.
rejects!(
    case05_ch_key_share_trailing_byte,
    client().replace(51, &format!("0025001d0020{CLIENT_SHARE}00"))
);

// 6. RFC 8446:2674, for an entry bertie skips.
rejects!(
    case06_ch_key_share_empty_skipped_entry,
    client().replace(51, &format!("002800170000001d0020{CLIENT_SHARE}"))
);

// ---- Mandatory ClientHello extensions, RFC 8446:5778–5790 (cases 7–8) ----

rejects!(case07_ch_missing_signature_algorithms, client().without(13));

rejects!(case08_ch_missing_supported_groups, client().without(10));

// ---- ServerHello extensions and HelloRetryRequest (cases 9–14) ----

// 9. RFC 8446:1760–1762; bertie does not support HelloRetryRequest.
rejects!(case09_sh_hello_retry_request_random, {
    let mut p = server();
    p.random = hex(HELLO_RETRY_REQUEST_RANDOM);
    p
});

// 10–13. RFC 8446:1997–2001 and the table at 2007–2052.
rejects!(case10_sh_contains_server_name, server().with(0, ""));
rejects!(
    case11_sh_contains_supported_groups,
    server().with(10, "0002001d")
);
rejects!(
    case12_sh_contains_signature_algorithms,
    server().with(13, "00020804")
);
rejects!(
    case13_sh_contains_psk_key_exchange_modes,
    server().with(45, "0101")
);

// 14. RFC 8446:2674 key_exchange<1..2^16-1>.
rejects!(
    case14_sh_key_share_empty_key_exchange,
    server().replace(51, "001d0000")
);

// ---- supported_versions (case 15), RFC 8446:2176–2187 ----

rejects!(case15_sh_missing_supported_versions, server().without(43));

/// RFC 8446:1660–1663: without supported_versions the ClientHello offers
/// TLS 1.2 at most, which bertie never supports.
#[test]
fn client_hello_without_supported_versions_rejected() {
    let message = handshake(&client().without(43).encode());
    let result = parse_client_hello(&ALGORITHMS, &message);
    assert_eq!(result.err(), Some(PROTOCOL_VERSION_ALERT));
}

// ---- Sender side of case 3 ----

/// With `defensive`, `client_hello` reparses its own output, so an empty
/// server name (invalid under RFC 6066 §3) fails closed.
#[cfg(feature = "defensive")]
#[test]
fn client_hello_rejects_empty_server_name() {
    let random = Bytes::from(hex(CLIENT_RANDOM));
    let share = Bytes::from(hex(CLIENT_SHARE));
    let result =
        crate::tls13formats::client_hello(&ALGORITHMS, random, &share, &Bytes::new(), &None);
    assert!(result.is_err());
}
