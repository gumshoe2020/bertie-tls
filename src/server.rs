//! # TLS 1.3 Server
//!
//! This module implements a simple TLS 1.3 server database to handle the server
//! * name
//! * certificate
//! * private signature key
//! * optional PSKs

use crate::{
    tls13crypto::{Algorithms, Psk, PublicVerificationKey, SignatureKey},
    tls13utils::{eq, parse_failed, Bytes, TLSError, PSK_MODE_MISMATCH, UNSUPPORTED_ALGORITHM},
};

mod server_db;

pub use server_db::ServerDB;

impl ServerDB {
    /// Create a new server database.
    ///
    /// Note that this only holds one value at a time right now. #51
    pub fn new(
        server_name: Bytes,
        cert: Bytes,
        sk: SignatureKey,
        psk_opt: Option<(Bytes, Psk)>,
    ) -> Self {
        Self {
            server_name,
            cert,
            sk,
            psk_opt,
        }
    }
}

/// Global server information.
pub(crate) struct ServerInfo {
    pub(crate) cert: Bytes,
    pub(crate) sk: SignatureKey,
    pub(crate) psk_opt: Option<Psk>,
}

#[derive(Clone)]
pub struct ServerPubInfo {
    pub server_name: Bytes,
    pub certificate: Option<Bytes>,
    pub public_key: Option<PublicVerificationKey>,
    pub session_ticket: Option<Bytes>,
}

// ProVerif models "no PSK offered"; PSK is disabled, so both outcomes are errors.
// See TRUSTED.md, "ProVerif model assumptions".
#[cfg_attr(
    feature = "hax-pv",
    hax_lib::proverif::replace_body("false (* PSK disabled: no PSK offered *)")
)]
fn psk_offered(tkt: &Option<Bytes>, psk_opt: &Option<(Bytes, Psk)>) -> bool {
    tkt.is_some() && psk_opt.is_some()
}

/// Look up a server for the given `ciphersuite`.
///
/// The function returns a server with the first algorithm it finds.
pub(crate) fn lookup_db(
    ciphersuite: Algorithms,
    db: &ServerDB,
    sni: &Bytes,
    tkt: &Option<Bytes>,
) -> Result<ServerInfo, TLSError> {
    if
    //eq(sni, &Bytes::new()) ||
    eq(sni, &db.server_name) {
        if !ciphersuite.psk_mode() {
            let server = ServerInfo {
                cert: db.cert.clone(),
                sk: db.sk.clone(),
                psk_opt: None,
            };
            Ok(server)
        } else if psk_offered(tkt, &db.psk_opt) {
            Err(UNSUPPORTED_ALGORITHM)
        } else {
            Err(PSK_MODE_MISMATCH)
        }
    } else {
        Err(parse_failed())
    }
}

#[cfg(test)]
mod psk_tests {
    use super::*;
    use crate::tls13crypto::SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519;

    #[test]
    fn lookup_db_refuses_psk_acceptance() {
        let mut algorithms = SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519;
        algorithms.psk_mode = true;
        let db = ServerDB::new(
            b"example.com".into(),
            b"cert".into(),
            Bytes::new(),
            Some((b"ticket".into(), Bytes::new())),
        );
        for ticket in [b"ticket".as_slice(), b"different-ticket".as_slice()] {
            let result = lookup_db(algorithms, &db, &db.server_name, &Some(ticket.into()));
            assert!(matches!(result, Err(UNSUPPORTED_ALGORITHM)));
        }
    }

    #[test]
    fn lookup_db_ignores_client_ticket_when_psk_is_disabled() {
        let algorithms = SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519;
        for psk_opt in [None, Some((b"server-ticket".into(), Bytes::new()))] {
            let db = ServerDB::new(b"example.com".into(), b"cert".into(), Bytes::new(), psk_opt);
            let server = lookup_db(
                algorithms,
                &db,
                &db.server_name,
                &Some(b"client-ticket".into()),
            )
            .unwrap();
            assert_eq!(server.cert, db.cert);
            assert_eq!(server.sk, db.sk);
            assert!(server.psk_opt.is_none());
        }
    }

    #[test]
    fn lookup_db_reports_mismatch_when_psk_mode_lacks_ticket_or_server_psk() {
        let mut algorithms = SHA256_Chacha20Poly1305_EcdsaSecp256r1Sha256_X25519;
        algorithms.psk_mode = true;
        let with_psk = Some((b"ticket".into(), Bytes::new()));
        let cases = [
            (None, with_psk.clone()),
            (Some(b"t".into()), None),
            (None, None),
        ];
        for (ticket, psk_opt) in cases {
            let db = ServerDB::new(b"example.com".into(), b"cert".into(), Bytes::new(), psk_opt);
            let result = lookup_db(algorithms, &db, &db.server_name, &ticket);
            assert!(matches!(result, Err(PSK_MODE_MISMATCH)));
        }
    }
}
