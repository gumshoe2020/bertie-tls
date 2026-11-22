use crate::{
    tls13crypto::{Psk, SignatureKey},
    tls13utils::Bytes,
};

/// The Server Database
#[derive(Clone, Default)]
#[cfg_attr(not(hax), derive(Debug))]
pub struct ServerDB {
    pub(crate) server_name: Bytes,
    pub(crate) cert: Bytes,
    pub(crate) sk: SignatureKey,
    pub(crate) psk_opt: Option<(Bytes, Psk)>,
}
