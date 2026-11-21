//! # Streaming API
//!
//! A streaming API for Bertie.
//! This is a more usable API that is however NOT VERIFIED.

#[cfg(feature = "client")]
use self::client::ClientState;
use self::server::ServerState;

mod bertie_stream;
#[cfg(feature = "client")]
mod client;
mod server;

pub use bertie_stream::{BertieError, BertieStream, TlsStream};
pub use server::init_db;

/// A Bertie Client stream.
#[cfg(feature = "client")]
pub type BertieClient<Stream> = BertieStream<ClientState<Stream>>;
/// A Bertie Server stream.
pub type BertieServer<Stream> = BertieStream<ServerState<Stream>>;
