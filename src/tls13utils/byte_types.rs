use super::U8;
use crate::std::vec::Vec;

/// Bytes used in Bertie.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Bytes(pub(super) Vec<U8>);

#[derive(PartialEq)]
pub struct AppData(pub(super) Bytes);
