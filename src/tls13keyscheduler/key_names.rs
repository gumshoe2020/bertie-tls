#[derive(Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(not(hax), derive(Debug))]
#[allow(clippy::upper_case_acronyms)]
pub enum TLSnames {
    ES,
    EEM,
    CET,
    Bind,
    Binder,
    HS,
    SHT,
    CHT,
    HSalt,
    AS,
    RM,
    CAT,
    SAT,
    EAM,
    PSK,

    ZeroSalt, // 0
    ESalt,
    KEM,
    ZeroIKM, // 0^len(alg)
}

#[derive(PartialEq, Eq)]
#[cfg_attr(not(hax), derive(Debug))]
#[allow(non_camel_case_types)]
#[allow(clippy::just_underscores_and_digits)]
pub(crate) enum Label {
    ____________,
    RES_BINDER__,
    EXT_BINDER__,
    C_E_TRAFFIC_,
    E_EXP_MASTER,
    EXP_MASTER__,
    RES_MASTER__,
    C_HS_TRAFFIC,
    S_HS_TRAFFIC,
    DERIVED_____,
    C_AP_TRAFFIC,
    S_AP_TRAFFIC,
    RESUMPTION__,
}
