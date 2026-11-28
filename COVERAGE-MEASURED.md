<!-- measured coverage: begin -->

| Security runtime | Lines | Share |
| --- | ---: | ---: |
| proven | 4107 | 81.04% |
| tested | 251 | 4.95% |
| unverified | 710 | 14.01% |

Total: **5068** first-party security runtime SLoC. Proven includes explicitly labelled
`proven-extracted` hax credit (4107 lines); Verus proven: 0 lines.

Proof-to-code ratio: **0.33** (1372 proof SLoC / 4107 proven + proven-extracted runtime SLoC); informational, never blocking.

Proof components: 948 hax annotation SLoC, 353 standalone `cfg(hax)` proof-code SLoC, and 353 inline `cfg(hax)` SLoC (overlaps count once). F* models: 1 SLoC of trusted assumptions, excluded from the ratio.

| Module | Proven runtime | Proof SLoC | Proof / proven runtime |
| --- | ---: | ---: | ---: |
| bertie_tls::der | 90 | 364 | 4.04 |
| bertie_tls::server | 31 | 0 | 0.00 |
| bertie_tls::server::ServerDB | 13 | 0 | 0.00 |
| bertie_tls::tls13api | 16 | 0 | 0.00 |
| bertie_tls::tls13api::Client | 68 | 0 | 0.00 |
| bertie_tls::tls13api::Server | 63 | 0 | 0.00 |
| bertie_tls::tls13cert | 306 | 45 | 0.15 |
| bertie_tls::tls13cert::CloneforCertificateKey | 3 | 0 | 0.00 |
| bertie_tls::tls13crypto | 298 | 6 | 0.02 |
| bertie_tls::tls13crypto::AeadAlgorithm | 16 | 0 | 0.00 |
| bertie_tls::tls13crypto::AeadKey | 3 | 0 | 0.00 |
| bertie_tls::tls13crypto::AeadKeyIV | 3 | 0 | 0.00 |
| bertie_tls::tls13crypto::Algorithms | 115 | 13 | 0.11 |
| bertie_tls::tls13crypto::HashAlgorithm | 12 | 2 | 0.17 |
| bertie_tls::tls13crypto::backend | 0 | 28 | n/a |
| bertie_tls::tls13formats | 834 | 71 | 0.09 |
| bertie_tls::tls13formats::ContentType | 9 | 0 | 0.00 |
| bertie_tls::tls13formats::Extensions | 8 | 0 | 0.00 |
| bertie_tls::tls13formats::Transcript | 53 | 1 | 0.02 |
| bertie_tls::tls13formats::handshake_data | 94 | 4 | 0.04 |
| bertie_tls::tls13formats::handshake_data::HandshakeData | 76 | 13 | 0.17 |
| bertie_tls::tls13handshake | 714 | 1 | 0.00 |
| bertie_tls::tls13keyscheduler | 237 | 489 | 2.06 |
| bertie_tls::tls13keyscheduler::key_schedule | 304 | 129 | 0.42 |
| bertie_tls::tls13keyscheduler::key_schedule::KeySchedule<TLSnames>forTLSkeyscheduler | 45 | 0 | 0.00 |
| bertie_tls::tls13keyscheduler::key_schedule::TLSkeyscheduler | 28 | 22 | 0.79 |
| bertie_tls::tls13record | 252 | 6 | 0.02 |
| bertie_tls::tls13record::DuplexCipherStateH | 13 | 0 | 0.00 |
| bertie_tls::tls13utils | 301 | 125 | 0.42 |
| bertie_tls::tls13utils::<constC:usize>From<&[u8 ; C]>forBytes | 0 | 1 | n/a |
| bertie_tls::tls13utils::<constC:usize>From<[u8 ; C]>forBytes | 0 | 1 | n/a |
| bertie_tls::tls13utils::AppData | 9 | 0 | 0.00 |
| bertie_tls::tls13utils::Bytes | 90 | 44 | 0.49 |
| bertie_tls::tls13utils::From<&[u8]>forBytes | 0 | 5 | n/a |
| bertie_tls::tls13utils::From<Bytes>forAppData | 3 | 0 | 0.00 |
| bertie_tls::tls13utils::From<Vec<u8>>forBytes | 0 | 1 | n/a |
| bertie_tls::tls13utils::core::ops::Index<Range<usize>>forBytes | 0 | 1 | n/a |

### Proof depth

| Contract depth | Lines | Share of proven lines |
| --- | ---: | ---: |
| safety-only | 3628 | 88.34% |
| functional, checked only against own code | 209 | 5.09% |
| functional | 270 | 6.57% |

Safety-only means proven free of panics, overflows and out-of-bounds access, including length and range facts; it says nothing about what the code computes.

<!-- measured coverage: end -->
