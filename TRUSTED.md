# Maintained Bertie trust boundary

Updated 2026-11-23.

## Cryptographic backend

`src/tls13crypto/backend.rs` is the libcrux trust boundary. hax generates its
interface from Rust; F* checks signatures only. No backend function carries a
precondition or postcondition. In particular, F* assumes no digest, ciphertext,
public-key or shared-secret length beyond the signature's fixed-size arrays.
The Rust wrappers, error translation, allocation, encoding, dependency dispatch
and correspondence to upstream crypto remain trusted. Upstream verification
claims below do not establish those wrapper properties or entropy quality.

The inventory covers all feature gates, including algorithms outside the pinned
F* extraction. Versions are resolved from Cargo.lock. Evidence was inspected in
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/` on 2026-11-23:
each named crate's README.md and src/lib.rs, plus the implementation paths below.
No upstream proof was rerun.

| Backend function | Direct libcrux crate/version | Upstream status and source evidence |
| --- | --- | --- |
| `sha2_digest` | libcrux-sha2 0.0.3 | HACL*-verified implementation; README Verification section, src/lib.rs exports impl_hacl and generated hacl code. |
| `hmac_compute` | libcrux-hmac 0.0.3 | HACL*-verified implementation; README Verification section and src/impl_hacl.rs. |
| `hkdf_extract_prk` | libcrux-hkdf 0.0.3 | HACL*-verified implementation; README Verification section and src/impl_hacl.rs. |
| `hkdf_expand_okm` | libcrux-hkdf 0.0.3 | Same evidence as hkdf_extract_prk. |
| `chacha20poly1305_seal` | libcrux-chacha20poly1305 0.0.9 | HACL*-verified ChaCha20-Poly1305 implementation; README Verification section and src/impl_hacl.rs. The README excludes XChaCha wrappers, which this backend does not call. |
| `chacha20poly1305_open` | libcrux-chacha20poly1305 0.0.9 | Same evidence as chacha20poly1305_seal. |
| `ecdsa_p256_sha256_sign` | libcrux-ecdsa 0.0.3 | HACL*-verified implementation; README Verification section, src/lib.rs describes verified P-curve ECDSA. Randomness and our signature conversion remain trusted. |
| `ecdsa_p256_sha256_verify` | libcrux-ecdsa 0.0.3 | Same upstream evidence as ecdsa_p256_sha256_sign. |
| `ed25519_sign` | libcrux-ed25519 0.0.9 | HACL*-verified implementation; README Verification section and src/lib.rs generated hacl/impl_hacl modules. |
| `ed25519_verify` | libcrux-ed25519 0.0.9 | Same evidence as ed25519_sign. |
| `rsa_pss_sha256_sign` | libcrux-rsa 0.0.2 | HACL*-verified implementation; README Verification section and src/lib.rs hacl/impl_hacl exports. Our modulus slicing and fixed signature buffer remain trusted. |
| `rsa_pss_sha256_verify` | libcrux-rsa 0.0.2 | Same upstream evidence as rsa_pss_sha256_sign. |
| `kem_generate` | libcrux-kem 0.0.10 | Verification of the KEM interface/composition is not established: README explicitly marks it pre-verification. See component evidence below. |
| `kem_encapsulate` | libcrux-kem 0.0.10 | Same status as kem_generate, including decode/encode and hybrid composition. |
| `kem_decapsulate` | libcrux-kem 0.0.10 | Same status as kem_generate. |

The KEM component claims do not upgrade the generic libcrux-kem wrapper:
libcrux-ecdh 0.0.9's README Verification section claims HACL*-verified code;
libcrux-ml-kem 0.0.11's README Verification section claims hax/F* verification
for ML-KEM (and separately calls the optional Kyber implementation unverified).
The ML-KEM README links proofs/verification_status.md, which is not shipped in
the inspected registry crate, so detailed per-function verification status is
not established here. Hybrid composition is not claimed verified.

`src/tls13crypto/backend.rs::non_hax` is deliberately excluded from hax.
Its four algorithm translators return libcrux-specific enums. `KemRng` forwards
rand 0.9 CryptoRng to rand_core 0.10 TryCryptoRng through try_next_u32,
try_next_u64 and try_fill_bytes (infallible, same caller RNG). Its key_gen and
encapsulate wrappers keep those trait instances inside the boundary. The three
RNG methods, two wrappers and four translators remain trusted compatibility
glue. Retained-group handshake and key-share/shared-secret tests exercise wiring.

The generated backend interface still opens
`Libcrux_ecdsa.P256.Conversions` as an implicit trait dependency. The sole
remaining file in `proofs/fstar/libcrux-models` supplies only that empty namespace:
no value, type, instance or cryptographic claim. The nine unused models are
removed.

Algorithms::validate is included in strict crypto body checking; it is no
longer an interface-only trusted configuration helper.

## Known defects in unreachable PSK code

Recorded 2026-11-22. PSK and 0-RTT are disabled: `Algorithms::validate`
(`src/tls13crypto.rs`) rejects `psk_mode` and `zero_rtt` on every public
entry point (`Client::connect`, `Server::accept` and the stream wrappers).
Client PSK construction (`get_psk_extensions`, `pre_shared_key` and
`psk_key_exchange_modes`) has been removed, including the false lax truncation
claim and hard-coded offsets. `client_hello` now returns
`UNSUPPORTED_ALGORITHM` for PSK mode with a ticket. The server also refuses
PSK acceptance in `lookup_db` with `UNSUPPORTED_ALGORITHM`; with PSK mode
false it continues to ignore a client's ticket.

`process_psk_binder_zero_rtt` (`src/tls13handshake.rs`) still shadows the
received binder with the server's own derived value, so `hmac_verify`
compares that value with itself and any client binder is accepted. This is
now unreachable through both public configuration validation and the server
PSK refusal in `lookup_db`. It must be fixed against RFC 8448 before PSK is
re-enabled (ask in an issue first, per AGENTS.md). The failing binder
regression lives on branch `fix/psk-trunc-len`, not on main.

## Derived-trait instances

`src/tls13crypto/algorithm_types.rs` contains declarations only: HashAlgorithm,
KemScheme, AeadAlgorithm, SignatureScheme, Algorithms, RsaVerificationKey and
PublicVerificationKey. Original paths are re-exported from tls13crypto. hax
retains 25 inherited existence-only instances: six for HashAlgorithm, five for
KemScheme, four each for AeadAlgorithm, SignatureScheme and Algorithms, and
one Debug instance each for the two verification-key types. Clone bodies are
extracted. This module is a strict root, but those assumptions remain hazards;
no behavioral property follows from an instance's mere existence. All handwritten
logic remains in tls13crypto.rs. The original opaque TryFrom instance was removed:
hax now extracts and checks the actual name parser, including its error formatting.
The existing non-hax Display implementation remains outside F* coverage.


`src/tls13keyscheduler/key_names.rs` holds declarations only: `TLSnames`
and `Label`, with their derive attributes. hax assumes the existence of
Copy, StructuralPartialEq, PartialEq, Eq and Hash instances for `TLSnames`,
and StructuralPartialEq, PartialEq and Eq instances for `Label`. These
are trusted existence-only declarations with no behavioral claims; F*
proofs cannot use any property of them. Clone is extracted as code, and
Debug is derived only outside hax. Key-schedule logic stays in
`key_schedule.rs`, separated from these trusted declarations.

`src/tls13formats/handshake_type.rs` holds the `HandshakeType` declaration
with its original `repr(u8)` and `hax-pv` opaque attributes. hax assumes
Copy, StructuralPartialEq and PartialEq instances there.
`src/server/server_db.rs` holds the `ServerDB` declaration and its fields;
hax assumes its Default instance there. Clone is extracted as code for
both types, and Debug is derived only outside hax. These are the same
trusted existence-only declarations described above. All handwritten
functions and impl blocks remain in `handshake_data.rs` and `server.rs`;
no new proofs were added. The coverage gain comes from making
`Handshake_data` and `Server` strict F* roots (see COVERAGE.md).

`src/tls13formats/wire_types.rs` holds only the `AlertLevel`,
`AlertDescription` and `ContentType` enum declarations, with their original
wire values, `repr(u8)` and doc comments. For each enum, hax assumes Copy,
StructuralPartialEq and PartialEq instances (nine instances total). Clone
is extracted as code; Debug is derived only outside hax. All handwritten
conversions, parsing and serialization stay in `tls13formats.rs`, which
re-exports the three types at their original paths. These are the same
trusted existence-only declarations described above; no new proofs were
added.

## Hexadecimal debugging constructor

`Bytes::from_hex` in `src/tls13utils.rs::non_hax` is excluded from F*
extraction. It retains its public path and signature and its existing whitespace
handling and panic behavior for invalid hex. The string iterator model required
by `split_whitespace` is unavailable in the pinned hax library. This debugging
constructor remains unproven; stream callers use it to build a constant.

## External randomness helper

`random_bytes` in `src/tls13utils.rs::non_hax` is excluded from F* extraction
and re-exported at its original public path with its signature unchanged. It
calls `rand::random`, an external OS-backed randomness effect that the pinned
hax/F* libraries cannot model (`Rand` cannot be resolved). No library function
in `src/` calls it; integration tests use it. Entropy and this helper remain
unproven; the library receives randomness as parameters.

## Byte type declarations

`src/tls13utils/byte_types.rs` contains the `Bytes` and `AppData` declarations,
re-exported at their original public paths. hax assumes StructuralPartialEq
and PartialEq for both types, plus Debug and Default for Bytes (six
existence-only instances). Clone is extracted as code; Debug for Error is
derived only outside hax. Bytes retains Debug because the extracted crypto
interface derives Debug for a type containing Bytes. All handwritten logic stays in `tls13utils.rs`, whose bodies
are extracted for strict checking rather than trusted as interface-only. The
excluded `from_hex` and `random_bytes` helpers remain unproven as described above.

## Certificate parser

`src/tls13cert.rs` is no longer interface-only: its bodies are extracted and checked in strict F*.
Every offset and length step is checked against the buffer and returns an error when the input is
too short or inconsistent. `CertificateKey` writes out `Clone` and `Copy` so hax extracts them as
code rather than as an assumed instance. Nothing in this module is listed as trusted.

## ProVerif model assumptions

P1 run 4 (Andrew approved, 2026-11-25) replaces only the ProVerif body of
`tls13handshake::server_signature_input`, via `hax_lib::proverif::replace_body`
under `cfg_attr(feature = "hax-pv")`. It preserves prefix conversion and
concatenation with the digest, and omits the `digest.len() > 64` failure branch.
Both callers supply `Transcript::transcript_hash()` output. The model assumes
that the abstract hash returns its selected algorithm's output length: SHA-256,
SHA-384 and SHA-512 produce 32, 48 and 64 bytes, respectively. Thus the omitted
branch is unreachable for these callers with the real hash implementation.
Runtime Rust and the strict F* extraction (which does not enable `hax-pv`) retain
the check. This is a symbolic-model assumption, not a new Rust/F* proof or a
checked end-to-end refinement from libcrux to HACL*.

Backing upstream specification/proof source: HACL* commit
`f557259007db9933442dde10aa995c1b00bd3446`,
[`specs/Spec.Agile.Hash.fsti`](https://github.com/hacl-star/hacl-star/blob/f557259007db9933442dde10aa995c1b00bd3446/specs/Spec.Agile.Hash.fsti)
(`hash'` returns `lbytes (hash_length' a l)`, `hash` specializes fixed lengths),
with implementation `specs/Spec.Agile.Hash.fst`. The corresponding
[`specs/Spec.Hash.Definitions.fst`](https://github.com/hacl-star/hacl-star/blob/f557259007db9933442dde10aa995c1b00bd3446/specs/Spec.Hash.Definitions.fst)
defines `hash_length`, `hash_length'`, `word_length` and `hash_word_length`, giving
the lengths above. This run inspects those sources; it does not reverify HACL*.
The replacement uses the same upstream Bertie `replace_body` mechanism already
used by `tls13crypto::sign` and `tls13formats::client_hello`.

New handwritten declarations: **0/15** (rename-only edits to existing names are listed in
`proofs/proverif/renames.txt`).

### PSK acceptance (`server::psk_offered`, 2026-11-25)

`server::psk_offered(tkt, psk_opt)` is a private helper holding the test
`tkt.is_some() && psk_opt.is_some()` from `lookup_db`. Under `hax-pv` only, its body is replaced
by `false`: the model says "no PSK offered". Reason: hax would otherwise emit
`core_models__option__impl__is_some`, which cannot be defined in ProVerif's library load order.
Effect: in the PSK branch of `lookup_db`, the model returns `PSK_MODE_MISMATCH` instead of
`UNSUPPORTED_ALGORITHM`. Both are errors and PSK acceptance is disabled in the code (fail
closed), so the queries, which exercise only the non-PSK path, are unaffected. Runtime Rust and
the strict F* extraction keep the real test. The replacement string is
`false (* PSK disabled: no PSK offered *)` because hax rewrites a bare `false` to `r#false`,
which ProVerif rejects.

### Query results

Results of the model, with these assumptions, are in `proofs/proverif/expected-results.txt`
and are checked by CI. They are symbolic results about the model, not about the whole library.
