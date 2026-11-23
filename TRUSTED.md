# Maintained Bertie trust boundary

Updated 2026-11-22.

The F* protocol checks use the existing abstract cryptographic interface; they do
not prove libcrux implementations, entropy, or correspondence to that interface.

`src/tls13crypto.rs::non_hax` is deliberately excluded from hax extraction.
`KemRng` forwards rand 0.9 CryptoRng to rand_core 0.10 TryCryptoRng through
try_next_u32, try_next_u64 and try_fill_bytes (infallible, same caller RNG).
The key_gen and encapsulate wrappers keep the new trait instances entirely
inside this boundary, avoiding an unresolved implicit open in the extracted
crypto interface. These five functions are trusted compatibility glue, not
proven items. They preserve libcrux errors, output and randomness source.
Retained-group handshake and key-share/shared-secret tests exercise the wiring.
Algorithms::validate is also trusted configuration-rejection glue.
No proof item, assumption, or generated proof patch is changed by this repair.

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
