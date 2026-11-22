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
The PSK code below is therefore unreachable, but it is wrong and must be
fixed against RFC 8448 before PSK is ever re-enabled (ask in an issue first,
per AGENTS.md).

- `pre_shared_key` (`src/tls13formats.rs`, used by `get_psk_extensions`)
  derives the ClientHello truncation length from hard-coded offsets
  (`+ 199 - 16 - 82`), correct only for a 16-byte server name; the parser
  computes `ch.len() - hash_len - 3`. Binder offsets disagree otherwise.
- `process_psk_binder_zero_rtt` (`src/tls13handshake.rs`) shadows the
  received binder with the server's own derived value, so `hmac_verify`
  compares that value with itself and any client binder is accepted.

Failing regression tests for both live on branch `fix/psk-trunc-len`; they
are not on main because they fail by design until the fix lands.
