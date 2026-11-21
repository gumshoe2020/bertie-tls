# Maintained Bertie trust boundary

Updated 2026-11-21 (stage 19 E).

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
