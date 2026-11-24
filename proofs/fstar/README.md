# F* proofs

CI checks the F* proofs from scratch on every run (`scripts/verify-fstar.py`):

1. hax extracts fresh F* from the Rust source (`Bertie_tls.*` modules).
2. F* verifies each module in `MODULES` strictly: no lax mode, no admits, no patches.
3. The per-module receipt goes to `target/ci-logs/fstar/` and feeds the coverage report.

`Tls13crypto.Backend` is a generated, interface-only boundary for all libcrux
calls. Its signatures use Bertie/std types and have no handwritten contracts.
Strict F* checks the remaining crypto bodies and the algorithm declarations as
separate roots; the declaration module retains the inherited derived instances.

`libcrux-models/` retains only `Libcrux_ecdsa.P256.Conversions.fsti`, an empty
namespace required by hax's implicit dependency open in the generated backend
interface. It declares no type, value, instance or crypto fact. The nine former
libcrux model interfaces are unused and removed. See TRUSTED.md for the backend
inventory and upstream verification evidence.

Proof annotations live in the Rust source (`hax_lib::requires`/`ensures`/`fstar!` and
`#[cfg(hax)]` lemmas, mainly in `src/der.rs`).

Upstream Bertie kept hand-edited snapshots (`extraction-lax`, `extraction-panic-free`) and
the patch files that produced them. They targeted the old `Bertie.*` module names, CI no
longer applied them, and they were removed; see upstream history if needed.
