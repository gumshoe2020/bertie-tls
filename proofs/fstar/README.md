# F* proofs

CI checks the F* proofs from scratch on every run (`scripts/verify-fstar.py`):

1. hax extracts fresh F* from the Rust source (`Bertie_tls.*` modules).
2. F* verifies each module in `MODULES` strictly: no lax mode, no admits, no patches.
3. The per-module receipt goes to `target/ci-logs/fstar/` and feeds the coverage report.

`libcrux-models/` holds hand-written F* interfaces for the libcrux crypto calls. They are
trusted assumptions, not proofs, and the coverage report lists them separately.

Proof annotations live in the Rust source (`hax_lib::requires`/`ensures`/`fstar!` and
`#[cfg(hax)]` lemmas, mainly in `src/der.rs`).

Upstream Bertie kept hand-edited snapshots (`extraction-lax`, `extraction-panic-free`) and
the patch files that produced them. They targeted the old `Bertie.*` module names, CI no
longer applied them, and they were removed; see upstream history if needed.
