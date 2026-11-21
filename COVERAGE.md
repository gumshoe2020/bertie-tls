# Formal coverage

Measured 2026-11-21 on the standalone bertie-tls workspace. Runtime source is
revision `9b55643` plus the frozen-extraction driver recorded by SHA-256 in the
retained receipt. This baseline is the initial floor; it is not evidence of an
improvement caused by the package rename or feature reorganization.

<!-- measured coverage: begin -->

| Security runtime | Lines | Share |
| --- | ---: | ---: |
| proven | 884 | 13.85% |
| tested | 746 | 11.69% |
| unverified | 4752 | 74.46% |

Total: **6382** first-party security runtime SLoC. Proven includes explicitly labelled
`proven-extracted` hax credit (884 lines); Verus proven: 0 lines.

Proof-to-code ratio: **not measured**. formal-coverage counts proof lines only for Verus proofs; the hax/F* proofs here are not counted, so the tool reports 0 proof lines. Reporting 0 would be wrong, so the ratio is left unreported (informational only; it never blocks).

<!-- measured coverage: end -->

## Meaning and limits

“Proven” here sums the tool's `proven` and `proven-extracted` runtime categories;
they remain separate in baseline.json. Extracted credit trusts hax and only the
accepted F* contracts. Safety-only contracts establish no panics/overflows under
the abstract interfaces, not TLS correctness, crypto implementation correctness
or RFC conformance. Functional contracts carry the tool's self-consistency
heuristic where applicable. Tested means syntactically referenced by tests, not
executed line coverage. Unverified in the ratchet includes trusted, bounded,
upstream-only and hazardous lines as well as the tool's unverified category.
Security classification and source spans come from formal-coverage unchanged.

The historical v1.7.1 figure was about 19.5% proven-extracted; this baseline is
13.85% (884 of 6382 lines). The two are not like-for-like and the difference has
not been fully attributed. Known differences: this denominator now includes the
restored algorithm code (about 340 lines removed in the server-only trim), the
standalone workspace crates (`bogo_shim`, `record`, the example client and server,
about 330 lines), and the renamed crate. The old v1.7 run credited zero when its
external scratch-server lock-closure audit rejected extraction; this standalone run
freezes its own committed lockfile and checks its hash before and after extraction.

Two inherited functions carry `verification_status(lax)` in Rust
(`get_psk_extensions` in `tls13formats.rs`, `XTR` in `key_schedule.rs`), which hax
extracts as `--admit_smt_queries true`. The tool treats these as escapes and flags
the affected F* modules as hazards, so their definitions get no credit. They are
inherited, not added here, and removing them needs real proofs. They will also keep
those modules hazardous until proven.

`Tls13crypto.fsti` is an interface-only F* module. F* does not print the
`Verified module:` line formal-coverage requires for it, so it is checked by
`scripts/verify-fstar.py` (blocking) and recorded in `interface-only.json`, but not
listed as a credited module in the receipt. It is trusted abstract-interface code
either way.

Proof-to-code ratio: formal-coverage v1.7.2 counts proof lines only for Verus
proofs, so it reports 0 proof lines for this hax/F* repository. We show "not
measured" rather than 0, which would wrongly suggest free proofs. Measuring F*
proof cost needs support in the tool; this is for Andrew to decide.

No historical patched/lax F* snapshots, ProVerif/SSProve models, abstract crypto
interfaces, KEM RNG glue or libcrux implementations receive Rust proof credit from
those artifacts alone. They remain trust/inventory evidence. Fresh receipts bind
Rust sources, driver, manifest, lock, all F* siblings and exact strict invocations.
Any rejected receipt or unmapped function retains zero credit; see the full report.

## Reproduction and pins

- formal-coverage commit `4031d85f178365ac350a578c8d977514a473da01`
  (the v1.7.2 source checkout; its Cargo package/version string still says `1.5.0`).
- hax `0.4.2`, source `5ccf89dd2e996c9f88f2267eaa2a64739c4ca41a`.
- Rust extraction toolchain `nightly-2025-11-08`; F* `2025.10.06`, Z3 `4.13.3`.
- Local container images: `fc-verify-hax:v17` (aarch64) and
  `fc-verify-fstar-amd64:v17`. The local tool binaries are read-only. CI installs
  the same pinned upstream hax/F* versions and source libraries.
- Target/profile/size mode and dependency fallbacks are retained in the JSON report;
  first-party source totals are independent of dependency sizing. Unknown sizes
  and every audit remain explicit, never suppressed for proof credit.

```sh
cargo build --release --locked --manifest-path /path/to/formal-coverage/Cargo.toml
# Native tools: HAX_CORE_LIBS=/pinned/hax/proof-libs/fstar
#               HAX_LIB_PROOFS=/pinned/hax/hax-lib/proofs/fstar/extraction
python3 scripts/verify-fstar.py
formal-coverage report . --fstar-log target/ci-logs/fstar/fstar.log \
  --json target/ci-logs/report.json --markdown target/ci-logs/report.md
python3 scripts/write-coverage.py target/ci-logs/report.json --check
python3 -m unittest discover -s scripts/tests -v
scripts/coverage-ratchet MERGE_BASE_BASELINE target/ci-logs/report.json DIFF
```

For the local rebuilt toolchain, prefix verification with
`BERTIE_DOCKER_TOOLS=/Users/gumshoe/src/bertie-toolchain`. It copies the project to
`target/ci-logs/fstar/workspace`, fetches locked dependencies into a disposable
cache, extracts frozen sources and checks seven strict F* roots. No proof patch,
admission, lax check or checked cache is used. The original upstream snapshots
remain in git as historical artifacts; they are not inputs to this verification.

## Ratchet and exceptions

The merge-base `coverage/baseline.json` is the floor. A proposed baseline and this
document must match the recomputed report. Unverified security lines cannot rise;
proven share cannot fall. A change intersecting security-runtime spans in either
the old or new report must strictly increase proven share. Docs/CI/test-only diffs
are exempt from the strict increase, not from the other rules. Pure source renames
are security changes and do not count as proof improvement. Use `git diff -U0`.

CI never commits baselines. The first PR has no merge-base floor until the initial
baseline has been reviewed and installed; the workflow fails closed in that case.
A maintainer must resolve the bootstrap before claiming a passing ratchet.
Andrew must enable the repository's up-to-date-branch requirement before relying
on concurrent PR checks; no settings have been changed by this work.

Only urgent security fixes may use the table below: name a full commit in the
checked range, approving maintainer, reason and restoration obligation. Human
review verifies the approval; a Markdown name cannot authenticate a maintainer.
The next change to the affected code must restore the pre-exception floor.

## Exceptions

| Commit | Approving maintainer | Reason | Restoration obligation |
| --- | --- | --- | --- |

## Badges and proof-cost guidance

Proven badge colors: below 20% red, 20–49.99% orange, 50–79.99% yellow,
80–94.99% yellowgreen, 95% and above green. Tested is blue; unverified lines are
red unless zero. Ratchet is green only after a passing check. Missing measurements
are red/unavailable. Proof cost is informational: development range 5–15,
established range 10–20, established modules above 20 require review. The project
is alpha, so `formal-coverage.toml` sets 5–15 with Andrew's reason. Out-of-range
cost produces a warning and orange badge, never a failed ratchet. Every other
proof, audit, test, check and lint remains blocking.

Main-only badge publication uses GITHUB_TOKEN and writes endpoint JSON to the
`badges` branch. No service token is needed. These files are generated only by
an authorized future workflow; nothing has been pushed or published locally.
