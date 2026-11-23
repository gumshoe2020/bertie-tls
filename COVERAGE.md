# Formal coverage

Measured 2026-11-21 on the standalone bertie-tls workspace. Runtime source is
revision `9b55643` plus the frozen-extraction driver recorded by SHA-256 in the
retained receipt. This baseline is the initial floor; it is not evidence of an
improvement caused by the package rename or feature reorganization.

**Re-baselined for formal-coverage v1.7.3 (2026-11-21).** The tool changed, not the
code: v1.7.2 counted Rust doc comments (`///`, `//!`) as code, because the Rust lexer
turns them into `#[doc]` attributes. v1.7.3 skips them. On the same source and the same
F* receipt, the security denominator fell from 6,382 to 5,818 lines (564 doc-comment
lines, matched by an independent count), no unit changed tier and no unit grew.
Proven moved from 884 (13.85%) to 824 (14.16%), and tested from 746 (11.69%) to
548 (9.42%), because the proven and tested functions carried many doc lines
(e.g. `server`: 73 to 20 lines). Full comparison: formal-coverage
`dev/v173/compare.md` at tag v1.7.3.

**Re-baselined for formal-coverage v1.8.1 (2026-11-21).** Again the tool changed, not the
code. v1.8 counts hax/F* proof: `hax_lib` annotations move out of the runtime count, and
v1.8.1 classifies `#[cfg(hax)]` items (the DER lemmas in `src/der.rs`, which only exist for
F* checking and are never compiled) as proof code instead of runtime. On the same source and
an identical F* receipt, security runtime fell from 5,818 to 5,309 lines and proven from 824
(14.16%) to 549 (10.34%); no unit outside those rules changed tier or size. The proven share
fell because lemma code was previously counted as proven runtime; the lower figure is the
honest one. The drop is recorded under Exceptions. Full comparison: formal-coverage
`dev/v181/compare.md` at tag v1.8.1.

**Re-measured with formal-coverage v1.8.2 (2026-11-22).** The tool changed, not the code, and
this time the share went up. v1.8.1 marked every function carrying a ProverIf-only attribute
(`proverif::replace`, `replace_body`, or `opaque` under `cfg_attr(feature = "hax-pv")`) as
trusted, although the F* extraction keeps and checks the real Rust body. It also never matched
hax's `impl_<Type>__<method>` names, so no impl method could be credited. On identical source
and F* receipt, proven moved from 791 (14.90%) to 1,079 (20.33%) lines. 40 methods now link to
interface-only F* declarations and are trusted, which is the same rule free functions follow.
ProverIf attributes are still listed, as non-F* trust, in the full report. Full comparison:
formal-coverage `dev/v182/compare.md` at tag v1.8.2.

<!-- measured coverage: begin -->

| Security runtime | Lines | Share |
| --- | ---: | ---: |
| proven | 2761 | 52.16% |
| tested | 343 | 6.48% |
| unverified | 2189 | 41.36% |

Total: **5293** first-party security runtime SLoC. Proven includes explicitly labelled
`proven-extracted` hax credit (2761 lines); Verus proven: 0 lines.

Proof-to-code ratio: **0.20** (558 proof SLoC / 2761 proven + proven-extracted runtime SLoC); informational, never blocking.

Proof components: 293 hax annotation SLoC, 217 standalone `cfg(hax)` proof-code SLoC, and 61 inline `cfg(hax)` SLoC (overlaps count once). F* models: 18 SLoC of trusted assumptions, excluded from the ratio.

| Module | Proven runtime | Proof SLoC | Proof / proven runtime |
| --- | ---: | ---: | ---: |
| bertie_tls::der | 147 | 296 | 2.01 |
| bertie_tls::server | 24 | 0 | 0.00 |
| bertie_tls::tls13api | 16 | 0 | 0.00 |
| bertie_tls::tls13api::Client | 68 | 0 | 0.00 |
| bertie_tls::tls13api::Server | 63 | 0 | 0.00 |
| bertie_tls::tls13cert | 0 | 16 | n/a |
| bertie_tls::tls13crypto::Algorithms | 0 | 13 | n/a |
| bertie_tls::tls13crypto::HashAlgorithm | 0 | 1 | n/a |
| bertie_tls::tls13formats | 834 | 71 | 0.09 |
| bertie_tls::tls13formats::Extensions | 8 | 0 | 0.00 |
| bertie_tls::tls13formats::Transcript | 53 | 1 | 0.02 |
| bertie_tls::tls13formats::handshake_data | 94 | 4 | 0.04 |
| bertie_tls::tls13formats::handshake_data::HandshakeData | 76 | 13 | 0.17 |
| bertie_tls::tls13handshake | 708 | 1 | 0.00 |
| bertie_tls::tls13keyscheduler | 201 | 0 | 0.00 |
| bertie_tls::tls13keyscheduler::key_schedule | 181 | 0 | 0.00 |
| bertie_tls::tls13record | 0 | 6 | n/a |
| bertie_tls::tls13utils | 288 | 106 | 0.37 |
| bertie_tls::tls13utils::<constC:usize>From<&[u8 ; C]>forBytes | 0 | 1 | n/a |
| bertie_tls::tls13utils::<constC:usize>From<[u8 ; C]>forBytes | 0 | 1 | n/a |
| bertie_tls::tls13utils::Bytes | 0 | 26 | n/a |
| bertie_tls::tls13utils::From<&[u8]>forBytes | 0 | 1 | n/a |
| bertie_tls::tls13utils::core::ops::Index<Range<usize>>forBytes | 0 | 1 | n/a |

<!-- measured coverage: end -->

The `tls13utils` bodies are now extracted and checked by strict F*, including
byte conversion, length encoding, bounds and equality helpers. The four affected
caller roots also verify, using checked length guards for unbounded inputs and
stronger length postconditions. Numeric impl-method mappings still receive no
coverage credit; no mapping workaround was used. `from_hex` and `random_bytes`
remain excluded and unproven, and the byte type declarations retain six inherited
derived-trait assumptions in their declaration-only module.


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

Client PSK construction and its false lax truncation claim have been removed;
PSK now fails closed in both `client_hello` and server `lookup_db`.
`Tls13formats` no longer shares a module with that false claim or the
assumed derived-trait declarations for `AlertLevel`, `AlertDescription` and
`ContentType`. Those declarations now live in the declaration-only
`Tls13formats.Wire_types` module, which remains a hazard. The coverage gain
comes from existing proofs becoming separately measurable, not from new
proofs. No proof annotations were added.

`Tls13keyscheduler.Key_schedule` now has no derived-trait assumptions; those
remaining after hiding Debug from hax live in the declaration-only
`Tls13keyscheduler.Key_names` module, which remains a hazard. The credit gain
comes from proofs that already existed (strict XTR and the rest of the module)
being separated from trusted declarations, not from new proofs. The same
separation now applies to `Tls13formats.Handshake_data` and `Server`: their
derived-trait assumptions live in declaration-only
`Tls13formats.Handshake_type` and `Server.Server_db`. Both declaration
modules remain hazards; the logic modules contain no assumed instances.
Separation alone earned nothing for these two, because neither was a strict
F* root: F* loaded them only as dependencies and did not check their bodies.
They are now strict roots, so their existing extracted code is checked in full
for the first time. That is where the gain from 730 to 791 proven lines comes
from. No new proof annotations were added. F* verifies
XTR strictly, but formal-coverage still leaves its extracted `v_XTR` unmapped,
so that function receives no runtime proof credit.

`Tls13crypto.fsti` is an interface-only F* module. F* does not print the
`Verified module:` line formal-coverage requires for it, so it is checked by
`scripts/verify-fstar.py` (blocking) and recorded in `interface-only.json`, but not
listed as a credited module in the receipt. It is trusted abstract-interface code
either way.

Proof-to-code ratio: formal-coverage v1.8 measures hax/F* proof (annotations,
`cfg(hax)` proof code), so the ratio above is measured, not estimated. About 200 of
the 509 proof lines are annotations on functions F* does not yet verify, so the
ratio flatters the verified code somewhat.

No historical patched/lax F* snapshots, ProVerif/SSProve models, abstract crypto
interfaces, KEM RNG glue or libcrux implementations receive Rust proof credit from
those artifacts alone. They remain trust/inventory evidence. Fresh receipts bind
Rust sources, driver, manifest, lock, all F* siblings and exact strict invocations.
Any rejected receipt or unmapped function retains zero credit; see the full report.

## Reproduction and pins

- formal-coverage commit `ff72a88` (private) / `4f85c8e313bbeaa969f6cd0365e8a98908d9acc8`
  (public tag v1.8.2, identical tree; CI uses the public commit; version string `1.8.2`).
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
cache, extracts frozen sources and checks fifteen strict F* roots. No proof patch,
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

## Badges

On main, `coverage.yml` writes shields.io endpoint JSON to the `badges` branch
(`proven`, `tested`, `unverified`, `proof-ratio`, `ratchet`) using only the default
`GITHUB_TOKEN`. Colors are set by plain thresholds and are not tuned to look good:

| Badge | Color rule |
| --- | --- |
| proven | red below 25%, orange 25–50%, yellow 50–75%, green 75–90%, bright green 90% and up |
| unverified | bright green below 10% of security lines, green below 25%, yellow below 50%, orange below 75%, red above |
| tested | blue (informational: referenced by tests, not executed coverage) |
| proof/code | informational, never red: grey `n/a` when not measured, bright green inside 5–15, yellow outside |
| ratchet | green pass, red fail |

## Exceptions

An urgent security fix may skip the ratchet only if a maintainer lists the exact
40-character commit here, with the approver and what restores the ratchet. The only
entry so far is not a security fix: it is a one-time exception Andrew approved for a
tool measurement change, with the reason in the row.

| Commit | Approving maintainer | Reason | Restoration obligation |
| --- | --- | --- | --- |
| df7732434fc8321d4b688e46379e93da5fdecace | Andrew VanLoo | formal-coverage v1.8.1 moved cfg(hax) lemmas out of the runtime count. The measurement changed, not the code: the DER lemmas in `src/der.rs` only exist for F* checking and were previously counted as proven runtime, so proven share fell from 14.16% to 10.34% on identical source and F* receipt. | None: no code regressed. The v1.8.1 measurement is the new floor. |

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
