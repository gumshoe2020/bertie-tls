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

**Re-measured with formal-coverage v1.8.3 and v1.8.4 (2026-11-24).** The tool changed, not
the code, in two steps. v1.8.3 strips the `v_` prefix hax adds to Rust names that start with
an uppercase letter, so F*-checked `XTR`, `XPD`, `U8`, `U16` and `U32` are now credited:
proven moved from 3,635 to 3,776 lines on identical source and F* receipt. v1.8.4 adds a
`[ship]` setting, set here to the `bertie-tls` library with default features. Code that does
not ship (`benches`, `bogo_shim`, `record`, the example client and server, integration tests
and test helpers: 16 files, 324 security lines, none proven) leaves both sides of the share
but stays listed under Not shipped in the full report. Tests anywhere in the workspace still
count as evidence for shipped code. Every shipped unit kept its tier and size. Combined:
proven 3,635 of 5,402 (67.29%) to 3,776 of 5,078 (74.36%). Full comparisons: formal-coverage
`dev/v183/compare.md` at tag v1.8.3 and `dev/v184/compare.md` at tag v1.8.4.

**Re-measured with formal-coverage v1.8.5 (2026-11-24).** The tool changed, not the code.
hax names methods in numbered inherent impl blocks `impl_<N>__method`, and the tool could not
match those to Rust, so their F* proofs earned no credit. v1.8.5 maps a numbered group to an
impl block only when the module's whole method set selects exactly one block and the F* text
names that block's type; trait impls and ambiguous groups stay unmapped, and interface-only
methods stay trusted. 39 units in `tls13crypto` (`Algorithms`, `HashAlgorithm`,
`AeadAlgorithm`), `tls13formats` (`ContentType`) and `tls13utils` (`Bytes`, `AppData`) moved
to proven; no unit lost a tier. Proven 3,776 to 4,027 of 5,078 (74.36% to 79.30%). Full comparison: formal-coverage
`dev/v185/compare.md` at tag v1.8.5.

**Re-measured with formal-coverage v1.9.1 (2026-11-25).** The tool changed, not the code.
F* already checked these bodies strictly, but hax names them in five forms the tool could not
match to Rust: a trailing `_` after a final digit (`next_keys_c_2_`), trait instance records
(`impl KeySchedule<TLSnames> for TLSkeyscheduler`, `Clone for CertificateKey`,
`From<Bytes> for AppData`), the same records with bodies in the `.fsti` (Alert `try_from`,
`Index<usize> for Bytes`), and an empty type segment (`impl__new` for `ServerDB::new`). Each
maps only when exactly one Rust candidate fits. Interface-record bodies stay trusted, not
proven, although a canary showed F* rejects a broken body there. `aead_encrypt`,
`aead_decrypt` and `tlserr` have feature-flag twins and stay unmapped, because the F* receipt
does not record the extraction's feature set. 15 units changed and none lost a tier: proven
4,027 to 4,111 of 5,078 (79.30% to 80.96%), trusted 118 to 161, unverified 652 to 553; the
rendered table counts trusted with unverified (770 to 714). Full comparison: formal-coverage
`dev/v191/compare.md` at tag v1.9.1.

**Re-measured with formal-coverage v1.11.0 (2026-11-25).** The tool changed, not the code.
v1.11.0 reports what each proof establishes. A postcondition that only states lengths or
integer ranges now counts as safety-only, and a functional contract that is checked only
against first-party runtime code is labelled as such. No unit changed tier, status or size:
proven stays 4,125 of 5,092 (81.01%) and the proof ratio stays 0.14. The v1.11.0 Proof depth table
splits the proven lines: 92.39% safety-only, 5.70% functional but checked only against
own code, 1.92% functional. Full comparison: formal-coverage `dev/v1110/compare.md` at tag
v1.11.0.

Current measured tables (including module ratios and proof depth) live in
[COVERAGE-MEASURED.md on coverage-data](https://github.com/gumshoe2020/bertie-tls/blob/coverage-data/COVERAGE-MEASURED.md).
That page describes the most recently published measurement; overlapping main
runs may finish out of order. Exact commit measurements are in
`baselines/<full-sha>.json` on the same branch. The historical measurements
in this document explain earlier changes and are not the current floor.

The `tls13utils` bodies are now extracted and checked by strict F*, including
byte conversion, length encoding, bounds and equality helpers. The four affected
caller roots also verify, using checked length guards for unbounded inputs and
stronger length postconditions. Numeric impl-method mappings still receive no
coverage credit; no mapping workaround was used. `from_hex` and `random_bytes`
remain excluded and unproven, and the byte type declarations retain six inherited
derived-trait assumptions in their declaration-only module.

`Tls13record` is now a strict F* root. Its extracted code was already complete, but
F* loaded it only as a dependency of the handshake and never checked its bodies.
One proof obligation failed: the `concat` length bound in `encrypt_record_payload`.
The record header is now built with `bytes`, whose length postcondition F* can see
through the module interface, and a runtime check that the AEAD output is exactly
plaintext plus tag bounds the ciphertext without adding a trusted AEAD length fact.
Proven moves from 2,761 to 3,026 lines; no new proof annotations were added.


**tls13cert (2026-11-23).** tls13cert bodies extracted and proven; parser now checks offsets
and lengths against the buffer. Proven moves from 3,026 to 3,332 lines (57.16% to 62.89%);
the module no longer carries an assumed instance, and the proof-to-code ratio is 0.15.

**tls13crypto (2026-11-24).** tls13crypto bodies extracted and proven behind a thin libcrux
backend; short AEAD ciphertexts and malformed NIST KEM points are now rejected without panicking.
Proven moves from 3,332 to 3,635 lines (62.89% to 67.29%); the proof-to-code ratio is 0.16.

## Meaning and limits

“Proven” here sums the tool's `proven` and `proven-extracted` runtime categories;
they remain separate in each recorded baseline. Extracted credit trusts hax and only the
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

`Tls13crypto` is now a strict F* body root: algorithm tables, length checks,
encoding, configuration validation and the extracted name parser are checked
against the existing contracts. Fixed-byte encodings use the proved
`Bytes::from_slice` length guarantee. The generated, contract-free
`Tls13crypto.Backend` interface is the libcrux trust boundary; its implementation
and excluded RNG/algorithm glue remain trusted. The declaration-only
`Tls13crypto.Algorithm_types` root retains 25 inherited derived-trait assumptions,
while the parent crypto body has none. Nine unused libcrux models were removed;
the remaining file provides only an empty namespace required by hax. These proofs
establish safety and the stated length contracts, not cryptographic correctness.

Proof-to-code ratio: formal-coverage v1.8 measures hax/F* proof (annotations,
`cfg(hax)` proof code), so the reported ratio is measured, not estimated. About 200 of
the 509 proof lines are annotations on functions F* does not yet verify, so the
ratio flatters the verified code somewhat.

No historical patched/lax F* snapshots, ProVerif/SSProve models, abstract crypto
interfaces, KEM RNG glue or libcrux implementations receive Rust proof credit from
those artifacts alone. They remain trust/inventory evidence. Fresh receipts bind
Rust sources, driver, manifest, lock, all F* siblings and exact strict invocations.
Any rejected receipt or unmapped function retains zero credit; see the full report.

**formal-coverage v1.12.0 (2026-11-26).** Measurement is unchanged. Two ratchet changes: the
ratchet is enforced explicitly (`enforce-ratchet: 'true'` in coverage.yml, because 1.12.0 reports
without enforcing by default), and a change to security code at equal proven share now passes if it
raises the number of proven lines with functional contracts. That rule applies once main has a
coverage record written by 1.12.0, which the first main run after this change provides.

**formal-coverage v1.12.1 (2026-11-26).** Measurement and ratchet rules are unchanged. The ratchet
now refuses to run on a checkout with uncommitted changes, including untracked files git doesn't
ignore, because it compares the base to HEAD while measuring the files on disk. Commit before
running it locally. CI's hax checkout (`hax-src/`) is git-ignored for this reason.

**formal-coverage v1.12.3 (2026-11-26).** Three changes. (1) Test code is identified only by structural
evidence (built-in `#[test]`/`#[bench]`, `#[cfg(test)]`, or a test target); other attributes named `test` are
measured as runtime. This is a measurement change; bertie-tls's numbers are unchanged by it. (2) Main's coverage
record now stores each unit's status, which allows a deletion-only share drop (see AGENTS.md rule 1) once main has
a record written by 1.12.3. (3) A failing ratchet prints its reason as the last line of the CI output.

**formal-coverage v1.12.4 (2026-11-26).** Test scope follows `#[path]` module files and no longer trusts a
bare `#[test]` that an import could shadow. These are measurement changes; bertie-tls's numbers are unchanged.

## Reproduction and pins

- formal-coverage v1.12.4, public commit `04bfae9bdeef910980313061b8c8b425c1efb563`.
  All three shared CI actions pin this commit, which also pins the measurement tool.
- ProVerif `2.05`, official source
  `https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz`,
  SHA-256 `4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4`.
  Built by `scripts/install-proverif` and `.github/actions/setup-proverif`.
- hax `0.4.2`, source `5ccf89dd2e996c9f88f2267eaa2a64739c4ca41a`.
- Rust extraction toolchain `nightly-2025-11-08`; F* `2025.10.06`, Z3 `4.13.3`.
- Local container images: `fc-verify-hax:v17` (aarch64) and
  `fc-verify-fstar-amd64:v17`. The local tool binaries are read-only. CI installs
  the same pinned upstream hax/F* versions and source libraries.
- Target/profile/size mode and dependency fallbacks are retained in the JSON report;
  first-party source totals are independent of dependency sizing. Unknown sizes
  and every audit remain explicit, never suppressed for proof credit.

```sh
mkdir -p target/coverage-ci
cargo build --release --locked --manifest-path /path/to/formal-coverage/Cargo.toml \
  > target/coverage-ci/kit-build.log 2>&1
# Native tools: HAX_CORE_LIBS=/pinned/hax/proof-libs/fstar
#               HAX_LIB_PROOFS=/pinned/hax/hax-lib/proofs/fstar/extraction
FSTAR_JOBS=1 python3 scripts/verify-fstar.py > target/coverage-ci/fstar.log 2>&1
# /path/to/formal-coverage must be the public commit pinned above.
git fetch origin refs/heads/coverage-data:refs/remotes/origin/coverage-data
python3 /path/to/formal-coverage/ci/run.py \
  --tool /path/to/formal-coverage/target/release/formal-coverage \
  --workspace "$PWD" --report-args '["--fstar-log","target/ci-logs/fstar/fstar.log"]' \
  --config coverage/ci.json \
  --base "$(git merge-base origin/main HEAD)" --output "$PWD/target/coverage-ci" \
  > target/coverage-ci/runner.log 2>&1
python3 -m unittest discover -s /path/to/formal-coverage/ci/tests -v \
  > target/coverage-ci/kit-tests.log 2>&1
```

For the local rebuilt toolchain, prefix verification with
`BERTIE_DOCKER_TOOLS=/Users/gumshoe/src/bertie-toolchain`. It copies the project to
`target/ci-logs/fstar/workspace`, fetches locked dependencies into a disposable
cache, extracts frozen sources and checks eighteen strict F* roots. No proof patch,
admission, lax check or checked cache is used. The original upstream snapshots
remain in git as historical artifacts; they are not inputs to this verification.

### What CI caches

- `hax.yml` (pass/fail gate) caches F*'s per-module `.checked` files. Pull requests may read the cache; only a
  push to `main` writes it. The key binds the hax commit, F* and Z3 versions, the hash of
  `scripts/verify-fstar.py` and the hash of the extraction inputs (`src/**`, `Cargo.toml`, `Cargo.lock`,
  `hax-driver.py`, `proofs/fstar/libcrux-models/**`), and F* re-checks any module whose own digest or
  whose dependencies' digests differ. hax extraction is never cached.
- `coverage.yml` is never cached. formal-coverage v1.11.0 rejects `--cache_checked_modules`, any `.checked`
  file in the receipt scope, and any module without its own fresh `Verified module:` line (F* prints that line
  even when it loads a module from the cache), so cached results cannot be honest evidence.
  `scripts/verify-fstar.py --cache-dir DIR` therefore writes no `fstar.log.evidence.json`.
- `proverif.yml` also succeeds quickly on unrelated PRs. Its separate input policy covers Rust/workspace
  manifests, Cargo configuration/toolchain/build scripts, `hax-driver.py`, `proofs/proverif/**` (including
  handwritten libraries, extraction and expected results), `scripts/{install,check}-proverif`, both setup
  actions, its workflow and the detector/tests. F*-only inputs are unrelated; unknown paths run the job.
  Pushes to main and dispatch always run ProVerif.
- `hax.yml` succeeds quickly, with a log line, on a pull request that changes nothing F* reads
  (`scripts/ci-changes.py`: docs and unrelated workflows only; every other path counts). Pushes, the nightly
  schedule and manual dispatch always run. Coverage is never skipped.
- To force an uncached run: start `hax` from the Actions tab (`workflow_dispatch`) with `no_cache` ticked. The
  nightly schedule is always uncached. Locally, omit `--cache-dir` (the default).

## Ratchet and exceptions

The floor is `baselines/<merge-base-full-sha>.json` on `coverage-data` (on a main
push, the base is the push event's `before` commit). The coverage action fetches
that branch and fails closed if the record is missing or invalid. For adoption only,
`coverage/ci.json` sets `bootstrap_baseline`: while the data branch holds no
`baselines/*.json`, the floor is `coverage/baseline.json` read from the merge-base
commit (not the PR's tree). Once main's first push has recorded a baseline it is
ignored, and a follow-up PR removes the setting. The local runner requires the data
branch to have been fetched first; it does not fetch automatically.

Unverified security lines cannot rise; proven share cannot fall. A change
intersecting security-runtime spans in either the old or new report must strictly
increase proven share. Docs/CI/test-only diffs are exempt from the strict increase,
not from the other rules. Pure source renames are security changes and do not
count as proof improvement. The pinned kit uses `git diff -U0` and exact rational
comparisons, unchanged from committed-floor mode.

PRs no longer commit `coverage/baseline.json` or a measured section in this document;
recorded mode skips both committed-output equality checks. What stays committed:
`formal-coverage.toml` (measurement scope/settings), `coverage/ci.json` (floor mode
and data branch), this policy, historical explanations, tool pins and the
`## Exceptions` table. Change a tool version and its pin together; there is no
requirement to bundle version changes with measured numbers in one commit.

Every main push publishes the completed measurement append-only as
`baselines/<sha>.json` and refreshes `COVERAGE-MEASURED.md` on `coverage-data`.
Publication runs even if the ratchet failed, so the actual measured main state is
recorded and the failure stays visible. A failed measurement has no record to
publish and publication fails. The publisher rejects a different existing SHA
record, never forces and never commits to main. Its job alone has `contents: write`
for baseline publication; GitHub's token scope is repository-wide, while the
pinned action restricts its pushes to the configured data branch. Badge publication
retains its separate write job restricted by its action to `badges`.

Andrew must enable the repository's up-to-date-branch requirement or a merge queue
before relying on concurrent PR checks. No repository settings are changed here.

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
40-character commit here, with the approver and what restores the ratchet. Neither
entry so far is a security fix: both are one-time exceptions Andrew approved where
proof-only code stopped being counted as runtime, with the reason in the row.

| Commit | Approving maintainer | Reason | Restoration obligation |
| --- | --- | --- | --- |
| df7732434fc8321d4b688e46379e93da5fdecace | Andrew VanLoo | formal-coverage v1.8.1 moved cfg(hax) lemmas out of the runtime count. The measurement changed, not the code: the DER lemmas in `src/der.rs` only exist for F* checking and were previously counted as proven runtime, so proven share fell from 14.16% to 10.34% on identical source and F* receipt. | None: no code regressed. The v1.8.1 measurement is the new floor. |
| 9647b63667628d1409c40a90682f9fb4cee42577 | Andrew VanLoo | Eight DER spec items (`two_pow_256`, `be_value_prefix`, `be_value`, `der_sig_valid`, `encoder_correct`, `parser_sound`, `parser_complete`, `der_sig_unique`) are used only by hax contracts, lemmas and proof tests, so they now compile only under cfg(hax). 60 lines moved from proven runtime to proof code with no change to shipped code: proven share fell from 81.01% to 80.78%, while functional proofs rose from 1.92% to 3.57%. Approved 2026-11-25: "We improved the honesty of the tool, which is a worthwhile exception." | None: no code regressed. The post-gating measurement is the new floor. |

## Badges and proof-cost guidance

The shared kit's default badge set, labels and thresholds match the Badges table
above exactly; no badge overrides are needed in `coverage/ci.json`, which selects
the recorded floor. The measurement settings remain in `formal-coverage.toml`. See the pinned kit's `ci/README.md` for its action inputs
and local runner. The kit now owns the generic ratchet, writers and their tests.
Proof cost is informational: development range 5–15, established range 10–20;
established modules above 20 require review. The project is alpha, so
`formal-coverage.toml` sets 5–15 with Andrew's reason. Out-of-range cost produces
a warning and yellow badge, never a failed ratchet. Every other proof, audit,
test, check and lint remains blocking.

Main-only badge publication uses GITHUB_TOKEN and writes endpoint JSON to the
`badges` branch. No service token is needed. These files are generated only by
an authorized future workflow; nothing has been pushed or published locally.
