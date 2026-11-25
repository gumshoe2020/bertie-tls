# ProVerif P1

2026-11-25: M1 pins the official ProVerif 2.05 source archive, SHA-256
4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4.
`scripts/install-proverif` built successfully inside fc-verify-hax:v17; install
output is in target/proverif/install.log. The setup action uses this same script.
No Rust, queries, replacement attributes or handwritten library edits.

`hax-driver.py typecheck-proverif` invokes the complete ProVerif analysis without
`-parse-only`. Existing analysis.pv describes queries 1, 2, 3 and 5 as expected
failures (reachability and compromised-key controls). The task explicitly says
stop on any false, so no exceptions will be inferred for these controls.
Memory search/diary tools are unavailable in this session.

M2 blocked: `cargo build --locked --features hax-pv` and pinned hax extraction
both exited 0. The regenerated lib.pvl was committed separately as 647ad41
(3263 insertions, 4578 deletions); analysis.pv was unchanged. No extracted file
was hand-edited. Full analysis via `typecheck-proverif` then failed before any
query ran, with this exact diagnostic:

```text
File "proofs/proverif/extraction/lib.pvl", line 499, characters 7-134:
Error: type std__collections__hash__map__t_HashMap_of_bitstring_bertie_tls__tls13utils__byte_types__t_Bytes_std__hash__random__t_RandomState not declared.
```

ProVerif exit 2, driver exit 1. Wall time 0.0403965 seconds; peak RSS 11272 KiB
(Linux resource.getrusage(RUSAGE_CHILDREN), including the Python driver).
Logs and runner: target/proverif/{extract.log,analysis.log,metrics.json,
analyze-local.py,extract-local.sh}. Source installation: install.log.
All seven queries have NO RESULT (input rejected), not `cannot be proved`:
1. Client handshake completion reachability.
2. Server handshake completion reachability.
3. Server authentication without a compromise exception.
4. Server authentication or certificate signing-key compromise.
5. Session-key disclosure after client completion, without a compromise exception.
6. Session-key disclosure implies earlier certificate signing-key compromise.
7. Phase-1 session-key disclosure implies earlier signing-key compromise.

Stopped under AGENTS.md's failing-check rule. No expected-results.txt, analysis
workflow or badge was added: input rejection is not a query result to baseline.
M3 and M4 remain unimplemented. Resolving the generated model incompatibility
requires a separately authorized scope; the protected model, attributes, Rust,
queries and handwritten library were not changed to work around it.
No attack trace was produced. No F* or formal-coverage run was performed: Rust,
F* proofs, measurement configuration and coverage baseline are untouched.

## 2026-11-25T15:45:13-05:00 — ProVerif P1 blocker

Authoritative P1 requires running the unchanged model and stopping on failed
checks. ProVerif 2.05 was selected from the official release site and built from
https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz;
SHA-256 4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4.
Worktree /Users/gumshoe/src/bertie-proverif; branch proofs/proverif-ci.
M1 676da96 adds the checked-source installer and setup action, and COVERAGE pins.
Pinned hax 0.4.2 / 5ccf89dd2e996c9f88f2267eaa2a64739c4ca41a with Rust
nightly-2025-11-08 built hax-pv and extracted successfully. Generated lib.pvl
committed as 647ad41 (3263 insertions, 4578 deletions); analysis.pv unchanged.

`typecheck-proverif` runs full analysis, not parse-only. Both analysis attempts
failed before evaluating any query. Exact diagnostic:

```text
File "proofs/proverif/extraction/lib.pvl", line 499, characters 7-134:
Error: type std__collections__hash__map__t_HashMap_of_bitstring_bertie_tls__tls13utils__byte_types__t_Bytes_std__hash__random__t_RandomState not declared.
```

First run wall 0.0403965 s, peak RSS 11272 KiB. Final rerun wall
0.0745970 s, peak RSS 11208 KiB (Linux RUSAGE_CHILDREN,
including driver). ProVerif exit 2 / driver exit 1. No attack trace or true/false/
cannot-be-proved result was produced; every query is unexecuted. No expected
results invented. No model, query, handwritten library, attribute or Rust fix
attempted: that needs a separate approved scope. M3/M4 not attempted after the
failed model check. Four existing queries are labelled "Should fail"; even once
the input works, the literal stop-on-any-false requirement must be reconciled
by the maintainer with those intentional controls.

All requested final-tree non-ProVerif checks passed: cargo test --locked
--workspace, scripts/test-features, cargo fmt --all -- --check, cargo clippy
--locked -- -D warnings, cargo deny check, actionlint. F*/formal-coverage kit
checks were not rerun; no Rust or proof annotations or coverage measurements
changed. Reviewer acceptance remains outstanding. No push, gh, hook bypass,
new Cargo dependencies or forbidden files changed. Memory tools unavailable.
Evidence: target/proverif/analysis{,-initial}.log, metrics{,-initial}.json,
extract.log, install.log, final-checks.txt and *-final.log.

## 2026-11-25T15:47:59-05:00 — ProVerif P1 run 2: declaration rename and new blocker

Applied only the declaration rename authorized by Dudley/Andrew on 2026-11-25:
- Old: `std__collections__hash__map__t_HashMap_of_bitstring_bertie__tls13utils__t_Bytes_std__hash__random__t_RandomState`
- New: `std__collections__hash__map__t_HashMap_of_bitstring_bertie_tls__tls13utils__byte_types__t_Bytes_std__hash__random__t_RandomState`
- Causes: 321475845a26c79ef01578d551676bb33819a7ae renamed the crate to
  bertie-tls; ad6f6db37bd603db7843a1263cb335b49290a0c6 moved Bytes to
  tls13utils::byte_types. The abstract `type X.` declaration has no definition
  to change. All other handwritten library bytes are unchanged.

The pinned ProVerif 2.05 full analysis now passes the original HashMap error
but fails before queries with:

```text
File "proofs/proverif/extraction/lib.pvl", line 2764, characters 8-30:
Error: alloc__vec__impl_1__len not defined.
```

The undefined function is called by generated
`bertie_tls__tls13utils__impl_17__len`. No existing handwritten declaration
corresponds to Vec::len: the handwritten file contains only the two type
declarations, RNG fill, repeat, boolean not and numeric ge. This cannot be
fixed by renaming an existing declaration. Stopped under run 2's explicit
rename-only boundary; no new declaration, letfun change, extracted-file edit,
Rust/attribute edit or query change attempted. Additional stale `bertie__`
references remain visible in analysis.pv; analysis has not reached them, and
no claim is made that fixing Vec::len alone would complete the model.

First run: ProVerif exit 2 / driver exit 1, wall 0.073621083 s, peak RSS
11784 KiB (Linux RUSAGE_CHILDREN, includes driver). Evidence:
`target/proverif/run2-analysis.log`, `run2-metrics.json`. No query result or
attack trace exists. All seven queries remain NO RESULT (input rejected).
M2 blocked; M3/M4 not attempted. No fabricated expected-results baseline or
CI readiness claim. Memory tools unavailable; no diary filed.

Final-source verification: cargo test --locked --workspace, all ten
scripts/test-features configurations, fmt, clippy -D warnings, cargo deny,
actionlint and git diff --check all pass. Fresh pinned-nightly hax-pv build
passes (four existing warnings). Fresh extraction could not be completed:
the run-1 wrapper requires a read-only /tools mount not present in the bare
fc-verify-hax:v17 image or configured by BERTIE_DOCKER_TOOLS in this session.
Initial wrapper failed copying /tools/cargo-home/registry; a build retry
succeeded but extraction failed with `no such command: hax`. No generated
files changed. This is an additional reproduction limitation, separate from
the reproduced ProVerif input rejection on the run-1 regenerated model.
Logs: target/proverif/run2-extract.log, run2-extract-final.log and
run2-final-checks.txt plus run2-*-final.log.

Final full-analysis rerun reproduces exactly the undefined Vec::len error:
ProVerif exit 2 / driver exit 1, wall 0.066769584 s, peak RSS 11768 KiB.
Evidence: target/proverif/analysis.log and metrics.json. None of the seven
queries ran; no false result or attack trace. F*/formal-coverage kit checks
not rerun; source/proof annotations and coverage measurements unchanged.
Independent reviewer acceptance remains outstanding.
PROVERIF-BLOCKED

## 2026-11-25T15:51:54-05:00 — ProVerif P1 run 3: length abstraction affects handshake reachability

Worktree `/Users/gumshoe/src/bertie-proverif`, branch `proofs/proverif-ci`, start
`da9e5b2`. Read both P1 prompts, prior P1 reports and the RFC plan. Run 3 permits
at most 15 new declarations / two hours, only for data functions whose exact
value does not affect any security query; crypto/authentication modelling,
reductions/equations, analysis.pv and Rust/attribute changes remain prohibited.

Fresh extraction now PASSES with
`BERTIE_DOCKER_TOOLS=/Users/gumshoe/src/bertie-toolchain`, mounted read-only at
`/tools`, using the same pinned image, tool environment and disposable Cargo
cache pattern as `scripts/verify-fstar.py`. `cargo build --locked --features
hax-pv` and `hax-driver.py extract-proverif` both exit 0. hax explicitly reports
lib.pvl unchanged; no generated-file diff or regeneration commit is needed.

Full analysis (not parse-only) still fails:

```text
File "proofs/proverif/extraction/lib.pvl", line 2764, characters 8-30:
Error: alloc__vec__impl_1__len not defined.
```

Handwritten additions: **0 of 15**. No declaration or rename was applied.
The proposed symbol would have signature `fun alloc__vec__impl_1__len(bitstring):
nat.` and originates from `Bytes::len`, `self.0.len()` in
`src/tls13utils.rs:492–493`. Its only generated caller outside its wrapper is
`server_signature_input` at lib.pvl:3799. That function checks the digest length
against 64 and returns failure when it is too large. Rust calls this helper
before both CertificateVerify verification (`tls13handshake.rs:344`) and signing
(`tls13handshake.rs:742`); the generated signing call is at lib.pvl:4279.
Consequently the length predicate controls whether a handshake can finish.
Treating it as an uninterpreted value is not established harmless to the
reachability queries (or to non-vacuity of the authentication/secrecy queries).
The symbolic hash is an abstract constructor without a length relation, so the
real-world fact that supported transcript hashes fit in 64 bytes is not present
in this model. A comparison declaration alone would not supply that fact.

Decision: stop under run 3's query-independence restriction rather than assert
an unsupported harmlessness claim. This is a conservative modelling assessment,
not an observed false query or a Rust defect. A continuation needs an explicitly
approved treatment of this guard and symbolic digest lengths. No crypto fact,
length equation, fixed return value, or removed guard was introduced. The two-hour
and declaration limits were not exhausted; the semantic boundary was reached
first. Remaining observed error list: the undefined Vec::len above. Further
errors are unknown because ProVerif stops at its first error. Prior noted stale
`bertie__` references in the protected analysis.pv remain untouched.

ProVerif 2.05 official source:
https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
SHA-256: 4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4.
ProVerif exit 2 / driver exit 1; wall 0.040426417 s,
peak RSS 11784 KiB (Linux RUSAGE_CHILDREN, includes driver).
No query result or attack trace. M2 remains blocked; M3/M4 were not implemented
and no expected-results baseline was invented.

Final-source checks PASS: cargo test --locked --workspace, all ten
scripts/test-features configurations, cargo fmt --all -- --check,
cargo clippy --locked -- -D warnings, cargo deny check, actionlint,
and git diff --check. F*/formal-coverage kit checks were not rerun; no Rust,
F* proof, coverage configuration or baseline changed. Independent reviewer
acceptance remains outstanding. No push, gh, external message, branch creation
or hook bypass. Memory tools unavailable, so no palace diary filed.
Evidence: target/proverif/run3-extract.log, run3-analysis.log,
run3-metrics.json, run3-final-checks.txt and run3-*-final.log.
PROVERIF-BLOCKED

## 2026-11-25T15:55:52-05:00 — ProVerif P1 run 4: approved hash-length abstraction

Start 757caa8, branch proofs/proverif-ci. Andrew approved the hash-length
model fix and requires completion queries 1 and 2 to return true before M3.
Replaced only server_signature_input's ProVerif body, using the existing
hax_lib::proverif::replace_body mechanism. The replacement retains Bytes::from_slice
of PREFIX_SERVER_SIGNATURE and Bytes::concat with digest; it removes only the
length-guard failure branch in the symbolic body. Both callers pass transcript
hash output, whose SHA-256/384/512 lengths are 32/48/64. Runtime Rust is unchanged.
HACL* backing sources and the unverified libcrux refinement boundary are listed
by file/commit in TRUSTED.md (Spec.Agile.Hash.fsti/.fst and Spec.Hash.Definitions.fst,
f557259007db9933442dde10aa995c1b00bd3446). Sources retained under target/proverif.
No handwritten declaration added yet. Fresh extraction, strict F* and pinned
formal-coverage v1.9.1 checks started. Results will be appended.

The final replacement uses `${Bytes::concat}(${Bytes::from_slice}(${PREFIX_SERVER_SIGNATURE}), digest)`.
These are expression antiquotations, matching the existing `Bytes::prefix`
replacement in src/tls13utils.rs. An initial use of type antiquotation `$:{...}`
failed extraction with E0223/E0747; corrected without changing model semantics.
That failed attempt is retained as run4-extract.log, successful extraction as
run4-extract-fixed.log. lib.pvl is generated only by pinned hax, never hand-edited;
diffstat: 4 insertions / 26 deletions. It drops the length wrapper/dependency and
failure branch, preserves prefix/concat, and reorders the bytes helper.

Full analysis now fails at extraction/lib.pvl:3097:
`Error: type bertie__tls13formats__handshake_data__t_HandshakeData not declared.`
ProVerif exit 2 / driver exit 1; wall 0.071852625 s, peak RSS 11656 KiB
(Linux RUSAGE_CHILDREN including driver). The stale declaration is generated from
src/tls13record.rs:212–224's existing encrypt_handshake replacement, which still
hardcodes old crate/type names, alongside interpolated current names in its peer.
Other stale hardcoded names occur in tls13formats replacements (server_hello,
encrypted_extensions, server_certificate, certificate_verify, finished) and in
analysis.pv. These are not new missing standard-library data functions. Adding an
unrelated abstract old HandshakeData type would not establish identity with the
current type and would model message/authentication logic outside run 3's limits.
Repair requires reviewed rename/interpolation fixes outside the digest helper;
no such repair was attempted in run 4. No query/analysis.pv changes or declarations.

Queries 1–7: all NO RESULT (input rejected). Thus queries 1 and 2 do not meet the
mandatory true guard. No false security result or attack trace was produced.
M2 blocked, M3/M4 not implemented, no expected-results file or ProVerif CI job.
Final source checks PASS: workspace tests, all ten feature configurations, fmt,
clippy -D warnings, cargo deny, actionlint. Exact logs under target/proverif/run4-*.
The initial concurrent F* run was deliberately discarded after correcting the
attribute syntax (its frozen source binding would be stale); a fresh final-source
strict F* run was started. Coverage/ratchet results will be appended.

### Run 4 coverage result (recorded by Claude Code continuation, 2026-11-25)
formal-coverage v1.9.1 (pinned commit b737912) run per COVERAGE.md on the final tree,
after a fresh strict F* run (all roots exit 0, run4-fstar.log). Measured first-party
security SLoC: 5084 (baseline 5078). proven-extracted 4117 (baseline 4111, +6: the new
comment and attribute lines, credited), tested 253 (unchanged), unverified 714
(unchanged, trusted 161 included). Proven share 80.96% -> 80.98%. No unit lost credit.
`write-coverage.py --check` fails only because coverage/baseline.json and COVERAGE.md
still hold the old totals (5078/4111); run4-coverage.log. Not updated here: the run
prompt forbids touching the baseline while blocked. If the replace_body is kept, the
maintainer refreshes baseline.json and COVERAGE.md from target/coverage-ci/report.json.
Blocker (unchanged): stale hardcoded `bertie__...` names in existing proverif::replace
strings (tls13record.rs encrypt_handshake, tls13formats.rs, analysis.pv). Needs a
decision to permit reviewed rename-only edits to those strings and analysis.pv.
Queries 1-7 not evaluated; vacuity guard unmet; no expected-results file or CI job.

## ProVerif P1 run 8 (Codex limit at start; Claude Code): handwritten_post.pvl cannot supply `is_some`

Start 2c2c788. Tried the approved design: `proofs/proverif/handwritten_post.pvl` containing
`letfun core_models__option__impl__is_some(o: Option) = if o = None() then false else true.`,
loaded after `extraction/lib` via a one-line addition to `typecheck-proverif`'s `-lib` list.
Result (target/proverif/run8-analysis.log, ProVerif 2.05 in fc-verify-hax:v17, exit 2, wall ~0.04 s):
`lib.pvl:4136: Error: core_models__option__impl__is_some not defined.` Unchanged from run 7.

Cause: ProVerif reads `-lib` files strictly in order, and `is_some` is *called inside* lib.pvl
(`lookup_db`, line 4136). It must therefore be defined before lib.pvl line 4136 but after lib.pvl
line 10 (`type Option.`). A file loaded after lib.pvl is too late, a file loaded before it has no
`Option`. The approved placement cannot work; this is an ordering constraint, not a typo.
Reverted both the driver edit and the new file (tree clean). Handwritten additions 0/15.

Options needing a decision (none attempted): (a) split lib.pvl is not possible (generated);
(b) declare `type Option.` in handwritten_lib.pvl and have the generated duplicate removed, which
needs a hax/extraction change; (c) rewrite `lookup_db`'s PSK condition without `Option::is_some`
(e.g. `matches!`/nested match avoiding the hax nested-wildcard bug); (d) a `proverif::replace_body`
on `lookup_db`'s PSK branch (both branches return `Err`, only the error code differs).
Queries 1-7 not evaluated; vacuity guard unmet; no expected-results file or CI job; M2-M4 not done.
