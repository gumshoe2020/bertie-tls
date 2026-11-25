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
