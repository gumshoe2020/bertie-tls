# AGENTS.md — bertie-tls

Approved by Andrew, 2026-11-21.

## What this project is
bertie-tls is a small, formally verified TLS 1.3 library in Rust. It started from Cryspen's Bertie
(commit ef65f76, Apache-2.0) and is maintained independently. The goal: a TLS implementation small
enough to trust, where every line is either proven, tested, or explicitly listed as trusted with a reason.

Contributions are welcome: from people, from people working with AI agents, and from agents
working under a person's direction. This file is the rulebook for all of them.

## Scope
- In scope: TLS 1.3 (RFC 8446), client and server; the algorithms and extensions listed in
  Cargo.toml; proofs (hax/F*); tests; interop and fuzzing.
- Every algorithm and optional extension sits behind a Cargo feature. Default features are a small,
  modern set. A user who turns a feature off must get none of its code in their binary.
- Ask first, in an issue, before: new algorithms or extensions, TLS 1.2 or older, QUIC/DTLS,
  large refactors, or changes to the public API.
- Obsolete or pre-standard drafts are removed, not kept for compatibility.

## Correctness rules (no exceptions)
1. Never weaken a proof, test, check or lint to make a change pass: no `admit`, `assume`, `lax`,
   skipped or ignored tests, loosened assertions, or new cargo-deny advisory ignores. If something
   fails, stop and report it with the failing output.
2. A change to a proven module keeps its proofs passing. New parsing of untrusted input comes with
   a spec and a proof, or it is listed in TRUSTED.md with the reason it is not proven yet.
3. Parsers fail closed: unexpected input returns an error. Never panic on untrusted input.
4. Every new dependency needs a written reason in the PR. Fewer is better.
5. No secrets, keys or private data in the repo, tests or logs.

## Formal coverage (the ratchet)
Coverage of security code is measured with formal-coverage (github.com/gumshoe2020/formal-coverage),
which sorts every line of security code into proven, tested or unverified. Main records the
current numbers on `coverage-data` (`COVERAGE-MEASURED.md` and append-only `baselines/<sha>.json`).
PRs commit policy, proofs and code, not measured numbers; see COVERAGE.md.
1. No commit may increase the number of unverified security lines, or lower the proven share.
2. Every commit that touches security code must increase the proven share, by proving new or
   existing code, or, at equal proven share, increase the number of proven security lines with
   functional contracts (the two functional contract categories combined), by strengthening the
   contracts of proven code. Unverified security lines may never increase. Commits that do not
   touch security code (docs, CI, tests only) are exempt but must not lower the share.
3. Don't game it: splitting, renaming or moving code without adding proofs doesn't count as an
   improvement, and redefining what counts as security code needs maintainer approval.
4. The proof-to-code ratio (proof lines per proven code line) is reported alongside, as a
   measure of proof maintenance cost. It never blocks a commit. Guide ranges: 5–15 for code in
   development, 10–20 for established code; established modules above 20 get a review.
5. The one exception is an urgent security fix. A maintainer may approve it with a note in
   COVERAGE.md, and the next commit to that code must restore the ratchet.

## How work is done
- Small PRs, one concern each, with tests for every behaviour change.
- Run the checks below before calling anything done, and paste the summary lines into the PR.
- A reviewer reruns the checks before merging. An agent's report that it is done does not count
  as verification.
- AI disclosure: a commit or PR substantially written by an AI agent carries an
  `Assisted-by: <tool/model>` trailer. The person who directed the work is responsible for it.
  AI help is welcome; undisclosed AI help is not.
- Agents never push to `main`, tag or publish releases, change repository settings, or speak for
  the maintainers to outside parties.

## Checks
Run from the repository root. Coverage/proof commands require the pinned tools described in COVERAGE.md.
- `cargo test --locked --workspace`
- `scripts/test-features` (each algorithm alone, with defaults disabled)
- `python3 scripts/verify-fstar.py` (fresh extraction and strict F*, no admits; uncached, and the only form that
  produces a coverage receipt. `--cache-dir DIR` is an optional incremental gate for local use and the `hax` job, see COVERAGE.md)
- `python3 -m unittest discover -s scripts/tests -v` (CI scripts)
- `cargo deny check`
- `python3 -m unittest discover -s /path/to/formal-coverage/ci/tests -v` (pinned v1.12.3 kit; `cargo build --locked` it first)
- `python3 /path/to/formal-coverage/ci/run.py ...` (recorded-floor ratchet; exact invocation and pin in COVERAGE.md)
- `cargo fmt --all -- --check`
- `cargo clippy --locked --all-targets -- -D warnings` (library, tests and benches)
- `actionlint`

CI runs these on pull requests and main. A reviewer reruns acceptance checks before merge.
