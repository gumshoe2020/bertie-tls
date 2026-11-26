# ProVerif model

A symbolic (Dolev–Yao) model of the bertie-tls handshake. hax generates it from the Rust
source (`hax-driver.py extract-proverif`, features `hax-pv` plus the F* feature list) into
`extraction/lib.pvl`. `extraction/analysis.pv` holds the top-level process and the queries.
`handwritten_lib.pvl` declares the crypto primitives as perfect (an attacker without the key
learns nothing) plus a few abstract helpers; every assumption is listed in TRUSTED.md,
"ProVerif model assumptions". Generated files are never edited by hand.

## The seven queries (analysis.pv order)

1. The client can finish a handshake (event reachable). Guard against a vacuous model.
2. The server can finish a handshake (event reachable). Same guard.
3. Server authentication: a client that finishes need not have a matching server finish.
   ProVerif finds an attack because the test certificate key may be compromised. Expected `false`.
4. Server authentication holds unless the certificate signing key was compromised.
5. Session-key secrecy fails when the certificate key is compromised. Expected `false`.
6. Session-key secrecy holds unless the certificate key was compromised.
7. Harvest-now-decrypt-later: later key leaks do not expose earlier sessions' keys.

For reachability queries 1 and 2 ProVerif prints `is false`, meaning the event is reachable.
`expected-results.txt` holds the result of every query; CI fails on any difference.

## Run

```sh
# Build ProVerif 2.05 (checksum pinned): scripts/install-proverif
python3 hax-driver.py extract-proverif      # regenerate; git diff must be empty
python3 scripts/check-proverif              # run and compare with expected-results.txt
```

`hax-driver.py typecheck-proverif` runs ProVerif once and prints its output. Handwritten
declarations are matched to generated names by ProVerif itself: a stale name is a
"not declared" error, so the CI job already fails on it. `scripts/check-proverif-renames`
guards the rename-only edits listed in `renames.txt`.

## What it does not prove

- Only the symbolic model: no computational security, no side channels, no timing.
- Crypto is perfect by assumption; HACL*/libcrux correctness is a separate matter.
- Some functions are replaced or abstracted for the model (TRUSTED.md). The PSK path is
  modelled as "no PSK offered".
- It models a few handshake configurations, not every parser or extension; parsing of untrusted
  input is covered by the F* proofs, not here.
- A passing run says nothing about Rust code that `hax-pv` does not extract.
