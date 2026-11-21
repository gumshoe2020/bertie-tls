<img src="assets/bertie-logo.png" width="200px"/>

# bertie-tls

A small TLS 1.3 library in Rust, maintained independently from Cryspen’s Bertie.
This project started from [Cryspen/Bertie](https://github.com/cryspen/bertie)
commit `ef65f76`, under Apache-2.0. Upstream copyright notices and [LICENSE](LICENSE) are retained.

[![CI](https://github.com/gumshoe2020/bertie-tls/actions/workflows/ci.yml/badge.svg)](https://github.com/gumshoe2020/bertie-tls/actions/workflows/ci.yml)
[![Proofs](https://github.com/gumshoe2020/bertie-tls/actions/workflows/hax.yml/badge.svg)](https://github.com/gumshoe2020/bertie-tls/actions/workflows/hax.yml)
[![Coverage](https://github.com/gumshoe2020/bertie-tls/actions/workflows/coverage.yml/badge.svg)](https://github.com/gumshoe2020/bertie-tls/actions/workflows/coverage.yml)
[![proven](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fgumshoe2020%2Fbertie-tls%2Fbadges%2Fproven.json)](COVERAGE.md)
[![tested](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fgumshoe2020%2Fbertie-tls%2Fbadges%2Ftested.json)](COVERAGE.md)
[![unverified](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fgumshoe2020%2Fbertie-tls%2Fbadges%2Funverified.json)](COVERAGE.md)
[![proof-ratio](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fgumshoe2020%2Fbertie-tls%2Fbadges%2Fproof-ratio.json)](COVERAGE.md)
[![ratchet](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fgumshoe2020%2Fbertie-tls%2Fbadges%2Fratchet.json)](COVERAGE.md)

Proof credit is limited to the checked contracts. Safety-only extraction proofs do not establish
TLS correctness, cryptographic security or correspondence to RFC 8446. This is alpha software.
Read [COVERAGE.md](COVERAGE.md) and [TRUSTED.md](TRUSTED.md) before relying on it.
Badges appear after an authorized main workflow publishes them; no badge branch is created locally.

## Use

The package is `bertie-tls`; the Rust library is `bertie_tls`.
Default features: `api`, `std`, `defensive`, `client`, `chacha20poly1305`, `ecdsa-p256`,
`rsa`, `ed25519`, `x25519`, `p256`, `mlkem768`, `sha256`, `sha384`, `sha512`.
Each algorithm can be disabled. Algorithm features require `std`.
AES, the obsolete Kyber draft, unsupported curves, PSK and 0-RTT are unavailable.
Ed25519 restores the upstream primitive; TLS certificate negotiation remains unsupported.

A minimal server dependency uses:

```toml
bertie-tls = { path = ".", default-features = false, features = [
  "api", "std", "defensive", "sha256", "chacha20poly1305", "ecdsa-p256",
  "x25519", "p256", "mlkem768"
] }
```

Use `bertie_tls::Server`; opt into `client` for `bertie_tls::Client`.
The `simple_https_client` and `simple_https_server` workspace crates contain examples.

## Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md), the approved [AGENTS.md](AGENTS.md) policy,
and the [code of conduct](CODE_OF_CONDUCT.md).

### PUBLICATIONS

Bertie is inspired by a number of prior research works, including works on [hacspec] and TLS 1.3.

Some of the most relevant publications are listed below:

* *Hacspec: succinct, executable, verifiable specifications for high-assurance cryptography embedded in Rust.* Denis Merigoux, Franziskus Kiefer, Karthikeyan Bhargavan.  Inria Technical Report, 2021. [hal-03176482](https://hal.inria.fr/hal-03176482)
* *Verified Models and Reference Implementations for the TLS 1.3 Standard Candidate.* Karthikeyan Bhargavan, Bruno Blanchet, Nadim Kobeissi.  38th IEEE Symposium on Security and Privacy, 2017. [hal-01575920](https://hal.inria.fr/hal-01575920)
* *A Messy State of the Union: Taming the Composite State Machines of TLS.* Benjamin Beurdouche, Karthikeyan Bhargavan, Antoine Delignat-Lavaud, Cédric Fournet, Markulf Kohlweiss, Alfredo Pironti, Pierre-yves Strub, Jean Karim Zinzindohoue. IEEE Symposium on Security & Privacy, 2015. [hal-01114250](https://hal.inria.fr/hal-01114250/)

### LICENSE

Bertie is licensed under [Apache 2.0](LICENSE).

### ACKNOWLEDGEMENTS

The Bertie project is supported by [Inria] and the [nlnet foundation].

[project tasks]: https://github.com/orgs/cryspen/projects/2/views/2
[code of conduct]: CODE_OF_CONDUCT.md
[contributing guidelines]: CONTRIBUTING.md
[hacspec]: https://github.com/hacspec/hacspec
[F*]: https://www.fstar-lang.org/
[Cryspen]: https://www.cryspen.com/
[Inria]: https://www.inria.fr
[nlnet foundation]: https://nlnet.nl/project/Bertie/
