# Vendored HACL* specification interfaces (unedited)

These files give F* the names used by the one approved HKDF link
(TRUSTED.md, "HKDF link to HACL* (assumed, approved by Andrew 2026-11-26)").
They are copied byte for byte, with no edits, and are Apache-2.0 (THIRD_PARTY.md).
`scripts/verify-fstar.py` adds this directory to the F* include path; F* loads
them as dependencies only. No bertie proof module is checked against anything
here except through the declared postcondition on `backend::hkdf_expand_okm`.

The set is the minimum closure needed for a client to typecheck against
`Spec.Agile.HKDF.expand` (found by adding missing modules until a probe client
typechecked with the pinned F* 2025.10.06). HKDF and HMAC are vendored as
interfaces only. Their definitions (RFC 5869) are upstream in
`specs/Spec.Agile.HKDF.fst` and `specs/Spec.Agile.HMAC.fst` at the same commit,
where HACL* verifies them; with those definitions the closure is 30 files.

HACL*: https://github.com/hacl-star/hacl-star, commit
`f557259007db9933442dde10aa995c1b00bd3446`.
KaRaMeL (HACL*'s pinned dependency, from HACL*'s `flake.lock`; `Spec.Loops` is
referenced by `Spec.Agile.HMAC.fsti`): https://github.com/FStarLang/karamel,
commit `bd2d4fa8a61344042c7cd7a31013d72bfe4568ce`.

| File | Repository | Upstream path | SHA-256 |
| --- | --- | --- | --- |
| `Spec.Agile.HKDF.fsti` | HACL* | `specs/Spec.Agile.HKDF.fsti` | `1893a50043553ae813d1647590af3f322ce714bd10d5f77b5201f4d77b75c957` |
| `Spec.Agile.HMAC.fsti` | HACL* | `specs/Spec.Agile.HMAC.fsti` | `8e5fa1ddbd7f375323852d0da6f1848dbab57f0bfadbeeeed052526db647022f` |
| `Spec.Hash.Definitions.fst` | HACL* | `specs/Spec.Hash.Definitions.fst` | `705fd3651671d106afa556edf0533e65cb0f85c6a6a45c5221859f7e1920bace` |
| `Spec.Blake2.Definitions.fst` | HACL* | `specs/Spec.Blake2.Definitions.fst` | `ceb8ac920fad76e903f508d6ab26379075e7eea494928a57e9e0c3cd5679338d` |
| `Spec.Blake2.fst` | HACL* | `specs/Spec.Blake2.fst` | `5d0e1f4bffbdeab2d8be25db927415b92be60364e30893bbe65a2b299a00e814` |
| `Lib.IntTypes.fsti` | HACL* | `lib/Lib.IntTypes.fsti` | `389792e9226efeec10da39ac3d8d69e2ec7899d915eaf52a2d32f97975c5d442` |
| `Lib.Sequence.fsti` | HACL* | `lib/Lib.Sequence.fsti` | `50174205ad8b557d85d0ef7a2b537080e9980a28149cef6147dcefe30f98d98f` |
| `Lib.ByteSequence.fsti` | HACL* | `lib/Lib.ByteSequence.fsti` | `9363b750751d5695c284d5b626ca3048fe13237d879bbeba771cdb4e676a3e0d` |
| `Lib.LoopCombinators.fsti` | HACL* | `lib/Lib.LoopCombinators.fsti` | `bfa7542f66eb4609835e4fa7c57a83e1b87240e8d90d0b93b8645e1a9f393e84` |
| `Lib.RawIntTypes.fsti` | HACL* | `lib/Lib.RawIntTypes.fsti` | `228272e576a8491b7ac0f2901260f2968cab55c09d3d0d261c87a9f81634dcc4` |
| `Lib.UpdateMulti.fst` | HACL* | `lib/Lib.UpdateMulti.fst` | `02ccd1c25919420278c6606e53105efce3b23fbca531df1b0fa00eca301adbc2` |
| `Spec.Loops.fst` | KaRaMeL | `krmllib/Spec.Loops.fst` | `17fd8ccb6edca448cb68b57f3487bbae81924c318076c730476621657c202be2` |

`grep -nE 'admit|assume|lax|magic\(|unsafe_coerce'` over these files finds nothing.
