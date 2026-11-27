# Third-party specification structure

The TLS HKDF label grammar and key-schedule derivation structure in
`src/tls13keyscheduler/rfc8446_spec.rs` are adapted from project-everest/mitls-fstar,
commit `9a75fa8c46e50897b1f43002885d25a34dfa929a`. Per-item file/line citations
are retained in that source. Only the structure is ported; no miTLS proof
assumptions or verification status are imported.

Copyright 2015 INRIA and Microsoft Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this material except in compliance with the License.
You may obtain a copy of the License at
<http://www.apache.org/licenses/LICENSE-2.0>.
Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

The repository's Apache-2.0 license is retained in LICENSE.

## HACL* and KaRaMeL specification interfaces

`proofs/fstar/hacl-specs/` holds unedited copies of HACL* specification files
(hacl-star/hacl-star, commit `f557259007db9933442dde10aa995c1b00bd3446`) and one
KaRaMeL file, `Spec.Loops.fst` (FStarLang/karamel, commit
`bd2d4fa8a61344042c7cd7a31013d72bfe4568ce`, used under its Apache-2.0 option).
File list, upstream paths and SHA-256s are in `proofs/fstar/hacl-specs/README.md`.
They name the RFC 5869 functions used by the approved HKDF link (TRUSTED.md).

HACL*: Copyright the HACL* contributors (INRIA, Microsoft Corporation and others).
KaRaMeL: Copyright 2015-2016 Jonathan Protzenko and Microsoft Research.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use these files except in compliance with the License.
You may obtain a copy of the License at
<http://www.apache.org/licenses/LICENSE-2.0>.
Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
