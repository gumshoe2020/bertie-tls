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
