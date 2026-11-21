#!/usr/bin/env python3
"""Update committed coverage numbers from a measured report; never invent credit."""
import argparse
import json
from pathlib import Path
from coverage_metrics import snapshot

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('report', type=Path)
p.add_argument('--check', action='store_true', help='verify baseline and numeric document are current')
a = p.parse_args()
r = json.loads(a.report.read_text())
b = snapshot(r)
encoded = json.dumps(b, indent=2, sort_keys=True) + '\n'
start = '<!-- measured coverage: begin -->'
end = '<!-- measured coverage: end -->'
proven_pct = b['proven'] / b['total'] * 100
rows = []
for key in ['proven', 'tested', 'unverified']:
    rows.append(f"| {key} | {b[key]} | {100*b[key]/b['total']:.2f}% |")
ratio = 'n/a' if b['proof_ratio'] is None else f"{b['proof_ratio']:.2f}"
section = start + '\n\n| Security runtime | Lines | Share |\n| --- | ---: | ---: |\n' + '\n'.join(rows)
section += f"\n\nTotal: **{b['total']}** first-party security runtime SLoC. Proven includes explicitly labelled\n`proven-extracted` hax credit ({b['statuses'].get('proven-extracted',0)} lines); Verus proven: {b['statuses'].get('proven',0)} lines.\n"
if not b['proof_sloc']:
    section += "\nProof-to-code ratio: **not measured**. formal-coverage counts proof lines only for Verus proofs; the hax/F* proofs here are not counted, so the tool reports 0 proof lines. Reporting 0 would be wrong, so the ratio is left unreported (informational only; it never blocks).\n"
else:
    section += f"\nProof-cost inventory: **{b['proof_sloc']} proof SLoC / {b['proven']} proven runtime SLoC = {ratio}**.\n"
    section += '\n| Module | Proven runtime | Inventoried proof SLoC | Proof / proven runtime |\n| --- | ---: | ---: | ---: |\n'
for mod in (r['proof_ratio']['modules'] if b['proof_sloc'] else []):
    units = [u for u in r['units'] if u['first_party'] and u['security'] and u['category']=='runtime' and u['module']==mod['module'] and u['crate_name']==mod['crate_name']]
    proven = sum(u['runtime_sloc'] for u in units if u['status'] in ('proven', 'proven-extracted'))
    val = f"{mod['proof_sloc']/proven:.2f}" if proven else 'n/a'
    if units or mod['proof_sloc']:
        section += f"| {mod['crate_name']}::{mod['module']} | {proven} | {mod['proof_sloc']} | {val} |\n"
section += '\n' + end
baseline = Path('coverage/baseline.json')
page = Path('COVERAGE.md')
text = page.read_text()
updated = text[:text.index(start)] + section + text[text.index(end)+len(end):]
if a.check:
    if baseline.read_text() != encoded or text != updated:
        p.error('baseline.json or COVERAGE.md differs from measured report')
    print('coverage baseline and document match measurement')
else:
    baseline.parent.mkdir(exist_ok=True)
    baseline.write_text(encoded)
    page.write_text(updated)
    print(f'coverage: proven={b["proven"]} tested={b["tested"]} unverified={b["unverified"]} proven_share={proven_pct:.4f}% ratio={ratio}')
