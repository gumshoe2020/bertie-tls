"""Stable metric projection of a conservative formal-coverage schema-3 report."""
PROVEN = ('proven', 'proven-extracted')


def snapshot(report):
    if report['schema'] != 3 or not report['dependency_inventory_complete']:
        raise ValueError('incomplete inventory or unsupported report schema')
    if report['unparseable_files']:
        raise ValueError('unparseable files: security classification is incomplete')
    totals = report['summary']['first_party']['security_relevant']
    statuses = totals['statuses']
    total = totals['sloc']
    if total <= 0 or any(type(v) is not int or v < 0 for v in statuses.values()) or sum(statuses.values()) != total:
        raise ValueError('invalid security totals')
    proven = sum(statuses.get(k, 0) for k in PROVEN)
    tested = statuses.get('tested', 0)
    inventory = sorted([dict(file=u['file'], line=u['line'], end_line=u['end_line'])
                        for u in report['units'] if u['first_party'] and u['security']
                        and u['category'] == 'runtime'], key=lambda u: (u['file'], u['line'], u['end_line']))
    # The tool's native ratio counts Verus proven only. Preserve it verbatim;
    # also report an explicitly labelled cost ratio with extracted runtime.
    proof_sloc = report['proof_ratio']['proof_sloc']
    return dict(schema=1, scope='first-party security runtime', total=total, proven=proven,
                tested=tested, unverified=total-proven-tested, statuses=statuses,
                proof_sloc=proof_sloc, proof_ratio=(proof_sloc / proven if proven and proof_sloc else None),
                native_proof_ratio=report['proof_ratio']['ratio'], inventory=inventory)

