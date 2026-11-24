#!/usr/bin/env python3
"""Fresh extraction + strict per-module F* receipts. No patched models or cached proofs.

Native CI: set HAX_CORE_LIBS and HAX_LIB_PROOFS to the pinned hax source dirs.
Local reproduction: BERTIE_DOCKER_TOOLS=/Users/gumshoe/src/bertie-toolchain.
All build products and logs stay under target/ci-logs/fstar.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'target/ci-logs/fstar'
HAX_COMMIT = '5ccf89dd2e996c9f88f2267eaa2a64739c4ca41a'
MODULES = ['Der.fst', 'Server.Server_db.fst', 'Server.fst', 'Tls13api.fst', 'Tls13crypto.fsti',
           'Tls13formats.Wire_types.fst', 'Tls13formats.Handshake_data.fst', 'Tls13formats.Handshake_type.fst', 'Tls13formats.fst',
           'Tls13handshake.fst', 'Tls13keyscheduler.Key_names.fst',
           'Tls13keyscheduler.Key_schedule.fst', 'Tls13keyscheduler.fst', 'Tls13record.fst',
           'Tls13utils.Byte_types.fst', 'Tls13utils.fst']


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(command, log, **kw):
    with log.open('wb') as f:
        return subprocess.run(command, stdout=f, stderr=subprocess.STDOUT, **kw).returncode


def inventory(base):
    return {str(p.relative_to(OUT)): digest(p) for p in sorted(base.rglob('*'))
            if p.suffix in ('.fst', '.fsti')}


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    ws = OUT / 'workspace'
    # Only project inputs. Never carry old generated extraction or build artefacts.
    files = subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
    for name in files:
        p = ROOT / name
        if p.is_file() and not name.startswith(('target/', 'coverage/')):
            dest = ws / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dest)
    extraction = ws / 'proofs/fstar/extraction'
    for p in extraction.iterdir():
        if p.is_file() and p.suffix in ('.fst', '.fsti', '.checked', '.lax', '.hints'):
            p.unlink()
    tools = os.environ.get('BERTIE_DOCKER_TOOLS')
    common = []
    if tools:
        common = ['docker', 'run', '--rm', '--cpus', '4', '--memory', '5g',
                  '-v', f'{tools}:/tools:ro', '-v', f'{ROOT}:{ROOT}', '-w', str(ws)]
        # The toolchain stays read-only; Cargo writes only inside this checkout.
        cargo_home = OUT.parent / 'fstar-cargo-home'
        if not cargo_home.exists():
            cargo_home.mkdir()
            subprocess.run(['docker', 'run', '--rm', '-v', f'{tools}:/tools:ro',
                            '-v', f'{OUT.parent}:/out', 'fc-verify-hax:v17', 'sh', '-c',
                            'cp -R /tools/cargo-home/registry /out/fstar-cargo-home/'], check=True)
        prefix = ('export PATH=/tools/hax:/tools/rust-install/bin:$PATH; '
                  'export LD_LIBRARY_PATH=/tools/rust-install/lib:/tools/rust-install/lib/rustlib/aarch64-unknown-linux-gnu/lib; '
                  'export HOME=/tools/home RUSTUP_HOME=/tools/rustup RUSTUP_TOOLCHAIN=nightly-2025-11-08; '
                  f'export CARGO_HOME={cargo_home}; ')
        cmd = common + ['fc-verify-hax:v17', 'bash', '-ec', prefix + 'cargo fetch --locked && python3 hax-driver.py extract-fstar']
    else:
        # Fetch locked dependencies (including git sources) before the --frozen extraction.
        cmd = ['bash', '-ec', 'cargo fetch --locked && python3 hax-driver.py extract-fstar']
    lock_before = digest(ws / 'Cargo.lock')
    rc = run(cmd, OUT / 'extract.log', cwd=ws)
    if rc or lock_before != digest(ws / 'Cargo.lock'):
        print(f'extraction failed (exit={rc}) or Cargo.lock drifted; see {OUT / "extract.log"}', file=sys.stderr)
        return 1
    fresh = OUT / 'fresh'
    shutil.copytree(extraction, fresh, ignore=shutil.ignore_patterns('*.checked', '.cache', '.hints'))
    libs = OUT / 'libs'
    if tools:
        source = Path(tools) / 'source' / f'hax-{HAX_COMMIT}'
        shutil.copytree(source / 'proof-libs/fstar/core', libs / 'core')
        shutil.copytree(source / 'proof-libs/fstar/rust_primitives', libs / 'rust_primitives')
        shutil.copytree(source / 'hax-lib/proofs/fstar/extraction', libs / 'hax-lib')
    else:
        source = Path(os.environ['HAX_CORE_LIBS'])
        shutil.copytree(source / 'core', libs / 'core')
        shutil.copytree(source / 'rust_primitives', libs / 'rust_primitives')
        shutil.copytree(Path(os.environ['HAX_LIB_PROOFS']), libs / 'hax-lib')
    shutil.copytree(ws / 'proofs/fstar/libcrux-models', libs / 'libcrux-models')
    # Pinned sources may be read-only (e.g. a Nix store path); copytree keeps
    # those modes, so make the copies owner-writable before pruning them.
    for p in [libs, *libs.rglob('*')]:
        p.chmod(p.stat().st_mode | 0o200)
    for p in libs.rglob('*'):
        if p.is_file() and p.suffix not in ('.fst', '.fsti'):
            p.unlink()
    includes = [str(p.relative_to(OUT)) for p in [libs / 'rust_primitives', libs / 'core', libs / 'hax-lib', libs / 'libcrux-models', fresh]]
    modules = []
    def verify(suffix):
        file = f'fresh/Bertie_tls.{suffix}'
        command = ['fstar.exe']
        for inc in includes:
            command += ['--include', inc]
        command += [file]
        name = Path(file).name
        if tools:
            executable = common[:-2] + ['-w', str(OUT), '--platform', 'linux/amd64', '--network', 'none',
                          'fc-verify-fstar-amd64:v17', 'bash', '-ec',
                          'export PATH=/tools/fstar-bin-2025.10.06/fstar/bin:/tools/fstar-bin-2025.10.06/fstar/lib/fstar/z3-4.13.3/bin:$PATH; exec "$@"', 'proof'] + command
        else:
            executable = command
        rc = run(executable, OUT / f'{name}.log', cwd=OUT)
        result = dict(file=file, command=command, exit_code=rc,
                      outcome='success' if rc == 0 else 'failed')
        print(f'{name}: exit {rc}', flush=True)
        return result
    # Modules verified in parallel. Default 2 keeps local runs light; CI sets
    # FSTAR_JOBS to the runner's CPU count. Only scheduling changes, never what is checked.
    jobs = int(os.environ.get('FSTAR_JOBS', '2'))
    if jobs < 1:
        raise ValueError('FSTAR_JOBS must be at least 1')
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        modules = list(pool.map(verify, MODULES))
    combined = OUT / 'fstar.log'
    combined.write_bytes(b'\n'.join((OUT / f'Bertie_tls.{m}.log').read_bytes() for m in MODULES))
    bound = {name: digest(ws / name) for name in files if (ROOT / name).is_file()
             and (name.endswith('.rs') or name in ('Cargo.toml', 'Cargo.lock', 'hax-driver.py'))}
    if any(digest(ROOT / name) != sha for name, sha in bound.items()):
        raise RuntimeError('project source changed during verification; rerun before claiming credit')
    receipt = dict(tool='hax-fstar', hax_version='0.4.2', hax_commit=HAX_COMMIT,
                   fstar_version='2025.10.06', extraction_command=['python3', 'hax-driver.py', 'extract-fstar'],
                   extraction_exit_code=0, files=bound, fresh=inventory(fresh),
                   checked={**inventory(fresh), **inventory(libs)}, patches={},
                   log_sha256=digest(combined),
                   modules=[m for m in modules if not m['file'].endswith('.fsti')])
    (OUT / 'fstar.log.evidence.json').write_text(json.dumps(receipt, indent=2) + '\n')
    # formal-coverage only accepts "Verified module:" output, which F* does not print for an
    # interface-only module. It stays a blocking check here but is not claimed in the receipt.
    interfaces = [m for m in modules if m['file'].endswith('.fsti')]
    (OUT / 'interface-only.json').write_text(json.dumps(interfaces, indent=2) + '\n')
    return int(any(m['exit_code'] != 0 for m in modules))


if __name__ == '__main__':
    sys.exit(main())
