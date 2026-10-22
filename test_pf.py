#!/usr/bin/env python3
"""Manual macOS pf diagnostic. Changes pf.conf temporarily; run with sudo."""
import os
from pathlib import Path
import shlex
from subprocess import run, PIPE
import sys
import tempfile

PF_CONF = Path('/etc/pf.conf')


def cmd(argv):
    print(f"$ {shlex.join(argv)}")
    result = run(argv, stdout=PIPE, stderr=PIPE, text=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    for line in result.stderr.strip().splitlines():
        if 'ALTQ' not in line and 'flushing' not in line.lower():
            print(f'  [err] {line}')
    return result


def main():
    print('PF DIRECT BLOCK TEST (no anchor)')
    original = PF_CONF.read_bytes()
    # A fixed /tmp/pf.conf.backup can be replaced with a symlink before a root
    # run. Keep a private recovery copy until both file and rules are restored.
    with tempfile.NamedTemporaryFile(prefix='arpcut-pf-', suffix='.conf',
                                     delete=False) as recovery:
        recovery.write(original)
        recovery.flush()
        os.fsync(recovery.fileno())
        backup = Path(recovery.name)
    print(f'Recovery copy: {backup}')

    try:
        PF_CONF.write_bytes(b'block drop quick on en0 from any to 8.8.8.8\n' + original)
        if cmd(['pfctl', '-f', str(PF_CONF)]).returncode:
            raise RuntimeError('Could not load diagnostic firewall rule')
        cmd(['pfctl', '-s', 'rules'])
        result = cmd(['ping', '-c', '1', '-t', '2', '8.8.8.8'])
        if result.returncode:
            print('Ping failed while the rule was active; connectivity failure can also cause this.')
        else:
            print('Ping succeeded while the rule was active.')
    finally:
        # Includes Ctrl+C and exceptions during testing. Keep the private
        # recovery file if restoring the file or the live rules fails.
        try:
            PF_CONF.write_bytes(original)
            if cmd(['pfctl', '-f', str(PF_CONF)]).returncode:
                raise RuntimeError('Could not reload original firewall rules')
        except BaseException:
            print(f'Restore incomplete; original config remains at {backup}', file=sys.stderr)
            raise
        else:
            backup.unlink()
            print('Original firewall configuration restored.')


if __name__ == '__main__':
    if sys.platform != 'darwin':
        raise SystemExit('This diagnostic is only supported on macOS.')
    if os.geteuid() != 0:
        raise SystemExit('Run with: sudo python3 test_pf.py')
    main()
