# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for mask_passwords.py.

Every secret in the sample files contains the word LEAK, so a sanitized copy
passes when that word no longer appears in it. Run with:  python tests/run_tests.py
"""
import hashlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'mask_passwords.py'
SAMPLES = ROOT / 'tests' / 'samples'
FAILURES = []


def run(args, cwd):
    p = subprocess.run([sys.executable, '-I', str(SCRIPT)] + [str(a) for a in args], cwd=str(cwd),
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    return p.returncode, p.stdout + p.stderr


def check(name, condition, detail=''):
    print(('PASS  ' if condition else 'FAIL  ') + name + ('' if condition else '  ' + detail))
    if not condition:
        FAILURES.append(name)


def outputs(folder, tag):
    return sorted(p for p in folder.iterdir() if tag in p.name)


def text(p):
    return p.read_text(encoding='utf-8', errors='replace')


def test_samples(tmp):
    work = tmp / 'samples'
    shutil.copytree(SAMPLES, work)
    originals = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in work.iterdir()}
    files = sorted(p.name for p in work.iterdir() if p.name != 'personal.conf')
    code, out = run(files, work)
    check('samples: exit code 0', code == 0, out[-500:])
    sanitized = outputs(work, '_SANITIZED')
    check('samples: one sanitized copy per file with secrets', len(sanitized) == len(files) - 1,
          '%d copies for %d files' % (len(sanitized), len(files)))
    leaks = [p.name for p in sanitized if 'LEAK' in text(p)]
    check('samples: no LEAK left in any copy', not leaks, ', '.join(leaks))
    check('samples: file without secrets gets _NO-SECRETS-FOUND',
          (work / 'plain_NO-SECRETS-FOUND.conf').exists())
    check('samples: plain file copied unchanged',
          (work / 'plain_NO-SECRETS-FOUND.conf').read_bytes() == (work / 'plain.conf').read_bytes())
    fw = text(work / 'fortiweb-script_SANITIZED.conf')
    check('samples: public certificate kept', 'BEGIN CERTIFICATE' in fw and 'MIIBpublicCERTOK' in fw)
    check('samples: user:password@host masked', 'backupuser:REDACTED@192.0.2.53' in fw)
    changed = [n for n, h in originals.items() if hashlib.sha256((work / n).read_bytes()).hexdigest() != h]
    check('samples: originals never modified', not changed, ', '.join(changed))
    code, out = run(['cisco.conf'], work)
    check('samples: existing copy never overwritten', len(outputs(work, 'cisco_SANITIZED')) == 2, out[-300:])


def test_personal(tmp):
    work = tmp / 'personal'
    work.mkdir()
    shutil.copy(SAMPLES / 'personal.conf', work)
    code, out = run(['--personal', 'personal.conf'], work)
    copy = work / 'personal_ANONYMIZED.conf'
    check('personal: anonymized copy created', copy.exists(), out[-500:])
    if not copy.exists():
        return
    body = text(copy)
    for real in ('LEAK', 'john.smith', 'jane.doe', 'Jane', 'Doe', 'example.com', '7946', '5550123'):
        check('personal: "%s" removed' % real, real not in body)
    check('personal: generic account kept', 'username admin' in body)
    check('personal: BGP AS number kept', 'router bgp 4200000001' in body)
    check('personal: consistent placeholders in group members', 'set member "USER_' in body)
    maps = outputs(work, 'PERSONAL-DATA-MAP')
    check('personal: local map file created', len(maps) == 1)
    if maps:
        check('personal: map links placeholders to real values', 'john.smith' in text(maps[0]))


def test_rejections(tmp):
    work = tmp / 'reject'
    work.mkdir()
    (work / 'fake.zip').write_bytes(b'PK\x03\x04not really a zip')
    (work / 'binary.cfg').write_bytes(b'abc\x00\x01\x02' * 50)
    code, out = run(['fake.zip', 'binary.cfg'], work)
    check('reject: exit code 1', code == 1)
    check('reject: archive message', 'compressed archive' in out, out[-300:])
    check('reject: binary message', 'binary or encrypted' in out, out[-300:])
    check('reject: nothing written', not outputs(work, '_SANITIZED'))


def test_fortinet_multipart(tmp):
    work = tmp / 'multipart'
    work.mkdir()
    sep = b'-------FV-VMB-8.08-FW-build0000-000000-------2026-01-01 00:00:00' + b'-' * 36
    cfg = (b'config system global\n  set admin-password LEAKadmin\nend\nconfig system automation-action\n'
           b'  edit "b"\n    set script "execute backup full-config sftp a/b.conf bck:LEAKsftp@192.0.2.1:22"\n'
           b'  next\nend\n')

    def block(name, kind, enc, comp, content):
        return (b'[file]\nname=%s\ndomain=global\ntype=%s\nencrypt=%s\ncompress=%s\n' % (name, kind, enc, comp)
                + sep + b'\n' + content + sep + b'\n[/file]\n')
    raw = (b'[header]\nmagic=ABCDEFGH\nversion=1.4\nmodel=FV-VMB\nprivate_key=LEAKheader\ntype=full_config\n'
           b'file_number=2\nfile_split=' + sep + b'\n\n[/header]\n'
           + block(b'/data/config/sys_global.conf.gz', b'config', b'no', b'no', cfg)
           + block(b'/tmp/extend_tar_file', b'extend', b'yes', b'gzipped', bytes(range(256)) * 20 + b'LEAKbin'))
    (work / 'fwb_system.conf').write_bytes(raw)
    code, out = run(['fwb_system.conf'], work)
    copy = work / 'fwb_system_SANITIZED.conf'
    check('multipart: copy created', copy.exists(), out[-500:])
    if copy.exists():
        data = copy.read_bytes()
        check('multipart: no LEAK left', b'LEAK' not in data)
        check('multipart: binary block omitted', b'[binary block omitted' in data and b'\x00' not in data)
        check('multipart: block listed in report', 'Block OMITTED' in out)


def test_zip(tmp):
    work = tmp / 'zip'
    work.mkdir()
    with zipfile.ZipFile(work / 'configs.zip', 'w') as z:
        z.write(SAMPLES / 'zyxel.conf', '../../outside/zyxel.conf')
        z.write(SAMPLES / 'netgear-m4300.cfg', 'switches/netgear-m4300.cfg')
    code, out = run(['configs.zip'], work)
    copies = outputs(work, '_SANITIZED')
    check('zip: one copy per file inside', len(copies) == 2, out[-500:])
    check('zip: no LEAK left', all('LEAK' not in text(p) for p in copies))
    check('zip: nothing written outside the folder', not (tmp / 'outside').exists())
    check('zip: originals never extracted', not (work / 'switches').exists() and not (work / 'zyxel.conf').exists())


def test_3cx(tmp):
    work = tmp / '3cx'
    work.mkdir()
    db = ('<?xml version="1.0" encoding="utf-8"?>\n<PhoneSystem>\n <Extension>\n'
          '  <AuthID>LEAKauthid</AuthID>\n  <AuthPassword>LEAKauthpw</AuthPassword>\n  <VMPIN>LEAK12</VMPIN>\n'
          '  <DNProperty>\n   <Name>DESKPHONE_PASSWORD</Name>\n   <Type>String</Type>\n'
          '   <Value>LEAKdesk</Value>\n  </DNProperty>\n'
          '  <DNProperty>\n   <Name>SIPINTERFACEIP</Name>\n   <Type>String</Type>\n'
          '   <Value>192.0.2.10</Value>\n  </DNProperty>\n'
          '  <Settings>&lt;PhoneDeviceSettings Secret="LEAKsecret"&gt;&lt;Password&gt;LEAKesc&lt;/Password&gt;'
          '&lt;/PhoneDeviceSettings&gt;</Settings>\n </Extension>\n <licensekey>LEAK-LICENSE</licensekey>\n'
          '</PhoneSystem>\n')
    with zipfile.ZipFile(work / '3CXScheduledBackup.zip', 'w') as z:
        z.writestr('1234Db.xml', db)
        z.writestr('DbTables/cdr.csv', 'caller,callee\n+15555550100,+15555550101\n')
        z.writestr('recordings/call.wav', b'RIFF0000WAVE')
    code, out = run(['3CXScheduledBackup.zip'], work)
    copies = outputs(work, '_SANITIZED')
    check('3cx: only the configuration is written', len(copies) == 1, out[-500:])
    if copies:
        body = text(copies[0])
        check('3cx: no LEAK left', 'LEAK' not in body)
        check('3cx: technical setting kept', '192.0.2.10' in body)
    check('3cx: skipped folders listed', 'Skipped: DbTables' in out and 'Skipped: recordings' in out)


def main():
    tmp = Path(tempfile.mkdtemp(prefix='mask-passwords-tests-'))
    try:
        for test in (test_samples, test_personal, test_rejections, test_fortinet_multipart, test_zip, test_3cx):
            print('--- ' + test.__name__)
            test(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    print('%d check(s) failed' % len(FAILURES) if FAILURES else 'All checks passed')
    sys.exit(1 if FAILURES else 0)


if __name__ == '__main__':
    main()
