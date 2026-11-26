# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for netblur.

Every secret in the sample files contains the word LEAK, so a sanitized copy
passes when that word no longer appears in it. Run with:  python tests/run_tests.py
"""
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'netblur.py'
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
    check('personal: one JSON map next to the copy', len(maps) == 1 and maps[0].suffix == '.json'
          and maps[0].name.startswith('personal_ANONYMIZED'))
    if maps:
        m = json.loads(text(maps[0]))
        check('personal: map links placeholders to real values', m['users'].get('USER_1') == 'john.smith')
        check('personal: map names its source', m['sources'] == ['personal.conf'])


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
    folder = work / 'configs_SANITIZED'
    copies = sorted(p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()) if folder.is_dir() else []
    check('zip: several files give a folder with the same tree', copies == ['outside/zyxel.conf', 'switches/netgear-m4300.cfg'],
          str(copies) + out[-500:])
    check('zip: no LEAK left', all('LEAK' not in text(folder / p) for p in copies))
    check('zip: nothing written outside the folder (zip slip)', not (tmp / 'outside').exists())
    check('zip: originals never extracted', not (work / 'switches').exists() and not (work / 'zyxel.conf').exists())
    # a second run never touches the first folder
    code, out = run(['configs.zip'], work)
    check('zip: existing folder never reused', len([p for p in work.iterdir() if p.is_dir() and p.name.startswith('configs') and p.name.endswith('_SANITIZED')]) == 2)
    # one file inside: the copy takes the archive's name
    with zipfile.ZipFile(work / 'router.conf.zip', 'w') as z:
        z.write(SAMPLES / 'cisco.conf', 'exports/cisco.conf')
    code, out = run(['router.conf.zip'], work)
    check('zip: single file named after the archive', (work / 'router_SANITIZED.conf').exists(), out[-300:])


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


def test_freepbx(tmp):
    work = tmp / 'freepbx'
    work.mkdir()
    # level 1 on the Asterisk sample: PINs, register lines, dial strings and the [secret] section
    shutil.copy(SAMPLES / 'asterisk.conf', work)
    code, out = run(['asterisk.conf'], work)
    body = text(work / 'asterisk_SANITIZED.conf')
    check('asterisk: format recognised', 'Asterisk / FreePBX' in out)
    check('asterisk: register secret masked, host kept', 'register => 1001:REDACTED@sip.provider.example/1001' in body)
    check('asterisk: register with authuser', 'REDACTED:authuser1002@sip.provider.example' in body)
    check('asterisk: voicemail PIN masked, name and options kept', '1001 => REDACTED,John Smith,john.smith@example.com,,attach=yes' in body)
    check('asterisk: dial string credentials masked', 'Dial(SIP/trunk:REDACTED@sip.provider.example/${EXTEN})' in body
          and 'IAX2/iaxuser:REDACTED@iax.provider.example' in body)
    check('asterisk: [secret] section value masked', '[secret]\nREDACTED\n[1]' in body)
    check('asterisk: trailing comment not kept after a secret', 'LEAKgeneral' not in body and 'alwaysauthreject=yes' in body)
    # level 2 adds caller ID names, voicemail names and SIP account names
    code, out = run(['-p', 'asterisk.conf', '-o', 'p2', '--no-map'], work)
    body = text(work / 'p2' / 'asterisk_ANONYMIZED.conf')
    check('asterisk: caller ID name anonymised, number kept', 'callerid="NAME_1 NAME_2" <1001>' in body)
    check('asterisk: voicemail name and email anonymised', '1001 => REDACTED,NAME_1 NAME_2,EMAIL_1,,attach=yes' in body
          and '1002 => REDACTED,NAME_3 NAME_4,,' in body)
    check('asterisk: trunk account anonymised consistently', body.count('USER_1') == 2 and 'trunkaccount' not in body)
    check('asterisk: register line not mistaken for an email', 'register => 1001:REDACTED@sip.provider.example/1001' in body
          and 'REDACTED:authuser1002@sip.provider.example' in body)
    # SQL dump and FreePBX JSON
    code, out = run([SAMPLES / 'freepbx-devices.sql', SAMPLES / 'freepbx-core.json', '-o', 'db'], work)
    sql = text(work / 'db' / 'freepbx-devices_SANITIZED.sql')
    check('sql: keyword/data rows masked by keyword name', "('1001','secret','REDACTED',0)" in sql and "('1001','md5secret','REDACTED',0)" in sql
          and "('1001','context','from-internal',0)" in sql)
    check('sql: secret columns found through CREATE TABLE', "('admin','REDACTED','')" in sql and "('operator','REDACTED','100')" in sql)
    check('sql: explicit column list honoured', "('readonly', 'REDACTED')" in sql)
    check('sql: PostgreSQL COPY block', '1\tbob\tCleartext-Password\t:=\tREDACTED' in sql and '\t:=\tnever' in sql)
    check('sql: structure untouched', 'PRIMARY KEY (`id`,`keyword`)' in sql)
    check('sql: rows continued on the next lines', "('1002','secret','REDACTED',52)" in sql and "('1002','md5secret','REDACTED',52);" in sql
          and "('1002','context','from-internal',13)" in sql)
    js = text(work / 'db' / 'freepbx-core_SANITIZED.json')
    check('freepbx json: keyword/data over several lines', '"data": "REDACTED"' in js and '"data": "sip.provider.example"' in js
          and '"data": "trunkaccount"' in js)
    check('freepbx json: compact keyword/data', '"keyword": "secret", "data": "REDACTED"' in js and '"data": "from-trunk"' in js)
    check('freepbx json: settings masked, setting sizes kept', '"AMPMGRPASS": "REDACTED"' in js and '"SIPSECRETSIZE": "32"' in js)
    check('freepbx json: nothing left to review', 'Lines to review locally: none flagged' in out.split('freepbx-core.json')[-1])
    code, out = run(['-p', SAMPLES / 'freepbx-devices.sql', SAMPLES / 'freepbx-core.json', '-o', 'db2', '--no-map'], work)
    sql2, js2 = text(work / 'db2' / 'freepbx-devices_ANONYMIZED.sql'), text(work / 'db2' / 'freepbx-core_ANONYMIZED.json')
    check('freepbx level 2: user names in SQL rows and keyword/data rows', 'John' not in sql2 and 'Jane' not in sql2
          and "('1001','callerid','NAME_1 NAME_2 <1001>',0)" in sql2 and "('1001','','NAME_1 NAME_2','default')" in sql2)
    check('freepbx level 2: user names in module JSON', 'John' not in js2 and '"name": "NAME_1 NAME_2"' in js2
          and '"description": "NAME_1 NAME_2"' in js2 and '"module": "core"' in js2)
    # a FreePBX-style tar.gz: folder output, audio and call records skipped, nested gzip and keys handled
    def add(tf, name, data):
        ti = tarfile.TarInfo(name)
        ti.size, ti.mtime = len(data), int(time.time())
        tf.addfile(ti, io.BytesIO(data))
    with tarfile.open(work / '20260101-010203-17.0.1-12345.tar.gz', 'w:gz') as tf:
        add(tf, 'modulejson/Core.json', (SAMPLES / 'freepbx-core.json').read_bytes())
        add(tf, 'modulejson/Calendar.json', b'{"module": "calendar", "pbx_version": null, "configs": {"noid": []}}\n')
        add(tf, 'customdir/etc/asterisk/manager.conf', (SAMPLES / 'asterisk.conf').read_bytes())
        add(tf, 'files/tmp/Devices_dump/Devices.sql', (SAMPLES / 'freepbx-devices.sql').read_bytes())
        add(tf, 'files/tmp/cdr_dump/cdr.sql.gz', gzip.compress(b"INSERT INTO cdr VALUES ('+15550100','LEAKcdr');\n"))
        add(tf, 'files/var/lib/asterisk/moh/wait.wav', b'RIFF' + bytes(range(256)) * 4)
        add(tf, 'files/etc/asterisk/keys/default.key', b'-----BEGIN PRIVATE KEY-----\nLEAKkey\n-----END PRIVATE KEY-----\n')
        add(tf, 'files/etc/asterisk/keys/default.crt', b'-----BEGIN CERTIFICATE-----\nMIIBpublicCERTOK\n-----END CERTIFICATE-----\n')
        add(tf, 'files/etc/asterisk/notes.txt.gz', gzip.compress(b'password=LEAKnested\n'))
        add(tf, '../evil.conf', b'password=LEAKslip\n')
    code, out = run(['20260101-010203-17.0.1-12345.tar.gz'], work)
    folder = work / '20260101-010203-17.0.1-12345_SANITIZED'
    files = sorted(p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()) if folder.is_dir() else []
    check('tar: FreePBX backup recognised', 'FreePBX / Asterisk backup' in out, out[-400:])
    check('tar: folder mirrors the archive, audio and CDR left out', files == [
        'customdir/etc/asterisk/manager.conf', 'evil.conf', 'files/etc/asterisk/keys/default.crt',
        'files/etc/asterisk/keys/default.key', 'files/etc/asterisk/notes.txt', 'files/tmp/Devices_dump/Devices.sql',
        'modulejson/Calendar.json', 'modulejson/Core.json'], str(files))
    check('tar: skipped groups reported', 'audio and voicemail' in out and 'call records (CDR/CEL)' in out)
    check('tar: no LEAK in any copy', folder.is_dir() and not [p for p in folder.rglob('*') if p.is_file() and 'LEAK' in text(p)])
    check('tar: zip slip contained', not (tmp / 'evil.conf').exists() and (folder / 'evil.conf').exists())
    check('tar: private key replaced, certificate kept', '[REDACTED_PRIVATE_KEY]' in text(folder / 'files/etc/asterisk/keys/default.key')
          and 'MIIBpublicCERTOK' in text(folder / 'files/etc/asterisk/keys/default.crt'))
    check('tar: unchanged files listed', 'copied unchanged' in out and 'Calendar.json' in out)
    # a single gzip-compressed configuration
    with gzip.open(work / 'running.conf.gz', 'wb') as g:
        g.write((SAMPLES / 'cisco.conf').read_bytes())
    code, out = run(['running.conf.gz'], work)
    check('gzip: single compressed file handled', (work / 'running_SANITIZED.conf').exists() and 'LEAK' not in text(work / 'running_SANITIZED.conf'), out[-300:])


def test_cli(tmp):
    work = tmp / 'cli'
    work.mkdir()
    for name in ('zyxel.conf', 'cisco.conf', 'plain.conf', 'personal.conf', 'mikrotik.rsc'):
        shutil.copy(SAMPLES / name, work)
    # stdin -> stdout: the copy goes to stdout, the report to stderr
    p = subprocess.run([sys.executable, '-I', str(SCRIPT), '-', '-o', '-'], cwd=str(work),
                       input=(SAMPLES / 'zyxel.conf').read_bytes(), capture_output=True)
    check('cli: stdin to stdout works', p.returncode == 0 and b'LEAK' not in p.stdout and b'REDACTED' in p.stdout)
    check('cli: report goes to stderr', b'Copy created' in p.stderr and b'Copy created' not in p.stdout)
    # -o FILE, never overwritten without --force
    code, out = run(['cisco.conf', '-o', 'out/clean.conf'], work)
    check('cli: -o file written where asked', code == 0 and (work / 'out' / 'clean.conf').exists(), out[-300:])
    code, out = run(['cisco.conf', '-o', 'out/clean.conf'], work)
    check('cli: -o file refuses to overwrite', code == 1 and 'already exists' in out, out[-300:])
    code, out = run(['cisco.conf', '-o', 'out/clean.conf', '--force'], work)
    check('cli: --force overwrites the named output', code == 0, out[-300:])
    # directory input -> output directory, structure mirrored, binaries skipped, own outputs ignored
    tree = work / 'tree'
    (tree / 'sub').mkdir(parents=True)
    shutil.copy(SAMPLES / 'asa.conf', tree)
    shutil.copy(SAMPLES / 'exos.cfg', tree / 'sub')
    (tree / 'sub' / 'blob.bin').write_bytes(b'\x00\x01\x02' * 50)
    (tree / 'old_SANITIZED.conf').write_text('LEAK should be ignored\n')
    code, out = run(['tree', '-o', 'clean'], work)
    written = sorted(p.relative_to(work / 'clean').as_posix() for p in (work / 'clean').rglob('*') if p.is_file())
    check('cli: directory processed into output dir', code == 0 and written ==
          ['tree/asa_SANITIZED.conf', 'tree/sub/exos_SANITIZED.cfg'], str(written) + out[-300:])
    check('cli: binary skipped without failing the run', 'Skipped' in out and '1 skipped' in out)
    # --strict and errors
    code, out = run(['plain.conf', '-o', 's1/', '--strict'], work)
    check('cli: --strict exits 2 when nothing was masked', code == 2, out[-200:])
    code, out = run(['zyxel.conf', '-o', 's2/', '--strict'], work)
    check('cli: --strict exits 0 on a clean run', code == 0, out[-200:])
    code, out = run(['missing.conf'], work)
    check('cli: missing input exits 1', code == 1 and 'not found' in out)
    # one map shared by every file of a run
    code, out = run(['-p', 'personal.conf', 'mikrotik.rsc', '-o', 'pers', '-m', 'pers/map.json'], work)
    m = json.loads(text(work / 'pers' / 'map.json')) if (work / 'pers' / 'map.json').exists() else {}
    check('cli: shared map written where -m says', code == 0 and bool(m), out[-300:])
    check('cli: shared map covers both files', set(m.get('sources', [])) == {'personal.conf', 'mikrotik.rsc'}
          and {'vpnuser', 'john.smith'} <= set(m.get('users', {}).values()))
    code, out = run(['-p', 'personal.conf', '-o', 'nomap/', '--no-map'], work)
    check('cli: --no-map writes no map', code == 0 and not outputs(work / 'nomap', 'MAP'))
    code, out = run(['--version'], work)
    check('cli: --version', code == 0 and out.strip().startswith('netblur '))


def test_identities(tmp):
    work = tmp / 'identities'
    work.mkdir()
    shutil.copy(SAMPLES / 'identity.conf', work)
    code, out = run(['-p', 'identity.conf', '-w', 'Leakcorp,Milano', '-o', 'out/', '-m', 'out/map.json'], work)
    copy = work / 'out' / 'identity_ANONYMIZED.conf'
    check('identities: copy created', code == 0 and copy.exists(), out[-400:])
    if not copy.exists():
        return
    body = text(copy)
    for real in ('ACMEHOST', 'leakcorp', 'Leakcorp', 'Milano', '82.121.34', '2a00:1450', '0011.22aa', '00:11:22', 'noc@'):
        check('identities: "%s" removed' % real, real not in body)
    check('identities: hostname pseudonymised', 'hostname HOST_1' in body)
    check('identities: domain pseudonymised also inside FQDNs', 'ntp server ntp1.example-1.net' in body)
    check('identities: same public IP gets the same alias', body.count('192.0.2.1') == 2 and 'neighbor 192.0.2.2 remote-as' in body)
    check('identities: private IPs, masks and wildcards kept',
          '192.168.10.1 255.255.255.0' in body and '10.0.0.0 0.0.0.255' in body)
    check('identities: MAC format preserved', 'mac-address 0200.0000.0001' in body and '02:00:00:00:00:02 ARPA' in body)
    check('identities: four-part version number kept', 'firmware version 7.2.8.1' in body)
    check('identities: AS numbers and structure kept', 'remote-as 3215' in body and 'router bgp 65001' in body)
    m = json.loads(text(work / 'out' / 'map.json'))
    check('identities: map holds every kind', m['hosts'].get('HOST_1') == 'ACMEHOST-CORE-01'
          and m['domains'].get('example-1.net') == 'leakcorp.example' and m['ips'].get('192.0.2.1') == '82.121.34.5'
          and '2001:db8::1' in m['ipv6'] and '02:00:00:00:00:01' in m['macs'] and m['words'].get('WORD_1') == 'leakcorp')
    # --keep-ips / --all-ips / --keep-macs
    code, out = run(['-p', 'identity.conf', '-o', 'keep', '--keep-ips', '--keep-macs', '--no-map'], work)
    kept = text(work / 'keep' / 'identity_ANONYMIZED.conf')
    check('identities: --keep-ips and --keep-macs honoured', '82.121.34.5' in kept and '0011.22aa.bbcc' in kept)
    code, out = run(['-p', 'identity.conf', '-o', 'all', '--all-ips', '--no-map'], work)
    every = text(work / 'all' / 'identity_ANONYMIZED.conf')
    check('identities: --all-ips replaces private addresses too', '192.168.10.1' not in every and '255.255.255.0' in every)
    # restore round trip, including placeholders in other MAC notations
    answer = work / 'answer.txt'
    answer.write_text('HOST_1 in example-1.net peers with 192.0.2.2 via 0200.0000.0001; contact EMAIL_1 about WORD_1.\n')
    code, out = run(['--restore', 'answer.txt', '-m', 'out/map.json'], work)
    restored = text(work / 'answer_RESTORED.txt') if (work / 'answer_RESTORED.txt').exists() else ''
    check('restore: placeholders replaced by real values', code == 0 and restored.startswith('ACMEHOST-CORE-01 in leakcorp.example peers with 82.121.34.6 via 00:11:22:aa:bb:cc;')
          and 'noc@leakcorp.example' in restored and 'leakcorp.' in restored, restored + out[-200:])
    code, out = run(['--restore', 'answer.txt'], work)
    check('restore: refuses to run without a map', code == 1)


def test_zyxel(tmp):
    work = tmp / 'zyxel'
    work.mkdir()
    shutil.copy(SAMPLES / 'zyxel-zld.conf', work)
    code, out = run(['zyxel-zld.conf'], work)
    body = text(work / 'zyxel-zld_SANITIZED.conf')
    check('zyxel: every ZLD secret masked', 'LEAK' not in body and '$4$' not in body)
    for line in (' server password-encrypted REDACTED', ' encrypted-keystring REDACTED', ' keystring REDACTED',
                 ' server key REDACTED', 'radius-server key REDACTED', ' wpa-psk REDACTED', ' wpa-psk-encrypted REDACTED',
                 ' security wpa aes psk key REDACTED', ' encrypted-password REDACTED',
                 'username admin encrypted-password REDACTED user-type admin'):
        check('zyxel: "%s"' % line.strip(), line + '\n' in body)
    check('zyxel: nothing left to review or suspicious', 'Lines to review locally: none flagged' in out
          and 'possible secrets still' not in out, out[-400:])
    # regression: the two values reported in the issue and the password setting that is not a password
    lines = ('aaa group server ad AD1\n'
             ' server password-encrypted $4$AbCdEfGh$Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg+/x$\n'
             'isakmp policy VPN1\n'
             ' encrypted-keystring $4$QwErTyUi$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo0NTY3$\n'
             'no pwd-expiry force-to-change-pwd\n')
    p = subprocess.run([sys.executable, '-I', str(SCRIPT), '-', '-o', '-'], cwd=str(work), input=lines.encode(),
                       capture_output=True)
    got = p.stdout.decode()
    check('zyxel: password-encrypted value masked', ' server password-encrypted REDACTED\n' in got, got)
    check('zyxel: encrypted-keystring value masked', ' encrypted-keystring REDACTED\n' in got, got)
    check('zyxel: keyword without a value left unchanged', 'no pwd-expiry force-to-change-pwd\n' in got
          and 'force-to-change-pwd REDACTED' not in got, got)
    # lines without secrets stay byte for byte identical
    plain = ('hostname ZYWALL-TEST\nno pwd-expiry force-to-change-pwd\nno pwd force-to-change-pwd\n'
             'user-setting pwd-expiry force-to-change-pwd 30\npassword-encryption enable\nwpa-encrypt aes\n'
             'isakmp policy VPN1\n authentication pre-share\n transform-set isakmp-algo aes256-sha256\n'
             ' local-ip interface wan1\n exit\nip http secure-server cipher-suite aes256 aes128\n'
             'wlan-security-profile OFFICE\n group-key 3600\n exit\n')
    p = subprocess.run([sys.executable, '-I', str(SCRIPT), '-', '-o', '-'], cwd=str(work), input=plain.encode(),
                       capture_output=True)
    check('zyxel: lines without secrets unchanged', p.stdout.decode() == plain, p.stdout.decode())
    check('zyxel: password settings not flagged for review', b'Lines to review locally: none flagged' in p.stderr,
          p.stderr.decode()[-300:])


def test_hashes_and_residual(tmp):
    work = tmp / 'residual'
    work.mkdir()
    # $n$salt$hash goes whatever keyword precedes it, in any format
    sample = ('custom-field $1$LEAKa$LEAKb\nnote $6$LEAKsalt$LEAKhash$ end\nother=$5$LEAKs$LEAKh$\n'
              '{"opaque": "$9$LEAKj$LEAKk$"}\n<blob>$4$LEAKz$LEAKw$</blob>\n')
    (work / 'hashes.conf').write_text(sample)
    code, out = run(['hashes.conf'], work)
    body = text(work / 'hashes_SANITIZED.conf')
    check('hashes: $n$ values masked under any keyword', 'LEAK' not in body and 'note REDACTED end' in body, body)
    # idempotent: sanitizing the copy again changes nothing
    for name in ('hashes_SANITIZED.conf',):
        first = (work / name).read_bytes()
        p = subprocess.run([sys.executable, '-I', str(SCRIPT), '-', '-o', '-'], cwd=str(work), input=first,
                           capture_output=True)
        check('idempotent: %s' % name, p.stdout == first)
    for sample_name in sorted(p.name for p in SAMPLES.iterdir()):
        once = subprocess.run([sys.executable, '-I', str(SCRIPT), '-', '-o', '-'], cwd=str(work),
                              input=(SAMPLES / sample_name).read_bytes(), capture_output=True).stdout
        twice = subprocess.run([sys.executable, '-I', str(SCRIPT), '-', '-o', '-'], cwd=str(work),
                               input=once, capture_output=True).stdout
        check('idempotent: %s sanitized twice gives the same copy' % sample_name, once == twice)
    # a random-looking value under an unknown keyword is reported with its line, never declared clean
    (work / 'odd.conf').write_text('hostname test\nvendor-blob k9Qx7LmP2vRt8ZwB4nYc6Hd3\nexit\n')
    code, out = run(['odd.conf', '--strict'], work)
    check('residual: suspicious line reported with its number', 'check these lines before sharing it: 2' in out, out[-400:])
    check('residual: copy not named as clean', not (work / 'odd_NO-SECRETS-FOUND.conf').exists()
          and (work / 'odd_SANITIZED.conf').exists())
    check('residual: --strict exits 2', code == 2)
    check('residual: summary says the copies are not clean', 'NOT clean yet' in out)
    # level 2: PPPoE usernames, public IPs and MACs with consistent placeholders
    (work / 'isp.conf').write_text('account pppoe ISP_MAIN\n user isp-account-01\n password LEAKp\n exit\n'
                                   'interface wan1\n ip address 82.121.34.5 255.255.255.248\n mac 00:11:22:33:44:55\n'
                                   'ip route 0.0.0.0 0.0.0.0 82.121.34.1\nip dns server 82.121.34.5\n')
    code, out = run(['-p', 'isp.conf', '-o', 'p2', '--no-map'], work)
    isp = text(work / 'p2' / 'isp_ANONYMIZED.conf')
    check('level 2: PPPoE username replaced', 'isp-account-01' not in isp and ' user USER_1' in isp, isp)
    check('level 2: same public IP, same placeholder', isp.count('192.0.2.1') == 2 and '82.121' not in isp, isp)
    check('level 2: MAC replaced, private and mask kept', '00:11:22' not in isp and '255.255.255.248' in isp)


def test_gui(tmp):
    work = tmp / 'gui'
    work.mkdir()
    shutil.copy(SAMPLES / 'cisco.conf', work)
    code, out = run([], work)
    check('gui: no input without --gui is a usage error', code == 2 and 'INPUT' in out)
    env = dict(os.environ, NETBLUR_GUI_AUTOCLOSE='1')
    try:
        p = subprocess.run([sys.executable, '-I', str(SCRIPT), '--gui', 'cisco.conf', '--personal', '--no-map', '-o', 'out'],
                           cwd=str(work), env=env, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        check('gui: window processes its inputs and closes', False, 'timeout')
        return
    if p.returncode == 3:
        print('SKIP  gui: no tkinter or no display here (' + p.stderr.strip()[:80] + ')')
        return
    copy = work / 'out' / 'cisco_ANONYMIZED.conf'
    check('gui: window processes its inputs and closes', p.returncode == 0 and copy.exists() and 'LEAK' not in text(copy),
          'code %s %s' % (p.returncode, p.stderr[-300:]))
    p = subprocess.run([sys.executable, '-I', str(SCRIPT), '--gui'], cwd=str(work), env=env, capture_output=True, timeout=120)
    check('gui: opens with no inputs', p.returncode == 0)


def test_menu(tmp):
    if os.name == 'nt' or not shutil.which('sh'):
        print('SKIP  menu: install-menu.sh is for macOS and Linux')
        return
    home = tmp / "menu home"
    work = home / "it's my folder"
    work.mkdir(parents=True)
    shutil.copy(SAMPLES / 'cisco.conf', work)
    env = dict(os.environ, HOME=str(home), NETBLUR_MENU_NO_WINDOW='1')
    env.pop('XDG_DATA_HOME', None)
    env.pop('XDG_CONFIG_HOME', None)
    p = subprocess.run(['sh', str(ROOT / 'install-menu.sh')], env=env, capture_output=True, text=True)
    check('menu: installer runs', p.returncode == 0, p.stdout[-300:] + p.stderr[-300:])
    name = 'netblur (secrets and personal data)'
    if sys.platform == 'darwin':
        bundle = home / 'Library' / 'Services' / (name + '.workflow') / 'Contents'
        lint = subprocess.run(['plutil', '-lint', str(bundle / 'Info.plist'), str(bundle / 'document.wflow')],
                              capture_output=True, text=True)
        check('menu: Quick Action files are valid property lists', lint.returncode == 0, lint.stdout[-300:])
        try:
            p = subprocess.run(['automator', '-i', str(work / 'cisco.conf'), str(bundle.parent)], env=env,
                               capture_output=True, text=True, timeout=120)
            detail = 'code %s %s %s' % (p.returncode, p.stdout[-200:], p.stderr[-300:])
        except subprocess.TimeoutExpired:
            detail = 'timeout'
        check('menu: Quick Action runs through Automator', (work / 'cisco_ANONYMIZED.conf').exists(), detail)
    else:
        script = home / '.local' / 'share' / 'nautilus' / 'scripts' / name
        p = subprocess.run([str(script), str(work / 'cisco.conf')], env=env, capture_output=True, text=True)
        check('menu: file manager script sanitizes the selected file', (work / 'cisco_ANONYMIZED.conf').exists(),
              p.stdout[-200:] + p.stderr[-300:])
    p = subprocess.run(['sh', str(ROOT / 'install-menu.sh'), '--remove'], env=env, capture_output=True, text=True)
    left = [q for q in home.rglob('*') if q.is_file() and work not in q.parents]
    check('menu: --remove leaves nothing behind', p.returncode == 0 and not left, str(left)[:300])


def test_plugin_guard(tmp):
    work = tmp / 'guard'
    work.mkdir()
    shutil.copy(SAMPLES / 'fortigate.conf', work)
    shutil.copy(SAMPLES / 'plain.conf', work)
    (work / 'netblur_PERSONAL-DATA-MAP_x.json').write_text('{}', encoding='utf-8')
    (work / 'app.py').write_text('password = "LEAK"\n', encoding='utf-8')
    guard = ROOT / 'hooks' / 'netblur_guard.py'

    def decision(tool, tool_input, env=None):
        data = json.dumps({'cwd': str(work), 'tool_name': tool, 'tool_input': tool_input})
        p = subprocess.run([sys.executable, '-I', str(guard)], input=data, capture_output=True, text=True,
                           env=dict(os.environ, **(env or {})))
        if p.returncode != 0 or not p.stdout.strip():
            return 'allow'
        return json.loads(p.stdout)['hookSpecificOutput']['permissionDecision']

    check('guard: Read of a config with secrets is denied',
          decision('Read', {'file_path': 'fortigate.conf'}) == 'deny')
    check('guard: Read of a config without secrets is allowed',
          decision('Read', {'file_path': str(work / 'plain.conf')}) == 'allow')
    check('guard: Read of a netblur map is denied',
          decision('Read', {'file_path': 'netblur_PERSONAL-DATA-MAP_x.json'}) == 'deny')
    check('guard: source code is not checked', decision('Read', {'file_path': 'app.py'}) == 'allow')
    check('guard: cat in a pipeline is denied',
          decision('Bash', {'command': 'ls && cat fortigate.conf | head -5'}) == 'deny')
    check('guard: Grep on the file is denied',
          decision('Grep', {'pattern': 'set', 'path': 'fortigate.conf'}) == 'deny')
    check('guard: Get-Content in PowerShell is denied',
          decision('PowerShell', {'command': 'Get-Content -Path .\\fortigate.conf'}) == 'deny')
    check('guard: running netblur on the file is allowed',
          decision('Bash', {'command': 'python3 netblur.py fortigate.conf'}) == 'allow')
    check('guard: NETBLUR_GUARD=off disables it',
          decision('Read', {'file_path': 'fortigate.conf'}, {'NETBLUR_GUARD': 'off'}) == 'allow')
    run(['fortigate.conf'], work)
    check('guard: the sanitized copy is allowed',
          decision('Read', {'file_path': 'fortigate_SANITIZED.conf'}) == 'allow')
    manifest = json.loads((ROOT / '.claude-plugin' / 'plugin.json').read_text(encoding='utf-8'))
    import importlib.util
    spec = importlib.util.spec_from_file_location('netblur', str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    check('plugin: manifest version matches netblur', manifest['version'] == module.VERSION,
          '%s != %s' % (manifest['version'], module.VERSION))
    directory = json.loads((ROOT / 'plugin' / '.claude-plugin' / 'plugin.json').read_text(encoding='utf-8'))
    skill = (ROOT / 'plugin' / 'skills' / 'netblur' / 'SKILL.md').read_text(encoding='utf-8')
    check('plugin: directory manifest version matches netblur', directory['version'] == module.VERSION,
          '%s != %s' % (directory['version'], module.VERSION))
    check('plugin: directory version ships the current netblur.py',
          (ROOT / 'plugin' / 'netblur.py').read_bytes() == SCRIPT.read_bytes(),
          'copy netblur.py into plugin/ after changing it')
    check('plugin: skill runs the bundled copy and installs nothing',
          '${CLAUDE_PLUGIN_ROOT}/netblur.py' in skill and 'pip install' not in skill and 'https://' not in skill)


def main():
    tmp = Path(tempfile.mkdtemp(prefix='netblur-tests-'))
    try:
        for test in (test_samples, test_personal, test_rejections, test_fortinet_multipart, test_zip, test_3cx, test_freepbx,
                     test_cli, test_identities, test_zyxel, test_hashes_and_residual, test_gui, test_menu,
                     test_plugin_guard):
            print('--- ' + test.__name__)
            test(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    print('%d check(s) failed' % len(FAILURES) if FAILURES else 'All checks passed')
    sys.exit(1 if FAILURES else 0)


if __name__ == '__main__':
    main()
