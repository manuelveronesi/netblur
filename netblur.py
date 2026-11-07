# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Manuel Veronesi
"""netblur: mask secrets and personal data in network device configurations before sharing them.

Usage: netblur [options] INPUT [INPUT ...]

INPUT can be a configuration file, a ZIP archive, a directory (processed
recursively) or "-" for standard input. By default each copy is written next
to its original with the _SANITIZED suffix, or _NO-SECRETS-FOUND when nothing
was masked. Originals are never modified and existing files are never
overwritten. ZIP archives are read in memory and only sanitized copies reach
the disk. The copies are NOT meant to be restored onto a device.

Level 1 (default): passwords, keys, communities, PINs, tokens and hashes.
Level 2 (--personal): names, usernames, email addresses and phone numbers are
also replaced with consistent placeholders (NAME_1, USER_1, EMAIL_1, PHONE_1)
shared by every file of the run, and the copies get the _ANONYMIZED suffix.
A JSON map links each placeholder to the real value: keep it local, never share it.
"""
import argparse
import json
import codecs
import re
import sys
import zipfile
from datetime import datetime
from pathlib import Path

VERSION = '3.0'

TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s]+')

# CLI keywords followed by a secret. Prefixes such as "encrypted-", "ro-", "ldap-login-" are allowed.
CLI_KEY = re.compile(r'''^(?:[a-z0-9]+[-_])*(?:
    password|passwd|passphrase|pwd|secret|psk|psksecret|
    pre-?share|pre-?shared-?key|presharekey|pre-?shared-?secret|preshared-?key|
    community|key-string|private-key|privkey|auth-key|md5-keys?|
    authentication-key|message-digest-key|ipsec-secret|password-encrypt|
    psk-passphrase|wpa-passphrase|token|api-?key|apikey|engineid)$
    |^(?:auth|priv)-[a-z0-9-]+-key$
    |^(?:auth|priv)-(?:md5|sha\d*|des|3des|aes\d*)$''', re.X)

# Modifiers that precede the value and are left visible (encryption type, algorithm).
MODIFIERS = {
    '0', '4', '5', '6', '7', '8', '9', 'enc', 'encrypted', 'unencrypted', 'cipher', 'ciphertext',
    'plaintext', 'plain', 'simple', 'irreversible-cipher', 'hashed', 'hash', 'ascii', 'hex',
    'ascii-text', 'hex-text', 'text', 'md5', 'sha', 'sha1', 'sha-1', 'sha224', 'sha256', 'sha-256',
    'sha384', 'sha512', 'hmac-md5', 'hmac-sha', 'hmac-sha1', 'hmac-sha256', 'des', '3des', 'des56',
    'aes', 'aes128', 'aes192', 'aes256', 'aes-128', 'aes-192', 'aes-256', '128', '192', '256',
    'readonly', 'readwrite', 'read-only', 'read-write', 'read', 'write', 'local', 'remote',
}
ALGOS = {
    'md5', 'sha', 'sha1', 'sha-1', 'sha224', 'sha256', 'sha-256', 'sha384', 'sha512', 'hmac-md5',
    'hmac-sha', 'hmac-sha1', 'hmac-sha256', 'des', '3des', 'des56', 'aes', 'aes128', 'aes192',
    'aes256', 'aes-128', 'aes-192', 'aes-256', 'text',
}
# auth sha X / priv aes 128 Y / authentication md5 X: a secret only when an algorithm follows.
CONTEXT_ALGO = {'auth', 'authentication', 'priv', 'privacy', 'encrypt', 'encryption'}
# After the masked value, these words mean the rest of the line is not secret.
SAFE_FOLLOW = {
    'user-type', 'privilege', 'encrypted', 'pbkdf2', 'ro', 'rw', 'rwa', 'read-only', 'read-write',
    'readonly', 'readwrite', 'address', 'level', 'role', 'view', 'vr', 'vrf', 'index', 'port',
    'timeout', 'retransmit', 'auth-port', 'acct-port', 'no-xauth', 'no-config-mode', 'mask',
    'group', 'access-level', '{', ';',
}
# Words that, right after "password" and similar, mean a setting rather than a secret.
NOT_SECRET_NEXT = {
    'encryption', 'policy', 'complexity', 'min-length', 'prompt', 'history', 'aging', 'expire',
    'expiration', 'lockout', 'length', 'strength', 'recovery', 'reset', 'required', 'change',
    'type', 'mode', '=',
}
AUTH_PREV = {'authentication', 'auth', 'authmethod', 'method', 'mode', 'type', 'authentication-method'}
PSK_WORDS = {'pre-share', 'preshare', 'psk', 'pre-shared-key'}
KEY_NOT_NEXT = {
    'chain', 'generate', 'zeroize', 'import', 'export', 'label', 'storage', 'rsa', 'ec', 'dsa',
    'pubkey-chain', 'size', 'hash', 'exchange', 'lifetime', 'ring', 'id', 'type',
}
KEY_NOT_PREV = {'crypto', 'ssh', 'public', 'pubkey', 'host-key', 'rsa'}

# Recognisable hashes and ciphertexts wherever they appear (Cisco/Linux $1$ $5$ $8$ $9$, Juniper $9$, Huawei %^%#).
HASHTOKEN = re.compile(r'^["\']?(?:\$(?:1|2[abxy]?|5|6|7|8|9|y|sha1|sha256|sha512|pbkdf2[\w-]*)\$\S+|%\^%#\S+|%\$%\$\S+)')

# Secret field names for key=value, JSON and XML formats.
SECRET_NAME = re.compile(
    r'password|passwd|passphrase|pwd|bindpw|(?:^|[-_.])pw$|(?:^|[-_.])pass$|secret|psk|'
    r'pre-?shared|preshare|private-?key|privkey|priv-?key|auth-?key|authentication[-_]?key|'
    r'md5-?key|static-?key|community|shadow|iapp|api-?key|token|wep-?key|key-?string|credential|'
    r'(?:^|[-_.])prv$|shared[-_]?key|(?:^|[-_.])key$|hash$|(?:^|[-_.])tls$|'
    r'pin$|pincode|licen[sc]e[-_]?key|(?:^|[-_.])auth[-_]?id$|^authid$|2fa|totp|(?:^|[-_.])otp(?:$|[-_.])|'
    r'salt$|cookie|session[-_]?(?:id|key|token)')
# Name/Value pairs (3CX DNProperty and similar): the secret is in <Value>, its name in <Name>.
NV_SECRET_NAME = re.compile(r'pass|secret|pin|key|token|hash|rps|quickmeeting|openlink|services_access|'
                            r'signing|private|otp|totp|apikey|credential|pwd|authid', re.I)
# Property names that describe a setting (length, count, flag, expiry, address) rather than hold a secret.
NV_SETTING_NAME = re.compile(r'(?:^|_)(?:IP|ADDR|ADDRESS|HOST|PORT)$|INTERFACE|LENGTH$|COUNT$|ENABLED$|'
                             r'REQUIRED$|TIMEOUT$|MINUTES$|EXPIRE[DS]?(?:_AT)?$|^ALLOW_|^SHOW|^USE_|PROTECTED$', re.I)
NV_NAME = re.compile(r'<(Name|name|Key|key)>([^<]*)</\1>')
NV_VALUE = re.compile(r'<(Value|value)>([^<]*)</\1>')
# XML escaped inside a text value, e.g. &lt;Password&gt;x&lt;/Password&gt; in phone provisioning blobs.
ESC_ELEM = re.compile(r'&lt;([A-Za-z_][\w.:-]*)(?:\s(?:(?!&gt;).)*?)?&gt;((?:(?!&lt;).)*?)&lt;/\1&gt;')
EXCL_LAST = {
    'length', 'len', 'policy', 'type', 'types', 'mode', 'enabled', 'enable', 'disabled', 'status',
    'lifetime', 'strength', 'complexity', 'min', 'max', 'history', 'aging', 'expire', 'expires',
    'expiry', 'expiration', 'encryption', 'prompt', 'change', 'changed', 'required', 'format',
    'algo', 'algorithm', 'function', 'method', 'count', 'timeout', 'retry', 'retries', 'id',
    'index', 'size', 'profile', 'time', 'date', 'interval', 'version', 'level', 'file', 'path',
    'url', 'hint', 'reset', 'recovery',
}
TRIVIAL = {'', 'yes', 'no', 'true', 'false', 'enable', 'enabled', 'disable', 'disabled', 'none',
           'auto', 'on', 'off', 'redacted', 'null'}

KV = re.compile(r'(?<![\w.\-"\'])(?P<name>[A-Za-z_][\w.\-]*)(?P<eq>\s*=\s*)'
                r'(?P<val>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s"\'=][^\s]*|(?=\s|$))')
KV_LINE = re.compile(r'^(?P<pre>\s*(?P<name>[A-Za-z_][\w.\-]*)\s*=\s*)(?P<val>.*?)(?P<cont>\s+\\)?$')
JSONPAIR = re.compile(r'"(?P<name>(?:\\.|[^"\\])*)"\s*:\s*(?P<val>"(?:\\.|[^"\\])*")')
XMLELEM = re.compile(r'<(?P<tag>[A-Za-z_][\w.:-]*)(?P<attrs>\s[^<>]*)?>(?P<val>[^<]*)</(?P=tag)\s*>')
XMLOPEN = re.compile(r'<(?P<tag>[A-Za-z_][\w.:-]*)(?:\s[^<>]*)?>(?P<val>[^<]*)$')
XMLATTR = re.compile(r'(?P<name>[A-Za-z_][\w.:-]*)\s*=\s*(?P<val>"[^"]*"|\'[^\']*\')')
PEM_BEGIN = re.compile(r'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?|OpenVPN Static key V1)-----')
PEM_END = re.compile(r'-----END (?:[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?|OpenVPN Static key V1)-----')
EXOS_ACCOUNT = re.compile(r'(\baccount\s+(?:admin\s+|user\s+)?\S+\s+encrypted\s+)("(?:\\.|[^"\\])*"|\S+)', re.I)
SNMP_HOST = re.compile(r'^(\s*snmp-server\s+host\s+\S+(?:\s+(?:informs|traps))?(?:\s+version\s+(?:1|2c))?\s+)'
                       r'(?!(?:informs|traps|version|vrf)\b)(\S+)', re.I)
BENIGN = re.compile(r'service password-encryption|password encryption|authentication pre-share|'
                    r'crypto key generate|^\s*key chain\b|^\s*key \d+\s*$|authmethod psk|psk-type|'
                    r'mode pre-shared-secret|-password ""|authentication-types=|^/(?:ppp secret|snmp community)|'
                    r'^\s*config system snmp community|"key"\s*:\s*"|_required"\s*:|'
                    r'^\s*config\s|^\s*set type password\s*$|^\s*set \S*cipher\S*\s|^\s*set \S*(?:password|passwd|pwd)\S* \d+\s*$', re.I)
REVIEW_IGNORE = re.compile(r'\w*(?:secret|pass\w*|pwd|pin|key|token)\w*=(?:""|\'\')|<(Name|name|Description|description)>[^<]*</\1>', re.I)
CERT_BEGIN = re.compile(r'-----BEGIN [A-Z0-9 ]*CERTIFICATE[A-Z ]*-----')
CERT_END = re.compile(r'-----END [A-Z0-9 ]*CERTIFICATE[A-Z ]*-----')
# Credentials embedded as user:password@host, in URLs or in Fortinet backup/automation commands.
URL_CRED = re.compile(r'(?i)\b[a-z][a-z0-9+.-]*://([^:/@\s"\']+):([^\s"\']+)@([^@\s"\'/]+)')
CMD_CRED = re.compile(r'([A-Za-z0-9._-]+):([^\s"\']+)@([^@\s"\'/:]+)')
CMD_CRED_TRIGGER = re.compile(r'(?i)set script|execute backup|execute restore')
SUSPECT = re.compile(r'password|passwd|passphrase|pwd|secret|psk|preshar|pre-shar|community|private.?key|'
                     r'token|credential|api.?key|\bkey\b|\$\d\$|\bENC\b|cipher|shadow', re.I)
PEM_MARK = '[REDACTED_PRIVATE_KEY]'


def mask(orig):
    if orig.startswith('"'):
        return '"REDACTED"'
    if orig.startswith("'"):
        return "'REDACTED'"
    return 'REDACTED'


def unquote(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
        return v[1:-1]
    return v


def trivial(v):
    return unquote(v).strip().lower() in TRIVIAL


def is_secret_name(name, json=False):
    low = name.lower().split(':')[-1]
    if 'public' in low or 'hint' in low:
        return False
    if json and low == 'key':
        return False
    parts = [p for p in re.split(r'[-_.]', low) if p]
    if parts and parts[-1] in EXCL_LAST:
        return False
    return bool(SECRET_NAME.search(low))


def apply_spans(body, spans):
    for start, end, text in sorted(spans, reverse=True):
        body = body[:start] + text + body[end:]
    return body


class Context:
    def __init__(self):
        self.forti_stack = []
        self.ros_section = ''
        self.xml_open = None
        self.in_pem = False
        self.nv_secret = False
        self.nv_name = ''


def scan_json(body):
    spans = []
    for m in JSONPAIR.finditer(body):
        if is_secret_name(m.group('name'), json=True) and not trivial(m.group('val')):
            spans.append((m.start('val'), m.end('val'), '"REDACTED"'))
    return spans


def scan_xml(body, ctx):
    spans = []
    for m in XMLELEM.finditer(body):
        if is_secret_name(m.group('tag')) and m.group('val').strip() and not trivial(m.group('val')):
            spans.append((m.start('val'), m.end('val'), 'REDACTED'))
    for m in re.finditer(r'<[A-Za-z_][^<>]*>', body):
        for a in XMLATTR.finditer(m.group()):
            if is_secret_name(a.group('name')) and not trivial(a.group('val')):
                s = m.start() + a.start('val')
                spans.append((s, s + len(a.group('val')), mask(a.group('val'))))
    o = XMLOPEN.search(body)
    if o and is_secret_name(o.group('tag')) and not spans_cover(spans, o.start('val')):
        ctx.xml_open = o.group('tag')
        if o.group('val').strip():
            spans.append((o.start('val'), o.end('val'), 'REDACTED'))
    return spans


def spans_cover(spans, pos):
    return any(s <= pos < e for s, e, _ in spans)


def scan_kv(body, ctx):
    spans = []
    whole = KV_LINE.match(body)
    if whole and not re.search(r'\s[A-Za-z_][\w.\-]*=', whole.group('val')):
        name, val = whole.group('name'), whole.group('val')
        if (is_secret_name(name) or (ctx.ros_section == '/snmp community' and name == 'name')) and not trivial(val):
            spans.append((whole.start('val'), whole.end('val'), mask(val)))
        return spans
    for m in KV.finditer(body):
        name, val = m.group('name'), m.group('val')
        secret = is_secret_name(name) or (ctx.ros_section == '/snmp community' and name.lower() == 'name')
        if secret and val and not trivial(val):
            spans.append((m.start('val'), m.end('val'), mask(val)))
    return spans


def secret_keyword(i, words, raw):
    n = len(words)
    if i + 1 >= n:
        return False
    w, nxt = words[i], words[i + 1]
    prev = words[i - 1] if i else ''
    if w == 'key':
        if nxt in KEY_NOT_NEXT or prev in KEY_NOT_PREV:
            return False
        if i == 0 and nxt.isdigit() and n == 2:
            return False
        return True
    if w in CONTEXT_ALGO:
        return nxt in ALGOS and prev not in ('password', 'service')
    if w == 'encrypted':
        return nxt not in SAFE_FOLLOW
    if CLI_KEY.match(w):
        if nxt in NOT_SECRET_NEXT:
            return False
        if w in PSK_WORDS and prev in AUTH_PREV:
            return False
        return True
    return False


def scan_cli(body, ctx, taken):
    tokens = [t for t in TOKEN.finditer(body) if not spans_cover(taken, t.start())]
    if not tokens:
        return []
    raw = [t.group() for t in tokens]
    words = [r.lower().rstrip(':') for r in raw]
    n = len(tokens)
    spans = []

    # Fortinet: SNMP community name inside "config system snmp community".
    if ctx.forti_stack and ctx.forti_stack[-1] == 'system snmp community' and n >= 3 \
            and words[0] == 'set' and words[1] == 'name':
        return [(tokens[2].start(), len(body), mask(raw[2]))]

    i = 0
    while i < n:
        if HASHTOKEN.match(raw[i]):
            spans.append((tokens[i].start(), tokens[i].end(), mask(raw[i])))
            i += 1
            continue
        if raw[i] == 'ENC' or secret_keyword(i, words, raw):
            j = i + 1
            if j >= n:
                break
            skips = 0
            while j < n - 1 and words[j] in MODIFIERS and skips < 4:
                j += 1
                skips += 1
            if raw[j] in ('""', "''") or words[j].strip('"\'') == 'redacted':
                i = j + 1
                continue
            if j + 1 < n and words[j + 1] in SAFE_FOLLOW:
                spans.append((tokens[j].start(), tokens[j].end(), mask(raw[j])))
                i = j + 1
                continue
            end = len(body)
            if n - 1 > j and raw[-1] in ('{', ';'):
                end = tokens[-2].end()
            spans.append((tokens[j].start(), end, mask(raw[j])))
            break
        i += 1
    return spans


def update_sections(body, ctx):
    s = body.strip()
    m = re.match(r'^config\s+(.+?)\s*$', s)
    if m:
        ctx.forti_stack.append(m.group(1).lower())
    elif s == 'end' and ctx.forti_stack:
        ctx.forti_stack.pop()
    if s.startswith('/'):
        parts = []
        for tok in s.split():
            if tok in ('add', 'set', 'remove', 'print') or '=' in tok or tok.startswith('['):
                break
            parts.append(tok)
        ctx.ros_section = ' '.join(parts).lower()


def clean_line(line, ctx):
    newline = re.search(r'(\r\n|\n|\r)$', line)
    newline = newline.group() if newline else ''
    body = line[:-len(newline)] if newline else line

    # Private key blocks (PEM, OpenVPN), including single-line ones.
    if ctx.in_pem:
        e = PEM_END.search(body)
        if e:
            ctx.in_pem = False
            return PEM_MARK + body[e.end():] + newline, True
        return PEM_MARK + newline, True
    b = PEM_BEGIN.search(body)
    if b:
        e = PEM_END.search(body, b.end())
        if e:
            return body[:b.start()] + PEM_MARK + body[e.end():] + newline, True
        ctx.in_pem = True
        return body[:b.start()] + PEM_MARK + newline, True

    # Secret XML element spanning several lines.
    if ctx.xml_open:
        close = re.search(r'</' + re.escape(ctx.xml_open) + r'\s*>', body)
        if close:
            ctx.xml_open = None
            before = 'REDACTED' if body[:close.start()].strip() else body[:close.start()]
            return before + body[close.start():] + newline, True
        return 'REDACTED' + newline, True

    update_sections(body, ctx)
    was_open = ctx.xml_open
    stripped = body.lstrip()
    spans = []
    creds = list(URL_CRED.finditer(body))
    if CMD_CRED_TRIGGER.search(body):
        creds += [m for m in CMD_CRED.finditer(body) if not spans_cover([(c.start(), c.end(), '') for c in creds], m.start(2))]
    for m in creds:
        if m.group(2).strip('"\'').lower() != 'redacted':
            spans.append((m.start(2), m.end(2), 'REDACTED'))
    is_json = bool(re.search(r'"\s*:', body))
    is_xml = stripped.startswith('<')
    nv = NV_NAME.search(body)
    if nv:
        ctx.nv_name = nv.group(2)
        ctx.nv_secret = bool(NV_SECRET_NAME.search(nv.group(2)) or is_secret_name(nv.group(2)))
    val = NV_VALUE.search(body)
    if val and ctx.nv_secret and (not nv or val.start() > nv.start()):
        v = val.group(2).strip()
        setting = ctx.nv_name and NV_SETTING_NAME.search(ctx.nv_name) and len(v) <= 32
        if v and not trivial(v) and not setting:
            spans.append((val.start(2), val.end(2), 'REDACTED'))
        ctx.nv_secret = False
    if re.search(r'</(DNProperty|Property|Parameter|Setting)>', body):
        ctx.nv_secret = False
    for m in ESC_ELEM.finditer(body):
        if is_secret_name(m.group(1)) and m.group(2).strip() and not trivial(m.group(2)):
            spans.append((m.start(2), m.end(2), 'REDACTED'))
    if is_json:
        spans += scan_json(body)
    if is_xml or re.search(r'<[A-Za-z_][\w.:-]*[\s>]', body):
        spans += [s for s in scan_xml(body, ctx) if not spans_cover(spans, s[0])]
    if not is_json:
        spans += [s for s in scan_kv(body, ctx) if not spans_cover(spans, s[0])]
        for rx in (EXOS_ACCOUNT, SNMP_HOST):
            m = rx.search(body)
            if m and not spans_cover(spans, m.start(2)) and not (rx is SNMP_HOST and ' community ' in body.lower()):
                if not trivial(m.group(2)) and m.group(2).strip('"\'').lower() != 'redacted':
                    spans.append((m.start(2), m.end(2), mask(m.group(2))))
    if not is_json and not is_xml and not stripped.startswith('/'):
        spans += scan_cli(body, ctx, spans)
    if not spans:
        return line, bool(ctx.xml_open and not was_open)
    # Drop overlaps, keeping the widest span.
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    clean = []
    for s in spans:
        if clean and s[0] < clean[-1][1]:
            continue
        clean.append(s)
    return apply_spans(body, clean) + newline, True


def detect_format(text):
    head = text[:20000]
    low = head.lower()
    checks = [
        ('Fortinet (FortiGate, FortiWeb, FortiSwitch...)', '#config-version=' in low or 'config system global' in low),
        ('MikroTik RouterOS', 'by routeros' in low or re.search(r'^/(ip|interface|system) ', head, re.M)),
        ('3CX configuration (Db.xml)', '<phonesystem>' in low),
        ('pfSense', '<pfsense>' in low),
        ('OPNsense', '<opnsense>' in low),
        ('WatchGuard (XML)', 'watchguard' in low and '<' in head),
        ('Cisco ASA', 'asa version' in low),
        ('Juniper Junos', '## last commit' in low or 'set system host-name' in low),
        ('Ubiquiti EdgeOS/VyOS', '/* warning: do not remove' in low or re.search(r'^\s*interfaces \{', head, re.M)),
        ('Ubiquiti airOS/UniFi (system.cfg)', re.search(r'^(users|aaa|wireless|radio)\.\d+\.', head, re.M)),
        ('Extreme EXOS', re.search(r'^\s*configure (vlan|snmp|account|ports)\b', head, re.M)),
        ('Extreme VOSS', 'boot config flags' in low),
        ('Huawei', re.search(r'^\s*sysname ', head, re.M) and re.search(r'^#\s*$', head, re.M)),
        ('Zyxel', re.search(r'user-type|zysh|interface-name|zyxel', low)),
        ('Cisco IOS or compatible (Netgear, TP-Link, Aruba...)', re.search(r'^(hostname|version \d+\.\d+|interface \S+)', head, re.M)),
        ('WireGuard', re.search(r'^\[(Interface|Peer)\]', head, re.M)),
        ('OpenVPN', re.search(r'^(client|remote \S+|<ca>|<tls-auth>)', head, re.M)),
        ('JSON', re.match(r'\s*[\[{]\s*["{\[]', head)),
        ('XML', head.lstrip().startswith('<')),
    ]
    for name, ok in checks:
        if ok:
            return name
    return 'not recognised (generic rules applied)'


def redact(text):
    ctx = Context()
    output, changed, review = [], [], []
    in_cert = False
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        result, modified = clean_line(line, ctx)
        output.append(result)
        # Public certificates are left untouched and their base64 lines are never flagged.
        starts_cert = bool(CERT_BEGIN.search(line))
        if modified:
            changed.append(number)
        elif not (in_cert or starts_cert) and SUSPECT.search(REVIEW_IGNORE.sub('', line)) and not BENIGN.search(line):
            review.append(number)
        if starts_cert:
            in_cert = True
        if CERT_END.search(line):
            in_cert = False
    if ctx.in_pem:
        raise ValueError('Unterminated private key block: no file written.')
    return ''.join(output), changed, review


def decode(raw):
    if raw.startswith(b'PK\x03\x04') or raw.startswith(b'\x1f\x8b') or raw.startswith(b'Rar!') \
            or raw.startswith(b'7z\xbc\xaf'):  # ZIP archives are handled before decode() is called
        raise ValueError('The file is a compressed archive: extract the text configuration file first.')
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        return raw.decode('utf-16'), 'utf-16'
    if b'\x00' in raw:
        raise ValueError('The file is binary or encrypted: export the configuration from the device as text.')
    if raw.startswith(codecs.BOM_UTF8):
        text, enc = raw.decode('utf-8-sig'), 'utf-8-sig'
    else:
        try:
            text, enc = raw.decode('utf-8'), 'utf-8'
        except UnicodeDecodeError:
            text, enc = raw.decode('cp1252', errors='strict'), 'cp1252'
    if text:
        ctrl = sum(1 for c in text if (ord(c) < 32 and c not in '\t\n\r\f\x0b') or ord(c) == 127)
        if ctrl / len(text) > 0.005:
            raise ValueError('The file looks binary or encrypted: export the configuration from the device as text.')
    return text, enc


# ---------------------------------------------------------------- personal data
EMAIL = re.compile(r'(?<![\w.%+-])[A-Za-z0-9._%+-]*[A-Za-z][A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])')
# Fields that hold phone numbers by definition: any number of 6+ digits in them is replaced.
PHONE_FIELDS = re.compile(r'<(PhoneNumber|MobileNumber|CallerID|OutboundCallerID|ExternalNumber|DIDNumbers|'
                          r'AddressNumberOrData\d*|Fax(?:Number)?|Pager|HomePhone|BusinessPhone|Business2Phone|'
                          r'Mobile2|HomePhone2|Other|phone)>([^<]*)</\1>', re.I)
PHONE_IN_FIELD = re.compile(r'(?<![\w.])\+?\d[\d ./-]{4,18}\d(?![\w.])')
PHONE = re.compile(r'(?<![\w.+/-])(?:\+\d{1,3}(?:[ -]?\d{2,5}){2,5}|0\d{1,3}[ /-]\d{5,8}|'
                   r'3\d{2}[ -]\d{3}[ -]?\d{3,4}|(?:00)?\d{6,15})(?![\w.-])')
# System contact fields usually hold a person's name.
CONTACT_CMD = re.compile(r'(?i)^\s*(?:snmp-server contact|snmp-agent sys-info contact|configure snmp syscontact|'
                         r'set contact-info|set contact|snmp contact)\s+(.+?)\s*$')
NAME_TAGS = re.compile(r'<(FirstName|LastName|DisplayName|FullName|Surname|GivenName|CustomName|CompanyName|'
                       r'ContactName|contact|company)>([^<]+)</\1>', re.I)
NAME_KEYS = re.compile(r'(?i)"(first[-_]?name|last[-_]?name|full[-_]?name|display[-_]?name|surname|given[-_]?name|'
                       r'contact[-_]?name)"\s*:\s*"([^"]+)"|'
                       r'(?<![\w-])(first[-_]?name|last[-_]?name|full[-_]?name|display[-_]?name)\s*=\s*("[^"]+"|\S+)')
NAME_SET = re.compile(r'(?i)^\s*set (first-name|last-name|fullname|full-name|display-name|contact|company) (".*?"|\S+)')
USER_CMD = re.compile(r'(?i)^\s*(?:no\s+)?(?:username|user name|users passwd|local-user)\s+("[^"]+"|\S+)')
GENERIC_ACCOUNTS = {'admin', 'administrator', 'root', 'guest', 'operator', 'support', 'user', 'users', 'monitor',
                    'readonly', 'read-only', 'maintenance', 'ubnt', 'cisco', 'manager', 'default', 'test', 'service',
                    'backup', 'api', 'rwa', 'rw', 'ro', 'super', 'superuser', 'tech', 'technician', 'helpdesk',
                    'name', 'group', 'none', 'all', 'any'}
NAME_STOP = {'none', 'null', 'true', 'false', 'default', 'admin', 'user', 'test', 'name', 'unknown', 'reception',
             'centralino', 'ufficio', 'office', 'fax', 'voicemail', 'queue', 'ivr', 'operator', 'operatore',
             'redacted'}
WORD = re.compile(r"[A-Za-z0-9\u00c0-\u024f][\w.'\u00c0-\u024f-]*")


def looks_like_phone(raw):
    d = re.sub(r'\D', '', raw)
    if len(set(d)) == 1:
        return False
    if raw.startswith('+'):
        return 8 <= len(d) <= 15
    if d.startswith('00'):
        return 10 <= len(d) <= 15
    if d.startswith('0'):
        return 8 <= len(d) <= 12
    if d.startswith('3'):
        # Italian mobiles (3xx, including 39x) have 9-10 digits, 11-13 with the 39 country code.
        return 9 <= len(d) <= 10 or (d.startswith('39') and 11 <= len(d) <= 13)
    return False


class Privacy:
    """Consistent placeholders for personal data within one output file."""

    def __init__(self):
        self.maps = {'NAME': {}, 'USER': {}, 'EMAIL': {}, 'PHONE': {}}
        self.keywords = set()

    def total(self):
        return sum(len(m) for m in self.maps.values())

    def token(self, kind, value):
        m = self.maps[kind]
        if value not in m:
            m[value] = '%s_%d' % (kind, len(m) + 1)
        return m[value]

    def learn_keywords(self, text):
        # Words used as configuration keywords are never treated as personal names.
        self.keywords.update(t.lower() for t in re.findall(r'</?([A-Za-z_][\w.:-]*)', text))
        for line in text.splitlines():
            t = line.split()
            if t:
                self.keywords.add(t[0].lower())
                if t[0].lower() in ('set', 'config', 'unset', 'configure', 'no', 'show') and len(t) > 1:
                    self.keywords.add(t[1].lower())

    def add_name(self, value):
        for w in re.split(r'[\s,;/()]+', value.strip().strip('"\'')):
            w = w.strip(".-'\"")
            if len(w) >= 3 and not w.isdigit() and w.lower() not in NAME_STOP and w.lower() not in self.keywords:
                self.token('NAME', w)

    def add_user(self, value):
        v = value.strip().strip('"\'')
        if len(v) >= 3 and v.lower() not in GENERIC_ACCOUNTS and v.lower() != 'redacted' and not v.isdigit() \
                and v.lower() not in self.keywords:
            self.token('USER', v)

    def collect(self, text):
        self.learn_keywords(text)
        forti, ros = [], ''
        for line in text.splitlines():
            s = line.strip()
            m = re.match(r'^config\s+(.+?)\s*$', s)
            if m:
                forti.append(m.group(1).lower())
            elif s == 'end' and forti:
                forti.pop()
            if s.startswith('/'):
                ros = ' '.join(w for w in s.split() if '=' not in w and w not in ('add', 'set')).lower()
            for m in NAME_TAGS.finditer(line):
                self.add_name(m.group(2))
            for m in NAME_KEYS.finditer(line):
                self.add_name(m.group(2) or m.group(4) or '')
            m = NAME_SET.match(line)
            if m:
                self.add_name(m.group(2))
            m = CONTACT_CMD.match(line)
            if m:
                self.add_name(EMAIL.sub(' ', m.group(1)))
            if ros == '/snmp':
                for kv in re.finditer(r'(?:^|\s)contact=("[^"]+"|\S+)', line):
                    self.add_name(EMAIL.sub(' ', kv.group(1)))
            m = USER_CMD.match(line)
            if m:
                self.add_user(m.group(1))
            if forti and forti[-1] in ('user local', 'system admin'):
                e = re.match(r'^\s*edit\s+("[^"]+"|\S+)', line)
                if e:
                    self.add_user(e.group(1))
            if ros in ('/user', '/ppp secret', '/ip hotspot user', '/user-manager user'):
                for kv in re.finditer(r'(?:^|\s)name=("[^"]+"|\S+)', line):
                    self.add_user(kv.group(1))

    def apply(self, text):
        """Replace emails, phone numbers and the collected names everywhere in the text."""
        counts = {'NAME': 0, 'USER': 0, 'EMAIL': 0, 'PHONE': 0}

        def email(m):
            counts['EMAIL'] += 1
            return self.token('EMAIL', m.group().lower())

        def phone(m):
            if not looks_like_phone(m.group()):
                return m.group()
            counts['PHONE'] += 1
            return self.token('PHONE', re.sub(r'[ -]', '', m.group()))
        def field(m):
            def num(n):
                d = re.sub(r'\D', '', n.group())
                if len(d) < 6 or re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', n.group()):
                    return n.group()
                counts['PHONE'] += 1
                return self.token('PHONE', re.sub(r'[ ./-]', '', n.group()))
            return m.group().replace(m.group(2), PHONE_IN_FIELD.sub(num, m.group(2)), 1)
        text = EMAIL.sub(email, text)
        text = PHONE_FIELDS.sub(field, text)
        text = PHONE.sub(phone, text)
        names, users = self.maps['NAME'], self.maps['USER']

        def word(m):
            w = m.group()
            core = w.strip(".'-")
            for kind, table in (('USER', users), ('NAME', names)):
                if core in table:
                    counts[kind] += 1
                    return w.replace(core, table[core])
            return w

        def text_part(t):
            return WORD.sub(word, t)
        if names or users:
            # Tag names and attribute names in XML markup are never touched, only values.
            parts = re.split(r'(<[^<>]*>)', text)
            for i, part in enumerate(parts):
                if part.startswith('<') and part.endswith('>'):
                    parts[i] = re.sub(r'="([^"]*)"', lambda a: '="%s"' % text_part(a.group(1)), part)
                else:
                    parts[i] = text_part(part)
            text = ''.join(parts)
        return text, counts

    def map_dict(self, sources):
        """Placeholder -> real value, grouped by kind, ready to be written as JSON."""
        out = {
            '_warning': 'This file links placeholders to REAL personal data. Keep it local, never share it.',
            'tool': 'netblur', 'version': VERSION,
            'created': datetime.now().isoformat(timespec='seconds'),
            'sources': list(sources),
        }
        for kind, key in (('NAME', 'names'), ('USER', 'users'), ('EMAIL', 'emails'), ('PHONE', 'phones')):
            out[key] = {tok: value for value, tok in self.maps[kind].items()}
        return out


def is_multipart(raw):
    head = raw[:4096]
    return head.startswith(b'[header]') and b'file_split=' in head and b'[/header]' in head


def redact_multipart(raw, privacy=None):
    """Fortinet multi-part backup (e.g. FortiWeb "entire configuration"):
    text config blocks are sanitized, encrypted or compressed blocks are omitted."""
    hend = raw.index(b'[/header]')
    sep = re.search(rb'file_split=([^\r\n]*)', raw[:hend]).group(1)
    if len(sep) < 8:
        raise ValueError('Multi-part backup without a usable block separator: no file written.')
    header = re.sub(rb'(?m)^(private_key=)([^\r\n]+)', rb'\1REDACTED', raw[:hend])
    out, changed, review, blocks, hits = [header], [], [], [], [0]
    lines_so_far = header.count(b'\n')
    pos = hend
    while True:
        f = raw.find(b'[file]', pos)
        if f < 0:
            out.append(raw[pos:])
            break
        s1 = raw.find(sep, f)
        if s1 < 0:
            raise ValueError('Malformed multi-part backup (block without separator): no file written.')
        cstart = s1 + len(sep)
        cstart += 2 if raw[cstart:cstart + 2] == b'\r\n' else 1 if raw[cstart:cstart + 1] == b'\n' else 0
        s2 = raw.find(sep, cstart)
        if s2 < 0:
            raise ValueError('Malformed multi-part backup (unterminated block): no file written.')
        attrs = {k.lower(): v.strip() for k, v in re.findall(rb'(?m)^(\w+)=([^\r\n]*)', raw[f:s1])}
        name = attrs.get(b'name', b'?').decode('latin-1')
        prefix = raw[pos:cstart]
        out.append(prefix)
        lines_so_far += prefix.count(b'\n')
        content = raw[cstart:s2]
        if attrs.get(b'type') == b'config' and attrs.get(b'encrypt') == b'no' and attrs.get(b'compress') == b'no':
            text, enc = decode(content)
            result, ch, rv = redact(text)
            if privacy is not None:
                privacy.collect(result)
                result, counts = privacy.apply(result)
                hits[0] += sum(counts.values())
            changed += [n + lines_so_far for n in ch]
            review += [n + lines_so_far for n in rv]
            block = result.encode(enc)
            blocks.append(('text', name, len(content)))
        else:
            kinds = [k for k, a in (('encrypted', b'encrypt'), ('compressed', b'compress'))
                     if attrs.get(a, b'no') not in (b'no', b'')]
            label = ', '.join(kinds) or 'non-text'
            block = b'[binary block omitted: %s, %d bytes]\n' % (label.encode(), len(content))
            blocks.append((label, name, len(content)))
        out.append(block)
        lines_so_far += block.count(b'\n')
        pos = s2
    return b''.join(out), changed, review, blocks, hits[0]


MAX_ENTRY_SIZE = 512 * 1024 * 1024  # refuse suspiciously large archive members
OUTPUT_MARKERS = ('_SANITIZED', '_ANONYMIZED', '_NO-SECRETS-FOUND', 'PERSONAL-DATA-MAP')
STDIO = '-'


class Result:
    """What came out of one input file."""

    def __init__(self, data, changed, review, blocks, text, personal_hits):
        self.data, self.changed, self.review = data, changed, review
        self.blocks, self.text, self.personal_hits = blocks, text, personal_hits


def sanitize_bytes(raw, privacy=None):
    if is_multipart(raw):
        data, changed, review, blocks, hits = redact_multipart(raw, privacy)
        return Result(data, changed, review, blocks, None, hits)
    text, enc = decode(raw)
    result, changed, review = redact(text)
    hits = 0
    if privacy is not None:
        privacy.collect(result)
        result, counts = privacy.apply(result)
        hits = sum(counts.values())
    return Result(result.encode(enc), changed, review, None, text, hits)


def is_own_output(name):
    return any(m in name for m in OUTPUT_MARKERS)


def unique_path(folder, name, suffix):
    """A path that does not exist yet: date and time are added when the plain name is taken."""
    dst = folder / (name + suffix)
    if dst.exists():
        dst = folder / (name + '_' + datetime.now().strftime('%Y%m%d-%H%M%S') + suffix)
    return dst


class Run:
    """One invocation: options, the personal-data map shared by every file, counters and the log."""

    def __init__(self, args):
        self.args = args
        self.privacy = Privacy() if args.personal else None
        self.to_stdout = args.output == STDIO
        self.log = sys.stderr if self.to_stdout else sys.stdout
        self.failed = self.skipped = self.flagged = self.no_secrets = self.written = 0
        self.outputs = []          # paths written, in order
        self.sources = []          # input labels, for the map file
        self.output_dir = None     # set when -o names a directory
        self.explicit_file = None  # set when -o names one output file

    def say(self, *parts):
        print(*parts, file=self.log)

    # ---------------------------------------------------------------- destinations
    def tag(self, result):
        if not result.changed and not result.personal_hits:
            return '_NO-SECRETS-FOUND'
        return '_ANONYMIZED' if self.args.personal else '_SANITIZED'

    def destination(self, src, rel_parent, stem, suffix, result):
        """Where this result goes. None means standard output."""
        if self.to_stdout:
            return None
        if self.explicit_file is not None:
            dst = self.explicit_file
            if dst.exists() and not self.args.force:
                raise ValueError('Output file already exists (use --force to overwrite): ' + dst.name)
            dst.parent.mkdir(parents=True, exist_ok=True)
            return dst
        folder = self.output_dir / rel_parent if self.output_dir is not None else src.parent
        folder.mkdir(parents=True, exist_ok=True)
        return unique_path(folder, stem + self.tag(result), suffix)

    def write(self, dst, result):
        if dst is None:
            sys.stdout.buffer.write(result.data)
            sys.stdout.buffer.flush()
        else:
            mode = 'wb' if (dst == self.explicit_file and self.args.force) else 'xb'  # xb never overwrites
            with dst.open(mode) as f:
                f.write(result.data)
            self.outputs.append(dst)
        self.written += 1

    # ---------------------------------------------------------------- reporting
    def report(self, dst, result):
        if result.blocks is None:
            self.say('Likely format:', detect_format(result.text))
        else:
            self.say('Likely format: Fortinet multi-part backup (e.g. FortiWeb entire configuration)')
            for kind, name, size in result.blocks:
                if kind == 'text':
                    self.say('  Block processed as text: %s (%d bytes)' % (name, size))
                else:
                    self.say('  Block OMITTED (%s): %s (%d bytes)' % (kind, name, size))
        self.say('Copy created:', dst.name if dst is not None else '(standard output)')
        self.say('Lines masked:', len(result.changed))
        if self.privacy is not None:
            self.say('Personal data replaced in this file: %d value(s)' % result.personal_hits)
        if result.review:
            shown = ', '.join(map(str, result.review[:40]))
            extra = ' and %d more' % (len(result.review) - 40) if len(result.review) > 40 else ''
            self.say('Lines to review locally:', shown + extra)
            self.flagged += len(result.review)
        else:
            self.say('Lines to review locally: none flagged')
        if not result.changed and not result.personal_hits:
            self.no_secrets += 1
            self.say('WARNING: no secrets found. Check that the file is a configuration and that its')
            self.say('syntax is supported, and review the copy before sharing it.')

    # ---------------------------------------------------------------- inputs
    def handle_bytes(self, raw, src, rel_parent, stem, suffix, label):
        self.say('File:', label)
        result = sanitize_bytes(raw, self.privacy)
        dst = self.destination(src, rel_parent, stem, suffix, result)
        self.write(dst, result)
        self.report(dst, result)
        self.sources.append(label)

    def handle_zip(self, src, rel_parent):
        self.say('File:', src.name, '(ZIP archive, read in memory)')
        try:
            archive = zipfile.ZipFile(src)
        except zipfile.BadZipFile:
            raise ValueError('The ZIP archive is damaged or not a real ZIP file.')
        with archive:
            members = [i for i in archive.infolist() if not i.is_dir()]
            if not members:
                raise ValueError('The ZIP archive contains no files.')
            if any(i.flag_bits & 0x1 for i in members):
                raise ValueError('The ZIP archive is password protected: extract it manually first.')
            zip_stem = Path(src.stem)  # "backup.conf.zip" -> "backup.conf"
            db = [i for i in members if re.fullmatch(r'\d*Db\.xml', i.filename)]
            if db:
                # 3CX backup: only the configuration is sanitized. Database tables, recordings,
                # voicemail, prompts, certificates and phone provisioning files are never written out.
                self.say('Likely content: 3CX backup. Only the configuration file is processed.')
                skipped = {}
                for i in members:
                    if i in db:
                        continue
                    top = i.filename.split('/')[0] if '/' in i.filename else '(root)'
                    n, size = skipped.get(top, (0, 0))
                    skipped[top] = (n + 1, size + i.file_size)
                for top, (n, size) in sorted(skipped.items()):
                    self.say('  Skipped: %-20s %5d files %10.1f MB' % (top, n, size / 1048576))
                members = db
            if (self.to_stdout or self.explicit_file is not None) and len(members) > 1:
                raise ValueError('A single output works with a single file: this archive holds %d.' % len(members))
            for info in members:
                # Only the base name is used, never the path stored in the archive.
                inner = Path(info.filename.replace('\\', '/').split('/')[-1])
                self.say()
                label = '%s -> %s' % (src.name, info.filename)
                try:
                    if info.file_size > MAX_ENTRY_SIZE:
                        raise ValueError('The file inside the archive is too large to process safely.')
                    if len(members) == 1:
                        stem, suffix = zip_stem.stem, zip_stem.suffix or inner.suffix
                    else:
                        stem, suffix = zip_stem.stem + '__' + inner.stem, inner.suffix
                    self.handle_bytes(archive.read(info), src, rel_parent, stem, suffix, label)
                except ValueError as exc:
                    self.failed += 1
                    self.say('Operation not completed:', exc)
                except Exception as exc:
                    self.failed += 1
                    self.say('Operation not completed (' + type(exc).__name__ + ').')

    def handle_file(self, src, rel_parent=Path('.')):
        with src.open('rb') as f:
            head = f.read(4)
        if head[:2] == b'PK' and zipfile.is_zipfile(src):
            return self.handle_zip(src, rel_parent)
        self.handle_bytes(src.read_bytes(), src, rel_parent, src.stem, src.suffix, src.name)

    def handle_directory(self, root):
        count = 0
        for p in sorted(p for p in root.rglob('*') if p.is_file()):
            rel = p.relative_to(root)
            if any(part.startswith('.') for part in rel.parts) or is_own_output(p.name):
                continue
            count += 1
            self.say()
            try:
                self.handle_file(p, Path(root.name) / rel.parent)
            except ValueError as exc:
                # Inside a directory, non-text files are expected: skip them without failing the run.
                self.skipped += 1
                self.say('Skipped %s: %s' % (rel, exc))
            except Exception as exc:
                self.failed += 1
                self.say('Operation not completed for %s (%s).' % (rel, type(exc).__name__))
        if not count:
            raise ValueError('The directory contains no files to process: ' + str(root))

    def handle_stdin(self):
        raw = sys.stdin.buffer.read()
        if not raw:
            raise ValueError('Nothing was read from standard input.')
        self.handle_bytes(raw, Path.cwd() / 'stdin.txt', Path('.'), 'stdin', '.txt', '(standard input)')

    def handle(self, item):
        if item == STDIO:
            return self.handle_stdin()
        p = Path(item)
        if p.is_dir():
            return self.handle_directory(p.resolve())
        if not p.exists():
            raise FileNotFoundError(item)
        return self.handle_file(p.resolve())

    # ---------------------------------------------------------------- map file
    def map_destination(self):
        if self.args.map:
            return Path(self.args.map)
        if len(self.outputs) == 1:
            dst = self.outputs[0]
            return unique_path(dst.parent, dst.stem + '_PERSONAL-DATA-MAP', '.json')
        folder = (self.output_dir if self.output_dir is not None
                  else self.outputs[0].parent if self.outputs else Path.cwd())
        return unique_path(folder, 'netblur_PERSONAL-DATA-MAP_' + datetime.now().strftime('%Y%m%d-%H%M%S'), '.json')

    def write_map(self):
        if self.privacy is None or not self.privacy.total() or self.args.no_map:
            return
        path = self.map_destination()
        if path.exists() and not self.args.force:
            raise ValueError('Map file already exists (use --force to overwrite): ' + str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', encoding='utf-8') as f:
            json.dump(self.privacy.map_dict(self.sources), f, ensure_ascii=False, indent=2)
        self.say()
        self.say('Map of placeholders written (REAL personal data inside: keep it local, never share it):')
        self.say('  ' + str(path))


def resolve_output(args, run):
    """Decide whether -o names a directory or one file."""
    if args.output is None or run.to_stdout:
        return
    out = Path(args.output)
    many = len(args.input) > 1 or any(Path(i).is_dir() for i in args.input if i != STDIO)
    looks_dir = out.is_dir() or args.output.endswith(('/', '\\'))
    if many or looks_dir:
        out.mkdir(parents=True, exist_ok=True)
        run.output_dir = out.resolve()
    else:
        run.explicit_file = out


def build_parser():
    parser = argparse.ArgumentParser(prog='netblur', description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input', nargs='+', metavar='INPUT',
                        help='configuration file, ZIP archive, directory, or - for standard input')
    parser.add_argument('-o', '--output', metavar='PATH',
                        help='output file (single input) or directory (several inputs); - for standard output')
    parser.add_argument('-p', '--personal', action='store_true',
                        help='level 2: also replace names, usernames, email addresses and phone numbers')
    parser.add_argument('-m', '--map', metavar='FILE',
                        help='where to write the JSON map of placeholders (default: next to the copies)')
    parser.add_argument('--no-map', action='store_true', help='do not write the map file')
    parser.add_argument('--strict', action='store_true',
                        help='exit with status 2 when lines are flagged for review or a file had no secrets')
    parser.add_argument('--force', action='store_true',
                        help='allow overwriting the file named by -o or -m (never the originals)')
    parser.add_argument('--version', action='version', version='netblur ' + VERSION)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    run = Run(args)
    run.say('netblur', VERSION, '| level 2: secrets and personal data' if args.personal else '| level 1: secrets only')
    if run.to_stdout and len(args.input) > 1:
        run.say('Standard output works with a single input.')
        return 1
    try:
        resolve_output(args, run)
    except OSError as exc:
        run.say('Cannot use the output path:', exc.strerror or exc)
        return 1
    for item in args.input:
        run.say()
        try:
            run.handle(item)
        except ValueError as exc:
            run.failed += 1
            run.say('Operation not completed:', exc)
        except FileNotFoundError:
            run.failed += 1
            run.say('Operation not completed: not found:', item)
        except Exception as exc:
            run.failed += 1
            # Never print contents or details that might contain secrets.
            run.say('Operation not completed (' + type(exc).__name__ + ').')
    try:
        run.write_map()
    except ValueError as exc:
        run.failed += 1
        run.say('Operation not completed:', exc)
    run.say()
    run.say('Done: %d file(s) written, %d skipped, %d error(s), %d line(s) to review, %d file(s) without secrets.'
            % (run.written, run.skipped, run.failed, run.flagged, run.no_secrets))
    run.say('Manual review always required: complete coverage is not guaranteed.')
    run.say('Do not restore these copies onto devices.')
    if run.failed:
        return 1
    if args.strict and (run.flagged or run.no_secrets):
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
