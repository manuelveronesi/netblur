# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Manuel Veronesi
"""netblur: mask secrets and personal data in network device configurations before sharing them.

Usage: netblur [options] INPUT [INPUT ...]

INPUT can be a configuration file, an archive (ZIP, TAR, .tar.gz, .gz), a
directory (processed recursively) or "-" for standard input. By default each
copy is written next to its original with the _SANITIZED suffix, or
_NO-SECRETS-FOUND when nothing was masked; an archive with several files gives
a folder with the same tree. Originals are never modified and existing files
are never overwritten. Archives are read in memory and only sanitized copies
reach the disk. The copies are NOT meant to be restored onto a device.

Level 1 (default): passwords, keys, communities, PINs, tokens and hashes.
Level 2 (--personal): names, usernames, email addresses and phone numbers are
also replaced with consistent placeholders (NAME_1, USER_1, EMAIL_1, PHONE_1)
shared by every file of the run, and the copies get the _ANONYMIZED suffix.
A JSON map links each placeholder to the real value: keep it local, never share it.
"""
import argparse
import codecs
import gzip
import io
import json
import re
import sys
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path

VERSION = '3.2'

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
    r'salt$|cookie|session[-_]?(?:id|key|token)|'
    r'(?:db|mgr|vm|sip|iax|ami|ari|ldap|web|admin|user|auth|pg|mysql|sql|smtp|mail|proxy|radius|ftp|sftp)pass$|^amp\w*pass$')
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
SETTING_SUFFIX = ('size', 'length', 'count', 'enabled', 'policy', 'timeout', 'interval', 'expires', 'expiry',
                  'history', 'complexity', 'strength', 'minlen', 'maxlen', 'format', 'required')
TRIVIAL = {'', 'yes', 'no', 'true', 'false', 'enable', 'enabled', 'disable', 'disabled', 'none',
           'auto', 'on', 'off', 'redacted', 'null'}

KV = re.compile(r'(?<![\w.\-"\'])(?P<name>[A-Za-z_][\w.\-]*)(?P<eq>\s*=>?\s*)'
                r'(?P<val>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s"\'=][^\s]*|(?=\s|$))')
KV_LINE = re.compile(r'^(?P<pre>\s*(?P<name>[A-Za-z_][\w.\-]*)\s*=>?\s*)(?P<val>.*?)(?P<cont>\s+\\)?$')
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
                    r'^\s*config\s|^\s*set type password\s*$|^\s*set \S*cipher\S*\s|^\s*set \S*(?:password|passwd|pwd)\S* \d+\s*$|'
                    r'^\s*(?:CREATE TABLE|PRIMARY KEY|UNIQUE KEY|KEY `|`\w+` (?:varchar|text|int|char|tinyint|bigint|blob|datetime))|'
                    r'password_format\s*=|"(?:filename|pathto|path|file)"\s*:', re.I)
REVIEW_IGNORE = re.compile(r'\w*(?:secret|pass\w*|pwd|pin|key|token)\w*=(?:""|\'\')|"\w*(?:secret|pass\w*|pwd|pin|key|token)\w*"\s*:\s*""|<(Name|name|Description|description)>[^<]*</\1>|'
                           r'"(?:keyword|attribute|setting|option|param|parameter|property|variable)"\s*:\s*"[^"]*"|'
                           r'[\'`"]\w*(?:secret|pass\w*|pwd|pin|key|token)\w*[\'`"]\s*[,)]|^\s*\[[^\]]+\]\s*$', re.I | re.M)
CERT_BEGIN = re.compile(r'-----BEGIN [A-Z0-9 ]*(?:CERTIFICATE|PUBLIC KEY)[A-Z ]*-----')
CERT_END = re.compile(r'-----END [A-Z0-9 ]*(?:CERTIFICATE|PUBLIC KEY)[A-Z ]*-----')
COMMENT = re.compile(r'^\s*(?:;|#|//|--|!)')
# Credentials embedded as user:password@host, in URLs or in Fortinet backup/automation commands.
URL_CRED = re.compile(r'(?i)\b[a-z][a-z0-9+.-]*://([^:/@\s"\']+):([^\s"\']+)@([^@\s"\'/]+)')
CMD_CRED = re.compile(r'([A-Za-z0-9._-]+):([^\s"\']+)@([^@\s"\'/:]+)')
CMD_CRED_TRIGGER = re.compile(r'(?i)set script|execute backup|execute restore')
# Asterisk: register => [peer?][transport://]user[@domain]:secret[:authuser]@host, and dial strings with credentials.
AST_REGISTER = re.compile(r'(?i)^\s*register\s*=>\s*(?:\w+\?)?(?:\w+://)?[^\s:]+(?:@[^\s:@]+)?:(?P<secret>[^:@\s]+)(?=(?::[^@\s]+)?@)')
AST_DIAL = re.compile(r'(?i)\b(?:SIP|PJSIP|IAX2?|SKINNY)/[^/:@\s,()]+:(?P<secret>[^@/\s,()]+)@')
# Dialplan assignments to a secret-named key: Set(DB(AMPUSER/103/password)=x), Set(SECRET=x)
DIALPLAN_SET = re.compile(r'(?i)\bSet\((?:\w+\([^()]*?)?[\w/]*(?:password|passwd|secret|pin|pwd|token)\s*\)?\s*=\s*(?P<val>[^,)]+)')
# Asterisk voicemail.conf: mailbox => PIN,Full Name,email,pager,options
VM_ENTRY = re.compile(r'^(\s*\d+\s*=>\s*)(\d{2,})(\s*,)')
VM_NAME_ENTRY = re.compile(r'^\s*\d+\s*=>\s*(?:\d{2,}|REDACTED)\s*,')
INI_SECTION = re.compile(r'^\s*\[([^\]\n]+)\]')
# FreePBX tables stored as keyword/data rows (sip, iax, pjsip, queues_details...): the keyword names the secret.
KW_NAMES = {'keyword', 'attribute', 'setting', 'option', 'param', 'parameter', 'property', 'variable', 'var'}
VAL_NAMES = {'data', 'value', 'val', 'content', 'setting_value', 'option_value', 'param_value'}
JSON_KEYWORD = re.compile(r'"(?:keyword|attribute|setting|option|param|parameter|property|variable)"\s*:\s*"(?P<name>[^"]*)"')
JSON_DATA = re.compile(r'"(?:data|value|val|content)"\s*:\s*(?P<val>"(?:\\.|[^"\\])*")')
SQL_CREATE = re.compile(r'(?i)^\s*CREATE\s+(?:TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"\[]?(?:\w+[`"\]]?\.)?[`"\[]?(?P<table>\w+)[`"\]]?\s*(?P<paren>\()?')
SQL_INSERT = re.compile(r'(?i)^\s*(?:INSERT|REPLACE)\s+(?:IGNORE\s+)?INTO\s+[`"\[]?(?:\w+[`"\]]?\.)?[`"\[]?(?P<table>\w+)[`"\]]?\s*(?:\((?P<cols>[^)]*)\))?\s*VALUES\s*')
SQL_COPY = re.compile(r'(?i)^\s*COPY\s+(?:\w+\.)?"?(?P<table>\w+)"?\s*\((?P<cols>[^)]*)\)\s+FROM\s+stdin')
SQL_STRING = re.compile(r"'(?:[^'\\]|\\.|'')*'")
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
    if len(low) > 6 and low.endswith(SETTING_SUFFIX):
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
        self.ini_secret = False   # inside an INI section whose name says it holds secrets ([secret])
        self.kw_secret = False    # a JSON "keyword" naming a secret was seen; the next "data" is its value
        self.sql_tables = {}      # table -> list of column names, from CREATE TABLE statements
        self.sql_create = None    # table whose CREATE TABLE is being read line by line
        self.sql_copy = None      # columns of a PostgreSQL COPY block being read
        self.sql_insert = None    # columns of an INSERT whose rows continue on the following lines


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


SQL_CONSTRAINTS = {'PRIMARY', 'KEY', 'UNIQUE', 'INDEX', 'CONSTRAINT', 'FOREIGN', 'CHECK', 'FULLTEXT', 'SPATIAL', 'PERIOD'}


def split_top(text, sep=','):
    """Split on sep outside quotes and parentheses; returns (start, end) spans of the items."""
    items, start, depth, i, n = [], 0, 0, 0, len(text)
    while i < n:
        c = text[i]
        if c in '\'"`':
            m = SQL_STRING.match(text, i) if c == "'" else re.compile(c + r'(?:[^' + c + r'\\]|\\.)*' + c).match(text, i)
            if not m:
                break
            i = m.end()
            continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        elif c == sep and depth == 0:
            items.append((start, i))
            start = i + 1
        i += 1
    items.append((start, n))
    return items


def sql_columns(defs):
    """Column names from the body of a CREATE TABLE (...)."""
    cols = []
    for s, e in split_top(defs):
        m = re.match(r'\s*[`"\[]?(\w+)[`"\]]?', defs[s:e])
        if m and m.group(1).upper() not in SQL_CONSTRAINTS:
            cols.append(m.group(1).lower())
    return cols


def sql_tuples(body, start):
    """(start, end) spans of the items of every (...) tuple that follows position start."""
    tuples, i, n = [], start, len(body)
    while i < n:
        c = body[i]
        if c == '(':
            depth, j = 1, i + 1
            while j < n and depth:
                ch = body[j]
                if ch in '\'"':
                    m = SQL_STRING.match(body, j) if ch == "'" else re.compile(r'"(?:[^"\\]|\\.)*"').match(body, j)
                    if not m:
                        return tuples
                    j = m.end()
                    continue
                depth += (ch == '(') - (ch == ')')
                j += 1
            inner = body[i + 1:j - 1]
            tuples.append([(i + 1 + s, i + 1 + e) for s, e in split_top(inner)])
            i = j
        elif c == ';':
            break
        else:
            i += 1
    return tuples


def sql_row_spans(body, items, cols, strings=True):
    """Spans to mask in one row: secret columns, and the value column of keyword/value rows."""
    spans = []
    kw = [k for k, c in enumerate(cols) if c in KW_NAMES]
    val = [k for k, c in enumerate(cols) if c in VAL_NAMES]
    targets = [k for k, c in enumerate(cols) if is_secret_name(c)]
    if kw and val and kw[0] < len(items):
        s, e = items[kw[0]]
        name = unquote(body[s:e].strip()) if strings else body[s:e].strip()
        if is_secret_name(name):
            targets += val
    for k in targets:
        if k >= len(items):
            continue
        s, e = items[k]
        raw = body[s:e]
        v = raw.strip()
        if strings:
            if v[:1] not in '\'"' or trivial(v) or v.strip('\'"').upper() in ('NULL', 'REDACTED'):
                continue
            lead = len(raw) - len(raw.lstrip())
            spans.append((s + lead, s + lead + len(v), v[0] + 'REDACTED' + v[0]))
        elif v and v not in ('\\N', 'REDACTED'):
            spans.append((s, e, 'REDACTED'))
    return spans


def iter_sql_rows(text):
    """(table, columns, values) for every INSERT row and COPY line of a SQL dump; values are unquoted strings or None."""
    ctx = Context()
    insert_table = None
    for line in text.splitlines():
        body = line.rstrip('\r\n')
        if ctx.sql_create is not None or (ctx.sql_copy is None and ctx.sql_insert is None and SQL_CREATE.match(body)):
            scan_sql(body, ctx)
            continue
        if ctx.sql_copy is not None:
            if body.strip() == '\\.':
                ctx.sql_copy = None
            else:
                yield insert_table, ctx.sql_copy, [None if f == '\\N' else f for f in body.split('\t')]
            continue
        m = SQL_COPY.match(body)
        if m:
            insert_table = m.group('table').lower()
            scan_sql(body, ctx)
            continue
        m = SQL_INSERT.match(body)
        if m or ctx.sql_insert is not None:
            if m:
                insert_table = m.group('table').lower()
            cols, start = (ctx.sql_insert, 0) if not m else (None, m.end())
            scan_sql(body, ctx)  # keeps ctx.sql_insert up to date
            cols = cols or ctx.sql_insert or (ctx.sql_tables.get(insert_table, []) if m else [])
            if m and m.group('cols'):
                cols = [c.strip().strip('`"[]').lower() for c in m.group('cols').split(',')]
            if not cols:
                continue
            for items in sql_tuples(body, start):
                values = []
                for a, b in items:
                    v = body[a:b].strip()
                    values.append(unquote(v).replace("''", "'").replace("\\'", "'") if v[:1] in '\'"' else None)
                yield insert_table, cols, values


def scan_sql(body, ctx):
    """SQL dumps: secret columns of INSERT rows and PostgreSQL COPY blocks, found through CREATE TABLE."""
    spans = []
    if ctx.sql_create is not None:
        s = body.strip()
        if s.startswith(')'):
            ctx.sql_create = None
        elif s and not s.startswith(('--', '/*')):
            ctx.sql_tables[ctx.sql_create] += sql_columns(s.rstrip(','))
        return spans
    if ctx.sql_copy is not None:
        if body.strip() == '\\.':
            ctx.sql_copy = None
            return spans
        line = body.rstrip('\r\n')
        items, pos = [], 0
        for f in line.split('\t'):
            items.append((pos, pos + len(f)))
            pos += len(f) + 1
        return sql_row_spans(body, items, ctx.sql_copy, strings=False)
    m = SQL_CREATE.match(body)
    if m:
        table = m.group('table').lower()
        rest = body[m.end():]
        if m.group('paren') and ')' in rest and re.search(r'\)\s*(?:ENGINE|WITH|;|$)', rest.rstrip(), re.I):
            close = rest.rfind(')')
            ctx.sql_tables[table] = sql_columns(rest[:close])
        else:
            ctx.sql_tables[table] = []
            ctx.sql_create = table
        return spans
    m = SQL_COPY.match(body)
    if m:
        ctx.sql_copy = [c.strip().strip('"').lower() for c in m.group('cols').split(',')]
        return spans
    m = SQL_INSERT.match(body)
    if m or ctx.sql_insert is not None:
        if m:
            cols = ([c.strip().strip('`"[]').lower() for c in m.group('cols').split(',')] if m.group('cols')
                    else ctx.sql_tables.get(m.group('table').lower(), []))
            start = m.end()
        else:
            cols, start = ctx.sql_insert, 0
        if cols:
            for items in sql_tuples(body, start):
                spans += sql_row_spans(body, items, cols)
        # Rows may continue on the next lines until the statement ends with ";".
        ctx.sql_insert = cols if cols and not sql_statement_ends(body, start) else None
    return spans


def sql_statement_ends(body, start):
    i, n = start, len(body)
    while i < n:
        c = body[i]
        if c in '\'"':
            m = SQL_STRING.match(body, i) if c == "'" else re.compile(r'"(?:[^"\\]|\\.)*"').match(body, i)
            if not m:
                return False
            i = m.end()
            continue
        if c == ';':
            return True
        i += 1
    return False


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
    m = INI_SECTION.match(body)
    if m and not s.startswith('[['):
        name = m.group(1).strip()
        ctx.ini_secret = is_secret_name(name) and not name.startswith(('"', "'"))
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
    # Bare values under an INI section named after a secret, e.g. [secret] in FreePBX cdrpro_events.
    if ctx.ini_secret and stripped and not stripped.startswith(('[', ';', '#')) and '=' not in stripped:
        return body[:len(body) - len(stripped)] + 'REDACTED' + newline, True
    spans = []
    for m in ([AST_REGISTER.match(body)] if '=>' in body else []) + list(AST_DIAL.finditer(body)):
        if m and m.group('secret').lower() != 'redacted':
            spans.append((m.start('secret'), m.end('secret'), 'REDACTED'))
    m = VM_ENTRY.match(body)
    if m:
        spans.append((m.start(2), m.end(2), 'REDACTED'))
    for m in DIALPLAN_SET.finditer(body):
        if not trivial(m.group('val')) and m.group('val').strip().lower() != 'redacted':
            spans.append((m.start('val'), m.end('val'), 'REDACTED'))
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
        kw = JSON_KEYWORD.search(body)
        if kw:
            ctx.kw_secret = is_secret_name(kw.group('name'))
        d = JSON_DATA.search(body, kw.end() if kw else 0)
        if ctx.kw_secret and d and not trivial(d.group('val')) and not spans_cover(spans, d.start('val')):
            spans.append((d.start('val'), d.end('val'), '"REDACTED"'))
            ctx.kw_secret = False
        if '}' in body and not kw:
            ctx.kw_secret = False
    is_sql = ctx.sql_create is not None or ctx.sql_copy is not None or ctx.sql_insert is not None or bool(
        SQL_CREATE.match(body) or SQL_INSERT.match(body) or SQL_COPY.match(body))
    if is_sql:
        spans += [s for s in scan_sql(body, ctx) if not spans_cover(spans, s[0])]
    if is_xml or re.search(r'<[A-Za-z_][\w.:-]*[\s>]', body):
        spans += [s for s in scan_xml(body, ctx) if not spans_cover(spans, s[0])]
    if not is_json and not is_sql:
        spans += [s for s in scan_kv(body, ctx) if not spans_cover(spans, s[0])]
        for rx in (EXOS_ACCOUNT, SNMP_HOST):
            m = rx.search(body)
            if m and not spans_cover(spans, m.start(2)) and not (rx is SNMP_HOST and ' community ' in body.lower()):
                if not trivial(m.group(2)) and m.group(2).strip('"\'').lower() != 'redacted':
                    spans.append((m.start(2), m.end(2), mask(m.group(2))))
    if not is_json and not is_xml and not is_sql and not stripped.startswith('/'):
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
        ('FreePBX module data (JSON)', '"pbx_version"' in low and '"module"' in low),
        ('Asterisk / FreePBX configuration', re.search(r'(?im)^\s*(?:exten|same)\s*=>|^\s*type\s*=\s*(?:endpoint|friend|peer|aor|auth|identify|registration)\s*$|'
                                                       r'auto-generated by freepbx|^\s*register\s*=>|^;.*asterisk', head)),
        ('SQL dump', re.search(r'(?im)^\s*(?:CREATE TABLE|INSERT INTO|COPY \S+ .*FROM stdin|-- MySQL dump|-- PostgreSQL database dump)', head)),
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
        elif not (in_cert or starts_cert) and SUSPECT.search(REVIEW_IGNORE.sub('', line)) and not BENIGN.search(line) \
                and not (COMMENT.match(line) and '=' not in line and ':' not in line):
            review.append(number)  # prose comments are not flagged, commented-out assignments are
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
                       r'contact[-_]?name|fname|lname|displayname|callerid|cid_name|calleridname|outboundcid)"\s*:\s*"([^"]+)"|'
                       r'(?<![\w-])(first[-_]?name|last[-_]?name|full[-_]?name|display[-_]?name)\s*=\s*("[^"]+"|\S+)')
# Asterisk: caller ID names and SIP/IAX account names (the number part <1001> is left alone).
AST_CALLERID = re.compile(r'(?i)^\s*(?:callerid|cid_name|calleridname|fullname|outboundcid)\s*=>?\s*(.+?)\s*$')
AST_USER = re.compile(r'(?i)^\s*(?:username|fromuser|defaultuser|authuser|auth_username|remoteuser|user_name)\s*=>?\s*(\S+)')
USER_KEYS = re.compile(r'(?i)"(?:username|fromuser|defaultuser|authuser|auth_username|user_name)"\s*:\s*"([^"]+)"')
NAME_SET = re.compile(r'(?i)^\s*set (first-name|last-name|fullname|full-name|display-name|contact|company) (".*?"|\S+)')
USER_CMD = re.compile(r'(?i)^\s*(?:no\s+)?(?:username|user name|users passwd|local-user)\s+("[^"]+"|\S+)')
GENERIC_ACCOUNTS = {'admin', 'administrator', 'root', 'guest', 'operator', 'support', 'user', 'users', 'monitor',
                    'readonly', 'read-only', 'maintenance', 'ubnt', 'cisco', 'manager', 'default', 'test', 'service',
                    'backup', 'api', 'rwa', 'rw', 'ro', 'super', 'superuser', 'tech', 'technician', 'helpdesk',
                    'name', 'group', 'none', 'all', 'any'}
NAME_STOP = {'none', 'null', 'true', 'false', 'default', 'admin', 'user', 'test', 'name', 'unknown', 'reception',
             'centralino', 'ufficio', 'office', 'fax', 'voicemail', 'queue', 'ivr', 'operator', 'operatore',
             'redacted', 'asterisk', 'freepbx', 'device', 'devices', 'extension', 'trunk', 'sip', 'pjsip', 'iax',
             'iax2', 'dahdi', 'mobile', 'cell', 'home', 'work', 'main', 'general', 'anonymous', 'unavailable'}
WORD = re.compile(r"[A-Za-z0-9\u00c0-\u024f][\w.'\u00c0-\u024f-]*")

# Identities (level 2): hostnames, domains, IP and MAC addresses, user-supplied words.
HOST_CMD = re.compile(r'(?i)^\s*(?:set\s+)?(?:hostname|host-name|sysname|switchname|system-name|device-name|'
                      r'set system host-name)\s+("[^"]+"|\S+)\s*;?\s*$')
HOST_TAGS = re.compile(r'<(hostname|HostName|externalFqdn|systemName|system-name|sysname|device-name)>([^<]+)</\1>', re.I)
HOST_KV = re.compile(r'(?i)(?:^|\s)(?:hostname|host-name|identity|sysname|system\.name|resolv\.host\.1\.name)=("[^"]+"|\S+)')
DOMAIN_CMD = re.compile(r'(?i)^\s*(?:set\s+|ip\s+|ipv6\s+|dns\s+)?(?:domain[- ]name|domain|domainname|'
                        r'ip domain list|ip domain-list|search-domain|dns-suffix)\s+("[^"]+"|[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*;?\s*$')
DOMAIN_TAGS = re.compile(r'<(domain|domainName|dnsDomain|searchDomain|ldapDomain)>([^<]+)</\1>', re.I)
IPV4 = re.compile(r'(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])')
IPV6 = re.compile(r'(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}(?::?[0-9A-Fa-f]{1,4}){1,6}(?![\w:])|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){1,7}:(?![\w:])')
MAC = re.compile(r'(?<![\w:.-])(?:[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![\w:.-])')
VERSION_CONTEXT = re.compile(r'(?i)(?<![a-z])(?:version|build|release|firmware|fw|ver|v)[\s=:"\'-]*$')
MAC_SHAPED = re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
DOC_RANGES = [('192.0.2.', 1, 254), ('198.51.100.', 1, 254), ('203.0.113.', 1, 254)]
# Well-known public resolvers and similar: they say nothing about the customer, so they stay readable.
WELL_KNOWN_IPS = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112',
                  '208.67.222.222', '208.67.220.220', '4.2.2.1', '4.2.2.2'}
GENERIC_HOSTS = {'router', 'switch', 'firewall', 'fw', 'gw', 'gateway', 'core', 'localhost', 'default', 'none',
                 'ubnt', 'mikrotik', 'routeros', 'fortigate', 'fortiweb', 'zywall', 'usg', 'atp', 'pbx', '3cx'}
GENERIC_DOMAINS = {'local', 'lan', 'localdomain', 'home', 'internal', 'example.com', 'example.net', 'example.org'}


def classify_ipv4(ip):
    """'keep' for addresses that identify nothing, 'private' for RFC 1918, 'public' otherwise."""
    if ip in WELL_KNOWN_IPS:
        return 'keep'
    a, b, c, d = (int(x) for x in ip.split('.'))
    if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
        return 'private'
    if a in (0, 127) or a >= 224 or (a == 169 and b == 254) or (a == 100 and 64 <= b <= 127):
        return 'keep'
    if (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)) or (a == 198 and b in (18, 19)):
        return 'keep'  # documentation and benchmarking ranges: already anonymous
    # Netmasks (1...10...0) and wildcard masks (0...01...1) identify nothing.
    bits = (a << 24) | (b << 16) | (c << 8) | d
    inv = bits ^ 0xFFFFFFFF
    if (bits & (bits + 1)) == 0 or (inv & (inv + 1)) == 0:
        return 'keep'
    return 'public'


def classify_ipv6(ip):
    low = ip.lower()
    if low in ('::', '::1') or low.startswith(('fe80:', 'fe9', 'fea', 'feb', 'fc', 'fd', 'ff', '2001:db8:', '::ffff:')):
        return 'keep'
    return 'public'


def mac_placeholder(tok):
    n = int(tok.split('_')[1])
    fake = '02%010x' % n
    return ':'.join(fake[i:i + 2] for i in range(0, 12, 2))


def classify_mac(mac):
    h = re.sub(r'[^0-9A-Fa-f]', '', mac).lower()
    if h in ('000000000000', 'ffffffffffff') or h.startswith(('01005e', '333300', '00005e0001', '00000c07ac', '0180c2')):
        return 'keep'
    if int(h[1], 16) & 2:
        return 'keep'  # locally administered: already synthetic (also our own output)
    return 'public'


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

    KINDS = ('NAME', 'USER', 'EMAIL', 'PHONE', 'HOST', 'DOMAIN', 'IP', 'IP6', 'MAC', 'WORD')

    def __init__(self, words=(), ip_mode='public', macs=True):
        self.maps = {k: {} for k in self.KINDS}
        self.keywords = set()
        self.ip_mode = ip_mode    # 'public' (default), 'all', or 'keep'
        self.macs = macs
        self.words = []
        for w in words:
            w = w.strip()
            if len(w) >= 3:
                self.words.append(w)
                self.token('WORD', w.lower())
        self.ip_count = 0
        self.host_case = {}

    def total(self):
        return sum(len(m) for m in self.maps.values())

    def token(self, kind, value):
        m = self.maps[kind]
        if value not in m:
            if kind == 'IP':
                m[value] = self.next_ipv4()
            elif kind == 'IP6':
                m[value] = '2001:db8::%x' % (len(m) + 1)
            elif kind == 'DOMAIN':
                m[value] = 'example-%d.net' % (len(m) + 1)
            else:
                m[value] = '%s_%d' % (kind, len(m) + 1)
        return m[value]

    def next_ipv4(self):
        """Documentation ranges first (RFC 5737), then the benchmarking range 198.18.0.0/15 (RFC 2544)."""
        self.ip_count += 1
        n = self.ip_count
        for prefix, lo, hi in DOC_RANGES:
            if n <= hi - lo + 1:
                return '%s%d' % (prefix, lo + n - 1)
            n -= hi - lo + 1
        if n > 131070:
            raise ValueError('Too many distinct public IP addresses to anonymize consistently.')
        n += 0  # 198.18.0.1 onwards
        return '198.%d.%d.%d' % (18 + (n >> 16), (n >> 8) & 255, n & 255)

    def add_host(self, value):
        v = value.strip().strip('"\';')
        if '.' in v and not v.replace('.', '').isdigit():
            parts = v.split('.', 1)
            self.add_domain(parts[1])
            v = parts[0]
        if len(v) >= 3 and v.lower() not in GENERIC_HOSTS and not IPV4.fullmatch(v) and v.lower() != 'redacted':
            self.token('HOST', v.lower())
            self.host_case.setdefault(v.lower(), v)

    def add_domain(self, value):
        v = value.strip().strip('"\';').lower().rstrip('.')
        if len(v) >= 4 and '.' in v and v not in GENERIC_DOMAINS and not IPV4.fullmatch(v):
            self.token('DOMAIN', v)

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
        value = re.sub(r'<[^<>]*>', ' ', value)
        for w in re.split(r'[\s,;/()]+', value.strip().strip('"\'')):
            w = w.strip(".-'\"")
            if len(w) >= 3 and not w.isdigit() and w.lower() not in NAME_STOP and w.lower() not in self.keywords:
                self.token('NAME', w)

    def add_user(self, value):
        v = value.strip().strip('"\'')
        if len(v) >= 3 and v.lower() not in GENERIC_ACCOUNTS and v.lower() != 'redacted' and not v.isdigit() \
                and v.lower() not in self.keywords:
            self.token('USER', v)

    SQL_NAME_COLS = {'fname', 'lname', 'displayname', 'display_name', 'callerid', 'cid_name', 'outboundcid', 'fullname'}
    SQL_NAME_TABLES = {'users', 'devices', 'userman_users', 'extensions', 'sip', 'pjsip', 'iax'}
    SQL_USER_COLS = {'username', 'fromuser', 'user_name', 'auth_username'}
    NAME_KEYWORDS = {'callerid', 'cid_name', 'description', 'displayname', 'fullname', 'outboundcid'}

    def collect_sql(self, text):
        for table, cols, values in iter_sql_rows(text):
            kw = next((k for k, c in enumerate(cols) if c in KW_NAMES), None)
            val = next((k for k, c in enumerate(cols) if c in VAL_NAMES), None)
            for k, col in enumerate(cols):
                if k >= len(values) or values[k] is None:
                    continue
                if col in self.SQL_NAME_COLS or (col in ('name', 'description') and table in self.SQL_NAME_TABLES):
                    self.add_name(values[k])
                elif col in self.SQL_USER_COLS:
                    self.add_user(values[k])
            if kw is not None and val is not None and kw < len(values) and val < len(values) and values[kw] \
                    and values[kw].lower() in self.NAME_KEYWORDS and values[val]:
                self.add_name(values[val])

    def collect(self, text):
        self.learn_keywords(text)
        if re.search(r'(?im)^\s*(?:CREATE\s+(?:TEMPORARY\s+)?TABLE|(?:INSERT|REPLACE)\s+(?:IGNORE\s+)?INTO|COPY\s+\S+.*FROM\s+stdin)', text):
            self.collect_sql(text)
        forti, ros = [], ''
        since_extension = since_tech = 99
        for line in text.splitlines():
            # FreePBX module data: {"extension": "101", ..., "name": "John Smith"} and devices with "description".
            since_extension = 0 if re.search(r'"extension"\s*:\s*"\d+"', line) else since_extension + 1
            since_tech = 0 if re.search(r'"(?:tech|devicetype)"\s*:\s*"', line) else since_tech + 1
            m = re.search(r'"name"\s*:\s*"([^"]+)"', line)
            if m and since_extension <= 3:
                self.add_name(m.group(1))
            m = re.search(r'"description"\s*:\s*"([^"]+)"', line)
            if m and since_tech <= 6:
                self.add_name(m.group(1))
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
            m = AST_USER.match(line)
            if m:
                self.add_user(m.group(1))
            for m in USER_KEYS.finditer(line):
                self.add_user(m.group(1))
            m = AST_CALLERID.match(line)
            if m:
                self.add_name(m.group(1).split(';')[0])
            m = VM_NAME_ENTRY.match(line)
            if m:
                fields = line.split('=>', 1)[1].split(',')
                if len(fields) > 1:
                    self.add_name(fields[1])
            m = HOST_CMD.match(line)
            if m:
                self.add_host(m.group(1))
            for m in HOST_TAGS.finditer(line):
                self.add_host(m.group(2))
            if ros == '/system identity':
                for m in re.finditer(r'(?:^|\s)name=("[^"]+"|\S+)', line):
                    self.add_host(m.group(1))
            elif line.lstrip().startswith(('hostname=', 'system.name=', 'resolv.host')):
                for m in HOST_KV.finditer(line):
                    self.add_host(m.group(1))
            m = DOMAIN_CMD.match(line)
            if m:
                self.add_domain(m.group(1))
            for m in DOMAIN_TAGS.finditer(line):
                self.add_domain(m.group(2))
            if forti and forti[-1] in ('user local', 'system admin'):
                e = re.match(r'^\s*edit\s+("[^"]+"|\S+)', line)
                if e:
                    self.add_user(e.group(1))
            if ros in ('/user', '/ppp secret', '/ip hotspot user', '/user-manager user'):
                for kv in re.finditer(r'(?:^|\s)name=("[^"]+"|\S+)', line):
                    self.add_user(kv.group(1))

    def apply(self, text):
        """Replace emails, phone numbers, identities and the collected names everywhere in the text."""
        counts = {k: 0 for k in self.KINDS}

        def email(m):
            before = m.string[max(0, m.start() - 60):m.start()]
            # user:REDACTED@host and user:secret:authuser@host are credentials, not addresses.
            if m.group().split('@')[0].lower() == 'redacted' or (
                    before.endswith(':') and re.search(r'(?i)register\s*=>|://|[A-Z0-9]+/\S*$', before)):
                return m.group()
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
        text = self.apply_hosts(text, counts)
        text = self.apply_words(text, counts)
        text = self.apply_addresses(text, counts)
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

    def apply_hosts(self, text, counts):
        """Hostnames (as whole tokens, also inside FQDNs) and domains (as suffixes or alone)."""
        hosts = sorted(self.maps['HOST'], key=len, reverse=True)
        if hosts:
            rx = re.compile(r'(?<![\w-])(' + '|'.join(re.escape(h) for h in hosts) + r')(?![\w-])', re.I)

            def host(m):
                counts['HOST'] += 1
                return self.maps['HOST'][m.group(1).lower()]
            text = rx.sub(host, text)
        domains = sorted(self.maps['DOMAIN'], key=len, reverse=True)
        if domains:
            rx = re.compile(r'(?<![\w-])(' + '|'.join(re.escape(d) for d in domains) + r')(?![\w-])', re.I)

            def domain(m):
                counts['DOMAIN'] += 1
                return self.maps['DOMAIN'][m.group(1).lower()]
            text = rx.sub(domain, text)
        return text

    def apply_words(self, text, counts):
        """User-supplied sensitive words, anywhere they appear, even inside longer tokens."""
        if not self.words:
            return text
        rx = re.compile('|'.join(re.escape(w) for w in sorted(self.words, key=len, reverse=True)), re.I)

        def word(m):
            counts['WORD'] += 1
            return self.maps['WORD'][m.group().lower()]
        return rx.sub(word, text)

    def apply_addresses(self, text, counts):
        if self.ip_mode != 'keep':
            def v4(m):
                ip = m.group()
                kind = classify_ipv4(ip)
                if kind == 'keep' or (kind == 'private' and self.ip_mode != 'all'):
                    return ip
                if VERSION_CONTEXT.search(m.string[max(0, m.start() - 20):m.start()]):
                    return ip  # a four-part version number, not an address
                counts['IP'] += 1
                return self.token('IP', ip)

            def v6(m):
                ip = m.group()
                if classify_ipv6(ip) == 'keep' or ip.count(':') < 2 or MAC_SHAPED.fullmatch(ip):
                    return ip
                counts['IP6'] += 1
                return self.token('IP6', ip.lower())
            text = IPV4.sub(v4, text)
            text = IPV6.sub(v6, text)
        if self.macs:
            def mac(m):
                raw = m.group()
                if classify_mac(raw) == 'keep':
                    return raw
                counts['MAC'] += 1
                h = re.sub(r'[^0-9A-Fa-f]', '', raw).lower()
                tok = self.token('MAC', ':'.join(h[i:i + 2] for i in range(0, 12, 2)))
                n = int(tok.split('_')[1])
                fake = '02%010x' % n
                if '.' in raw:
                    return '%s.%s.%s' % (fake[0:4], fake[4:8], fake[8:12])
                sep = ':' if ':' in raw else '-'
                out = sep.join(fake[i:i + 2] for i in range(0, 12, 2))
                return out.upper() if raw.upper() == raw and any(c.isalpha() for c in raw) else out
            text = MAC.sub(mac, text)
        return text

    def map_dict(self, sources):
        """Placeholder -> real value, grouped by kind, ready to be written as JSON."""
        out = {
            '_warning': 'This file links placeholders to REAL personal data. Keep it local, never share it.',
            'tool': 'netblur', 'version': VERSION,
            'created': datetime.now().isoformat(timespec='seconds'),
            'sources': list(sources),
        }
        keys = {'NAME': 'names', 'USER': 'users', 'EMAIL': 'emails', 'PHONE': 'phones', 'HOST': 'hosts',
                'DOMAIN': 'domains', 'IP': 'ips', 'IP6': 'ipv6', 'MAC': 'macs', 'WORD': 'words'}
        for kind in self.KINDS:
            table = self.maps[kind]
            if kind == 'MAC':
                table = {k: mac_placeholder(v) for k, v in table.items()}
            if kind == 'HOST':
                table = {self.host_case.get(k, k): v for k, v in table.items()}
            out[keys[kind]] = {tok: value for value, tok in table.items()}
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
GZ_LIMIT = 256 * 1024 * 1024        # largest gzip content expanded in memory
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


class Member:
    """One file inside an archive: name, size and a function that reads its bytes."""

    def __init__(self, name, size, read):
        self.name, self.size, self.read = name.replace('\\', '/'), size, read


def read_member(member):
    if member.size > MAX_ENTRY_SIZE:
        raise ValueError('The file inside the archive is too large to process safely.')
    return member.read()


def gunzip(fileobj, limit=GZ_LIMIT):
    try:
        with gzip.GzipFile(fileobj=fileobj) as g:
            data = g.read(limit + 1)
    except (OSError, EOFError):
        raise ValueError('The gzip data is damaged or not really gzip.')
    if len(data) > limit:
        raise ValueError('The compressed file is too large to process safely.')
    return data


def safe_relative(name):
    """Path inside the output folder: no absolute parts, no '..', or None when nothing is left."""
    parts = [p for p in name.replace('\\', '/').split('/') if p not in ('', '.', '..')]
    return Path(*parts) if parts else None


def archive_stem(src):
    stem = src.stem
    if stem.lower().endswith('.tar'):
        stem = stem[:-4]
    return stem


AUDIO_EXT = {'.wav', '.alaw', '.ulaw', '.g722', '.g729', '.gsm', '.sln', '.sln16', '.sln48', '.mp3', '.ogg', '.opus',
             '.wma', '.m4a', '.aac', '.flac'}
BINARY_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.pdf', '.so', '.dll', '.exe', '.bin', '.pyc',
              '.woff', '.woff2', '.ttf', '.eot', '.db', '.sqlite', '.sqlite3', '.rrd', '.tdb', '.mp4', '.mov'}


def archive_policy(members):
    """(label, skip_reason) for an archive: skip_reason(name) returns None for files to process."""
    names = [m.name for m in members]

    def generic(name):
        ext = Path(name).suffix.lower()
        if ext in AUDIO_EXT:
            return 'audio files'
        if ext in BINARY_EXT:
            return 'binary files'
        return None

    if any('/' not in n and re.fullmatch(r'\d*Db\.xml', n) for n in names):
        # 3CX backup: database tables, recordings, voicemail, prompts, certificates and phone
        # provisioning files are never written out; only the configuration is sanitized.
        def three_cx(name):
            if '/' not in name and re.fullmatch(r'\d*Db\.xml', name):
                return None
            return name.split('/')[0] if '/' in name else 'other files at the root'
        return '3CX backup. Only the configuration file is processed.', three_cx
    if any(n.startswith('modulejson/') for n in names) or any('/etc/asterisk/' in n for n in names):
        # FreePBX backup: call records (CDR/CEL), audio and voicemail are never written out.
        def freepbx(name):
            if '/cdr_dump/' in name or '/cel_dump/' in name:
                return 'call records (CDR/CEL)'
            if '/var/lib/asterisk/moh/' in name or '/var/lib/asterisk/sounds/' in name or '/var/spool/asterisk/' in name:
                return 'audio and voicemail'
            return generic(name)
        return 'FreePBX / Asterisk backup. Configuration, module data and SQL dumps are processed.', freepbx
    return None, generic


class Run:
    """One invocation: options, the personal-data map shared by every file, counters and the log."""

    def __init__(self, args):
        self.args = args
        self.privacy = None
        if args.personal:
            words = list(args.words or [])
            if args.words_file:
                words += [w for w in Path(args.words_file).read_text(encoding='utf-8').splitlines()]
            ip_mode = 'keep' if args.keep_ips else 'all' if args.all_ips else 'public'
            self.privacy = Privacy(words=words, ip_mode=ip_mode, macs=not args.keep_macs)
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

    # ---------------------------------------------------------------- archives
    def handle_zip(self, src, rel_parent):
        try:
            archive = zipfile.ZipFile(src)
        except zipfile.BadZipFile:
            raise ValueError('The ZIP archive is damaged or not a real ZIP file.')
        with archive:
            infos = [i for i in archive.infolist() if not i.is_dir()]
            if any(i.flag_bits & 0x1 for i in infos):
                raise ValueError('The ZIP archive is password protected: extract it manually first.')
            members = [Member(i.filename, i.file_size, lambda i=i: archive.read(i)) for i in infos]
            self.handle_archive(src, rel_parent, members, 'ZIP archive')

    def handle_tar(self, src, rel_parent, fileobj=None):
        try:
            archive = tarfile.open(src if fileobj is None else None, 'r:*', fileobj=fileobj)
        except (tarfile.TarError, EOFError):
            raise ValueError('The TAR archive is damaged or not a real TAR file.')
        with archive:
            members = [Member(i.name, i.size, lambda i=i: archive.extractfile(i).read())
                       for i in archive.getmembers() if i.isfile()]
            self.handle_archive(src, rel_parent, members, 'TAR archive')

    def handle_gzip(self, src, rel_parent):
        with src.open('rb') as f:
            raw = gunzip(f)
        if raw[257:262] == b'ustar' or src.name.lower().endswith(('.tar.gz', '.tgz')):
            return self.handle_tar(src, rel_parent, fileobj=io.BytesIO(raw))
        inner = Path(src.stem)  # "running.conf.gz" -> "running.conf"
        self.handle_bytes(raw, src, rel_parent, inner.stem, inner.suffix or '.txt', src.name + ' (gzip, read in memory)')

    def handle_archive(self, src, rel_parent, members, kind):
        self.say('File:', src.name, '(%s, read in memory)' % kind)
        if not members:
            raise ValueError('The archive contains no files.')
        label, skip_reason = archive_policy(members)
        if label:
            self.say('Likely content:', label)
        kept, skipped = [], {}
        for m in members:
            reason = skip_reason(m.name)
            if reason is None and safe_relative(m.name) is None:
                reason = 'unsafe path'
            if reason is None:
                kept.append(m)
            else:
                n, size = skipped.get(reason, (0, 0))
                skipped[reason] = (n + 1, size + m.size)
        for reason, (n, size) in sorted(skipped.items()):
            self.say('  Skipped: %-28s %5d file(s) %10.1f MB' % (reason, n, size / 1048576))
        if not kept:
            raise ValueError('The archive holds no text files to process.')
        stem = archive_stem(src)
        if len(kept) == 1:
            # One file: the copy is named after the archive ("backup.conf.zip" -> "backup_SANITIZED.conf").
            inner = Path(kept[0].name.split('/')[-1])
            suffix = Path(stem).suffix or inner.suffix
            stem = Path(stem).stem if Path(stem).suffix else stem
            self.say()
            self.handle_bytes(read_member(kept[0]), src, rel_parent, stem, suffix, '%s -> %s' % (src.name, kept[0].name))
            return
        if self.to_stdout or self.explicit_file is not None:
            raise ValueError('A single output works with a single file: this archive holds %d.' % len(kept))
        self.handle_archive_folder(src, rel_parent, kept, stem)

    def handle_archive_folder(self, src, rel_parent, kept, stem):
        """Several files inside one archive: a folder with the same tree, one sanitized copy per file."""
        results, unreadable = [], {}
        for m in kept:
            rel = safe_relative(m.name)
            try:
                raw = read_member(m)
                if rel.suffix.lower() == '.gz':
                    raw, rel = gunzip(io.BytesIO(raw)), rel.with_suffix('')
                results.append((rel, sanitize_bytes(raw, self.privacy)))
            except ValueError as exc:
                key = str(exc).split(':')[0].rstrip('.')
                n, size = unreadable.get(key, (0, 0))
                unreadable[key] = (n + 1, size + m.size)
        for reason, (n, size) in sorted(unreadable.items()):
            self.say('  Skipped: %-28s %5d file(s) %10.1f MB' % (reason, n, size / 1048576))
        if not results:
            raise ValueError('The archive holds no text files to process.')
        any_change = any(r.changed or r.personal_hits for _, r in results)
        tag = ('_ANONYMIZED' if self.args.personal else '_SANITIZED') if any_change else '_NO-SECRETS-FOUND'
        base = self.output_dir / rel_parent if self.output_dir is not None else src.parent
        base.mkdir(parents=True, exist_ok=True)
        folder = unique_path(base, stem, tag)
        folder.mkdir()
        self.say('Folder created:', folder.name, '(%d files, same tree as the archive)' % len(results))
        untouched = []
        for rel, result in results:
            dst = folder / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            with dst.open('xb') as f:
                f.write(result.data)
            self.outputs.append(dst)
            self.written += 1
            if result.changed or result.personal_hits:
                extra = ''
                if self.privacy is not None and result.personal_hits:
                    extra += ', %d personal value(s)' % result.personal_hits
                if result.review:
                    shown = ', '.join(map(str, result.review[:20]))
                    extra += '; review lines ' + shown + (' ...' if len(result.review) > 20 else '')
                    self.flagged += len(result.review)
                self.say('  %s: %d line(s) masked%s' % (rel.as_posix(), len(result.changed), extra))
            else:
                untouched.append(rel.as_posix())
                if result.review:
                    self.flagged += len(result.review)
                    self.say('  %s: nothing masked; review lines %s' % (rel.as_posix(), ', '.join(map(str, result.review[:20]))))
        if untouched:
            self.say('  %d file(s) copied unchanged (nothing to mask): %s%s'
                     % (len(untouched), ', '.join(untouched[:8]), ' ...' if len(untouched) > 8 else ''))
        self.sources.append(src.name)
        if not any_change:
            self.no_secrets += 1
            self.say('WARNING: no secrets found in the whole archive. Check that it holds configuration')
            self.say('files whose syntax is supported, and review the copies before sharing them.')

    def handle_file(self, src, rel_parent=Path('.')):
        with src.open('rb') as f:
            head = f.read(512)
        if head[:2] == b'PK' and zipfile.is_zipfile(src):
            return self.handle_zip(src, rel_parent)
        if head[:2] == b'\x1f\x8b':
            return self.handle_gzip(src, rel_parent)
        if head[257:262] == b'ustar' or (src.suffix.lower() == '.tar' and tarfile.is_tarfile(src)):
            return self.handle_tar(src, rel_parent)
        self.handle_bytes(src.read_bytes(), src, rel_parent, src.stem, src.suffix, src.name)

    def handle_directory(self, root):
        count = 0
        for p in sorted(p for p in root.rglob('*') if p.is_file()):
            rel = p.relative_to(root)
            if any(part.startswith('.') or is_own_output(part) for part in rel.parts):
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
        if self.privacy is None or not self.privacy.total():
            return
        m = self.privacy.maps
        self.say()
        self.say('Identities replaced in this run: %d names, %d usernames, %d emails, %d phone numbers, %d hosts, '
                 '%d domains, %d IPv4, %d IPv6, %d MACs, %d words'
                 % tuple(len(m[k]) for k in Privacy.KINDS))
        if self.args.no_map:
            return
        path = self.map_destination()
        if path.exists() and not self.args.force:
            raise ValueError('Map file already exists (use --force to overwrite): ' + str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', encoding='utf-8') as f:
            json.dump(self.privacy.map_dict(self.sources), f, ensure_ascii=False, indent=2)
        self.say('Map of placeholders written (REAL personal data inside: keep it local, never share it):')
        self.say('  ' + str(path))


def resolve_output(args, run):
    """Decide whether -o names a directory or one file."""
    if args.output is None or run.to_stdout:
        return
    out = Path(args.output)
    many = len(args.input) > 1 or any(Path(i).is_dir() for i in args.input if i != STDIO)
    # A path without an extension is taken as a directory: configuration copies always keep theirs.
    looks_dir = out.is_dir() or args.output.endswith(('/', '\\')) or not out.suffix
    if many or looks_dir:
        out.mkdir(parents=True, exist_ok=True)
        run.output_dir = out.resolve()
    else:
        run.explicit_file = out


def build_parser():
    parser = argparse.ArgumentParser(prog='netblur', description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input', nargs='+', metavar='INPUT',
                        help='configuration file, archive (zip, tar, tar.gz, gz), directory, or - for standard input')
    parser.add_argument('-o', '--output', metavar='PATH',
                        help='output file (single input, with an extension) or directory; - for standard output')
    parser.add_argument('-p', '--personal', action='store_true',
                        help='level 2: also replace names, usernames, email addresses and phone numbers')
    parser.add_argument('-m', '--map', metavar='FILE',
                        help='where to write the JSON map of placeholders (default: next to the copies)')
    parser.add_argument('--no-map', action='store_true', help='do not write the map file')
    parser.add_argument('-w', '--words', metavar='WORD', action='append',
                        help='level 2: sensitive word to replace wherever it appears, even inside other words '
                             '(repeat the option or separate words with commas)')
    parser.add_argument('--words-file', metavar='FILE', help='level 2: file with one sensitive word per line')
    parser.add_argument('--all-ips', action='store_true',
                        help='level 2: also replace private IP addresses (default: public ones only)')
    parser.add_argument('--keep-ips', action='store_true', help='level 2: keep every IP address as it is')
    parser.add_argument('--keep-macs', action='store_true', help='level 2: keep MAC addresses as they are')
    parser.add_argument('--restore', action='store_true',
                        help='put the real values back into a text (for example an AI answer) using the map given with -m')
    parser.add_argument('--strict', action='store_true',
                        help='exit with status 2 when lines are flagged for review or a file had no secrets')
    parser.add_argument('--force', action='store_true',
                        help='allow overwriting the file named by -o or -m (never the originals)')
    parser.add_argument('--version', action='version', version='netblur ' + VERSION)
    return parser


def restore_text(text, mapping):
    """Replace every placeholder found in text with its real value."""
    table = {}
    for key in ('names', 'users', 'emails', 'phones', 'hosts', 'domains', 'ips', 'ipv6', 'words'):
        table.update(mapping.get(key, {}))
    for tok, real in mapping.get('macs', {}).items():
        h = tok.replace(':', '')
        table[tok] = real
        table[tok.upper()] = real
        table['-'.join(h[i:i + 2] for i in range(0, 12, 2))] = real
        table['%s.%s.%s' % (h[0:4], h[4:8], h[8:12])] = real
    if not table:
        return text, 0
    rx = re.compile(r'(?<![\w.:-])(' + '|'.join(re.escape(t) for t in sorted(table, key=len, reverse=True)) + r')(?![\w:-])')
    count = [0]

    def put(m):
        count[0] += 1
        return table[m.group(1)]
    return rx.sub(put, text), count[0]


def restore_main(args):
    if not args.map:
        print('--restore needs the map file: -m FILE', file=sys.stderr)
        return 1
    try:
        mapping = json.loads(Path(args.map).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print('Cannot read the map file:', getattr(exc, 'strerror', None) or exc, file=sys.stderr)
        return 1
    to_stdout = args.output == STDIO
    log = sys.stderr if to_stdout else sys.stdout
    failed = 0
    for item in args.input:
        try:
            if item == STDIO:
                raw, src = sys.stdin.buffer.read(), None
            else:
                src = Path(item)
                raw = src.read_bytes()
            text, enc = decode(raw)
            out, n = restore_text(text, mapping)
            if to_stdout:
                sys.stdout.buffer.write(out.encode(enc))
                sys.stdout.buffer.flush()
                dst = '(standard output)'
            else:
                if args.output and len(args.input) == 1:
                    dst = Path(args.output)
                    if dst.exists() and not args.force:
                        raise ValueError('Output file already exists (use --force to overwrite): ' + dst.name)
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.write_bytes(out.encode(enc))
                else:
                    folder = Path(args.output) if args.output else (src.parent if src else Path.cwd())
                    folder.mkdir(parents=True, exist_ok=True)
                    dst = unique_path(folder, (src.stem if src else 'stdin') + '_RESTORED', src.suffix if src else '.txt')
                    with dst.open('xb') as f:
                        f.write(out.encode(enc))
                dst = dst.name
            print('Restored %d placeholder(s) in %s -> %s' % (n, item, dst), file=log)
        except ValueError as exc:
            failed += 1
            print('Operation not completed:', exc, file=log)
        except FileNotFoundError:
            failed += 1
            print('Operation not completed: not found:', item, file=log)
        except Exception as exc:
            failed += 1
            print('Operation not completed (' + type(exc).__name__ + ').', file=log)
    print('The restored text contains REAL data: keep it local.', file=log)
    return 1 if failed else 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.words:
        args.words = [w for item in args.words for w in item.split(',')]
    if args.restore:
        return restore_main(args)
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
        except OSError as exc:
            run.failed += 1
            run.say('Operation not completed:', exc.strerror or type(exc).__name__)
        except Exception as exc:
            run.failed += 1
            # Never print contents or details that might contain secrets.
            run.say('Operation not completed (' + type(exc).__name__ + ').')
    try:
        run.write_map()
    except (ValueError, OSError) as exc:
        run.failed += 1
        run.say('Map not written:', getattr(exc, 'strerror', None) or exc)
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
