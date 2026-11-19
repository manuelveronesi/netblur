# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Manuel Veronesi
"""netblur guard, a Claude Code PreToolUse hook.

Before Claude reads a file (Read, Grep on a single file, or simple Bash and
PowerShell readers such as cat, head, grep, Get-Content), the guard runs the
netblur engine on that file locally. If netblur would mask something, the tool
call is denied and Claude is told to run netblur and read the sanitized copy.
netblur maps (PERSONAL-DATA-MAP) and restored texts (_RESTORED) are always
denied because they contain real values.

The guard never sends data anywhere and never writes files. It reads the hook
input on standard input and prints a decision on standard output. Set the
environment variable NETBLUR_GUARD=off before starting Claude Code to disable it.
This is a guardrail against mistakes, not a sandbox: a program written on
purpose to read the file can still get around it.
"""
import json
import os
import re
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MAX_SIZE = 20 * 1024 * 1024
# Source code, documentation, media and archives are never checked: the guard is about configurations.
SKIP_EXT = {
    '.py', '.pyw', '.pyi', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.go', '.rs', '.java', '.kt',
    '.kts', '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.php', '.rb', '.swift', '.scala', '.lua', '.r',
    '.sh', '.bash', '.zsh', '.fish', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.md', '.rst', '.adoc',
    '.html', '.htm', '.css', '.scss', '.less', '.vue', '.svelte', '.ipynb', '.lock', '.toml', '.svg',
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico', '.pdf', '.docx', '.xlsx', '.pptx',
    '.zip', '.tar', '.gz', '.tgz', '.7z', '.rar', '.unf', '.bin', '.exe', '.dll', '.so', '.dylib',
    '.mp3', '.wav', '.mp4', '.woff', '.woff2', '.ttf', '.otf',
}
READERS = {
    'cat', 'tac', 'head', 'tail', 'less', 'more', 'most', 'bat', 'batcat', 'nl', 'strings', 'xxd', 'od',
    'hexdump', 'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'sed', 'awk', 'gawk', 'cut', 'sort', 'uniq',
    'column', 'jq', 'yq', 'xmllint', 'diff', 'cmp', 'type', 'get-content', 'gc', 'select-string', 'sls',
    'findstr', 'more.com',
}
SEPARATORS = re.compile(r'\|\||&&|[|;&\n]|\$\(|`|<\(')
REAL_DATA = ('PERSONAL-DATA-MAP', '_RESTORED')


def decide(reason):
    print(json.dumps({'hookSpecificOutput': {
        'hookEventName': 'PreToolUse',
        'permissionDecision': 'deny',
        'permissionDecisionReason': reason,
    }}))
    sys.exit(0)


def tokens(command, powershell=False):
    """Candidate file arguments of the reading commands in a shell line."""
    found = []
    for segment in SEPARATORS.split(command):
        try:
            # PowerShell paths use backslashes, which POSIX splitting would treat as escapes.
            words = shlex.split(segment, posix=not powershell)
        except ValueError:
            words = segment.split()
        if powershell:
            words = [w.replace('\\', '/') for w in words]
        words = [w for w in words if not re.match(r'^\w+=', w)]  # leading VAR=value assignments
        if not words:
            continue
        name = os.path.basename(words[0].replace('\\', '/')).lower()
        if name in ('sudo', 'command', 'builtin', 'env') and len(words) > 1:
            words = words[1:]
            name = os.path.basename(words[0].replace('\\', '/')).lower()
        if name not in READERS:
            continue
        for w in words[1:]:
            w = w.lstrip('<').strip('"\'')
            if w.startswith('-') or not w:
                continue
            found.append(w)
    return found


def candidates(data):
    tool, inp = data.get('tool_name', ''), data.get('tool_input') or {}
    if tool == 'Read':
        return [inp.get('file_path', '')]
    if tool == 'Grep':
        return [inp.get('path', '')]
    if tool in ('Bash', 'PowerShell'):
        return tokens(inp.get('command', ''), powershell=tool == 'PowerShell')
    return []


def resolve(path, cwd):
    p = Path(os.path.expanduser(path))
    if not p.is_absolute():
        p = Path(cwd) / p
    try:
        return p.resolve()
    except OSError:
        return p


def check(path):
    """None when the file can be read, otherwise the reason to deny."""
    name = path.name
    if any(m in name for m in REAL_DATA):
        return ('netblur: %s contains real values (it is a netblur map or a restored text) and must stay '
                'on this computer. Do not read it: tell the user to open it locally if they need it.' % path)
    if not path.is_file() or path.suffix.lower() in SKIP_EXT:
        return None
    import netblur
    if netblur.is_own_output(name):
        return None
    try:
        if path.stat().st_size > MAX_SIZE:
            return None
        raw = path.read_bytes()
        result = netblur.sanitize_bytes(raw)
    except Exception:
        return None  # not a text configuration netblur understands
    if not result.changed:
        return None
    return ('netblur: %s still contains secrets (%d lines with passwords, keys, communities or similar). '
            'Do not read the original. Run netblur on it and read the copy it writes next to the original: '
            'python "%s" "%s" for secrets only (copy ending in _SANITIZED), or add --personal to also replace '
            'names, hostnames, public IP addresses and other identity data (copy ending in _ANONYMIZED). '
            'If the user explicitly wants the original read as it is, tell them they can restart Claude Code '
            'with the environment variable NETBLUR_GUARD=off.'
            % (path, len(result.changed), ROOT / 'netblur.py', path))


def main():
    if os.environ.get('NETBLUR_GUARD', '').strip().lower() in ('off', '0', 'false', 'no'):
        return
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return
    cwd = data.get('cwd') or os.getcwd()
    for item in candidates(data):
        if not item or any(c in item for c in '*?'):
            continue
        reason = check(resolve(item, cwd))
        if reason:
            decide(reason)


if __name__ == '__main__':
    main()
