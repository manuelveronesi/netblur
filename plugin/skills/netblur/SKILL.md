---
name: netblur
description: Sanitize network device and VoIP configurations, backups and logs with netblur before reading them. Use whenever the user asks to analyze, troubleshoot, review, compare or explain a firewall, router, switch, access point, VPN or PBX configuration (Fortinet, Cisco, Zyxel, MikroTik, Juniper, WatchGuard, pfSense, UniFi, 3CX, Asterisk, FreePBX and similar), or a backup or log that may hold passwords, keys or customer data.
---

### netblur

netblur masks passwords, keys, SNMP communities, PINs, tokens and hashes in configuration files, and optionally the identity of the customer too. It runs locally with Python 3.9 or later, needs no other packages and never connects to the Internet. The original is never modified: netblur writes a copy next to it.

### Rule

Never read, grep, print or paste the original configuration. Run netblur first and work only on the copy it writes. If a netblur guard denies reading a file, follow its message instead of looking for another way to read the file.

### Find netblur

1. Find the Python command: `python3`, then `python`, then `py` on Windows. If none works, tell the user that netblur needs Python 3.9 or later (on Windows `winget install Python.Python.3.13`) and stop.
2. If the file `${CLAUDE_PLUGIN_ROOT}/netblur.py` exists, use it: in the commands below, `NETBLUR` means `<python> "${CLAUDE_PLUGIN_ROOT}/netblur.py"`.
3. Otherwise check whether netblur is installed with `<python> -m netblur --version`. If it is, `NETBLUR` means `<python> -m netblur`.
4. If it is not installed, ask the user before installing it, then install the pinned release from its GitHub repository:
   ```
   <python> -m pip install --user "https://github.com/manuelveronesi/netblur/archive/refs/tags/v3.4.zip"
   ```
   It installs one Python module and no dependencies. Then use `<python> -m netblur`.

### Steps

1. Choose the level:
   - Level 1, secrets only, is the default and is enough to troubleshoot.
   - Level 2 (`--personal`) also replaces names, usernames, emails, phones, hostnames, domains, public IP addresses and MAC addresses with consistent placeholders. Use it when the user wants the customer not to be identifiable or will share the analysis. Customer words such as the company name or the city go with `-w Acme,Milano`.
2. Run netblur on the file, the archive or the folder:
   ```
   NETBLUR "<file>"
   NETBLUR --personal -w "<words>" "<file>"
   ```
   ZIP, TAR and gzip archives (3CX and FreePBX backups included) and whole folders are accepted. Several inputs can go in one run.
3. Read the report: it names each copy written, the likely format, how many lines were masked and which lines are worth a manual review. Read only the copy it names, ending in `_SANITIZED` or `_ANONYMIZED`.
4. If the copy ends in `_NO-SECRETS-FOUND`, tell the user: either the file really has no secrets or it uses a syntax netblur does not know. Ask before reading it.
5. If the report flags lines for review, look at those lines in the copy and tell the user if something looks like a secret that slipped through.

### Level 2 maps

At level 2 netblur writes a JSON map (`netblur_PERSONAL-DATA-MAP_<date>.json`) that links each placeholder to the real value. Never read it, print it or quote it. When the user wants your answer with the real values back, tell them to save the answer as a text file and run locally:

```
NETBLUR --restore answer.txt -m <map.json>
```

The restored copy ends in `_RESTORED` and contains real data: do not read it either.

### Where this protects the data

netblur protects the original only if it runs before the file reaches Claude. In Claude Code on the user's computer it runs locally and only the sanitized copy is read. If the user has already attached or uploaded the original to the conversation, its content has already been shared: say so plainly, then sanitize it anyway so that any further copy, log or document you produce stays clean.

### Limits to mention when relevant

netblur is pattern based, not a parser: new firmware or unusual syntax can slip through, so the user should review the copy before sharing it further. The sanitized copy cannot be restored onto a device. Binary or encrypted backups (for example UniFi `.unf`) must be exported as text first.
