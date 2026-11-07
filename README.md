### mask-passwords

Mask passwords, keys and other secrets in network device configuration files before you hand them to an AI for analysis. Optionally, replace names, usernames, email addresses and phone numbers too.

It runs locally, needs nothing but Python and never connects to the Internet. The original file is never modified: you get a sanitized copy next to it.

### Why

Pasting a firewall config into a chat is one of the fastest ways to troubleshoot it, and one of the easiest ways to leak a customer's VPN keys, admin passwords and SNMP communities. The AI needs the structure of the config (interfaces, objects, policies, routes), not the secrets. This tool removes the secrets and keeps the structure.

### What it recognises

| Family | Examples |
| --- | --- |
| CLI keyword followed by a value | Cisco IOS and ASA, Zyxel, Fortinet (FortiGate, FortiWeb, FortiSwitch), Extreme EXOS and VOSS, Netgear, TP-Link, Huawei, Aruba, Ubiquiti EdgeOS, Juniper |
| key=value | MikroTik RouterOS, Ubiquiti airOS `system.cfg`, WireGuard |
| JSON | UniFi |
| XML | WatchGuard, pfSense, OPNsense, 3CX `Db.xml` |
| Private keys | PEM blocks and OpenVPN static keys, including multi-line FortiGate `set private-key` values |
| Hashes and ciphertexts | `$1$`, `$5$`, `$6$`, `$8$`, `$9$`, Huawei `%^%#`, anything after Fortinet `ENC` |
| Embedded credentials | `user:password@host` in URLs and in Fortinet backup or automation scripts |
| SNMPv3 | `auth-*-key`, `priv-*-key`, plaintext `auth-sha512 <password>` forms, engine IDs |

It also handles:

- **ZIP archives**: every file inside is read in memory and only sanitized copies are written to disk. Paths stored in the archive are ignored, so nothing is ever written outside the folder.
- **Fortinet multi-part backups** (for example a FortiWeb "entire configuration"): text blocks are sanitized, encrypted or compressed blocks are omitted and listed in the report.
- **3CX backups**: only the configuration file `<number>Db.xml` is processed. Database tables, recordings, voicemail, prompts, certificates and phone provisioning files are skipped and never written out.

Public certificates (`BEGIN CERTIFICATE`) are left untouched.

### Two modes

| Mode | Command | Copy suffix | What is replaced |
| --- | --- | --- | --- |
| Secrets only | `python mask_passwords.py FILE` | `_SANITIZED` | passwords, keys, communities, PINs, tokens, hashes |
| Secrets and personal data | `python mask_passwords.py --personal FILE` | `_ANONYMIZED` | the above, plus names, usernames, email addresses and phone numbers |

In personal data mode the values are replaced with consistent placeholders such as `NAME_1`, `USER_1`, `EMAIL_1` and `PHONE_1`: the same value always gets the same placeholder, so the AI can still follow forwarding rules, group memberships and routing without knowing who is involved. A `..._PERSONAL-DATA-MAP.txt` file next to the copy links each placeholder to the real value, so you can read the AI's answers. That file contains the real data: keep it local and never share it.

When nothing is found to mask, the copy gets the `_NO-SECRETS-FOUND` suffix and a warning is shown, because zero secrets can also mean a syntax the tool doesn't know. An existing copy is never overwritten: a new one with date and time in its name is created instead.

### Requirements

Python 3.9 or later. No external packages.

### Usage

```
python mask_passwords.py startup-config.conf
python mask_passwords.py --personal 3CXScheduledBackup.zip
python mask_passwords.py config1.conf config2.cfg backup.zip
```

The report shows the likely format, the number of masked lines and the lines worth reviewing by hand.

### Windows: right-click menu

`run.bat` and `run_personal.bat` launch the two modes. To add them to the Send to menu, run this once from the repository folder:

```
powershell -ExecutionPolicy Bypass -File install-sendto.ps1
```

Then right-click a configuration file and choose Send to, "Mask passwords in configs" or "Mask passwords and personal data". On Windows 11 the Send to menu is under "Show more options", or press Shift+F10.

### Limitations

Read these before relying on the output.

- This is a conservative, pattern-based tool, not a parser. It recognises secrets from the shape of each line, and new firmware or unusual syntax can slip through. **Always review the copy before sharing it**, starting from the lines flagged in the report.
- When in doubt it masks, so some harmless values may be masked too.
- In personal data mode, names are recognised in the fields that hold them (`FirstName`, `username`, SNMP contact and similar). A name written only inside free text can remain visible.
- Fully binary or encrypted backups (for example UniFi `.unf`, encrypted WatchGuard backups, many router `.cfg` and `.bin` files) are rejected: export the configuration as text. Password-protected ZIP files must be extracted first.
- The sanitized copy cannot be restored onto a device.

### Tests

```
python tests/run_tests.py
```

The samples in `tests/samples` are synthetic and every secret in them contains the word `LEAK`, so a copy passes when that word no longer appears in it.

### Contributing

Found a secret that slipped through? See [CONTRIBUTING.md](CONTRIBUTING.md). Please never share a real configuration, not even partially.

### License

Apache License 2.0, see [LICENSE](LICENSE). The software is provided "as is", without warranties of any kind.

Built by Manuel Veronesi, with the help of Perplexity and Claude.
