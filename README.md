### netblur

Mask passwords, keys and other secrets in network device configurations before you hand them to an AI for analysis. Optionally, blur the identity too: names, usernames, email addresses, phone numbers, hostnames, domains, public IP addresses, MAC addresses and any word you choose.

It runs locally, needs nothing but Python and never connects to the Internet. Originals are never modified: you get a sanitized copy next to them.

### Why

Pasting a firewall config into a chat is one of the fastest ways to troubleshoot it, and one of the easiest ways to leak a customer's VPN keys, admin passwords and SNMP communities. The AI needs the structure of the config (interfaces, objects, policies, routes), not the secrets. Like a blurred photo, the output keeps the scene and hides the details.

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

- **ZIP archives**: every file inside is read in memory and only sanitized copies are written to disk. Paths stored in the archive are ignored, so nothing is ever written outside the output folder.
- **Fortinet multi-part backups** (for example a FortiWeb "entire configuration"): text blocks are sanitized, encrypted or compressed blocks are omitted and listed in the report.
- **3CX backups**: only the configuration file `<number>Db.xml` is processed. Database tables, recordings, voicemail, prompts, certificates and phone provisioning files are skipped and never written out.
- **Directories**: processed recursively, mirroring the structure in the output folder. Files that are not text are skipped and reported.

Public certificates (`BEGIN CERTIFICATE`) are left untouched.

### Two levels

| Level | Command | Copy suffix | What is replaced |
| --- | --- | --- | --- |
| 1, secrets only | `netblur FILE` | `_SANITIZED` | passwords, keys, communities, PINs, tokens, hashes |
| 2, secrets and identity | `netblur --personal FILE` | `_ANONYMIZED` | the above, plus names, usernames, email addresses, phone numbers, hostnames, domains, public IP addresses, MAC addresses and the words you pass with `-w` |

At level 2 the values are replaced with consistent placeholders: `NAME_1`, `USER_1`, `EMAIL_1`, `PHONE_1`, `HOST_1`, `example-1.net`, `WORD_1`, public addresses from the documentation ranges (`192.0.2.1`, `198.51.100.1`, `203.0.113.1`, then `198.18.0.0/15`), IPv6 under `2001:db8::/32` and locally administered MACs (`02:00:00:00:00:01`). The same value always gets the same placeholder, across every file of the run, so the AI can still follow forwarding rules, BGP peers, group memberships and routing without knowing who or where. Private addresses, netmasks, wildcard masks, multicast and well-known public resolvers stay readable, and `--all-ips`, `--keep-ips` and `--keep-macs` change that.

`-w` takes the words that identify the customer (company name, city, project) and replaces them wherever they appear, even inside hostnames and descriptions: `-w Acme,Milano` or `--words-file words.txt`.

A JSON map links each placeholder to the real value. `netblur --restore answer.txt -m map.json` puts the real values back into the AI's answer, so you can act on it. Both files contain real data: keep them local and never share them.

When nothing is found to mask, the copy gets the `_NO-SECRETS-FOUND` suffix and a warning is shown, because zero secrets can also mean a syntax the tool doesn't know. Existing files are never overwritten: a new copy with date and time in its name is created instead.

### Install

Python 3.9 or later, no external packages.

```
pip install git+https://github.com/manuelveronesi/netblur
```

Or just copy `netblur.py` anywhere and run it with `python netblur.py`. On Windows without Python: `winget install Python.Python.3.13`.

### Usage

```
netblur startup-config.conf
netblur --personal 3CXScheduledBackup.zip
netblur config1.conf config2.cfg backup.zip
netblur backups/ -o clean/
cat running-config.txt | netblur - -o - > clean.txt
netblur --personal site-a/ site-b/ -o clean/ -m clean/map.json -w Acme,Milano
netblur --restore ai-answer.txt -m clean/map.json
netblur config.conf -o out/ --strict
```

| Option | Effect |
| --- | --- |
| `-o PATH` | Output file (single input, with an extension) or directory (a path without extension, with a trailing slash, or with several inputs). `-` writes to standard output and sends the report to standard error |
| `-p`, `--personal` | Level 2: also replace names, usernames, emails, phones, hostnames, domains, public IPs, MACs |
| `-w WORD`, `--words-file FILE` | Level 2: sensitive words to replace wherever they appear (repeat `-w` or separate with commas) |
| `--all-ips`, `--keep-ips`, `--keep-macs` | Level 2: replace private addresses too, or keep every IP or MAC as it is |
| `-m FILE` | Where to write the JSON map of placeholders (default: next to the copies) |
| `--no-map` | Do not write the map file |
| `--restore` | Put the real values back into a text using the map given with `-m` (output: `_RESTORED` copy, or `-o`) |
| `--strict` | Exit with status 2 when lines are flagged for review or a file had no secrets (useful in scripts and CI) |
| `--force` | Allow overwriting the file named by `-o` or `-m`, never the originals |

Exit codes: 0 success, 1 an input could not be processed, 2 `--strict` findings.

The report shows the likely format, the number of masked lines and the lines worth reviewing by hand.

### Windows: right-click menu

`run.bat` and `run_personal.bat` launch the two levels. To add them to the Send to menu, run this once from the folder where you keep netblur:

```
powershell -ExecutionPolicy Bypass -File install-sendto.ps1
```

Then right-click one or more configuration files and choose Send to, "netblur (secrets only)" or "netblur (secrets and personal data)". On Windows 11 the Send to menu is under "Show more options", or press Shift+F10.

### Limitations

Read these before relying on the output.

- This is a conservative, pattern-based tool, not a parser. It recognises secrets from the shape of each line, and new firmware or unusual syntax can slip through. **Always review the copy before sharing it**, starting from the lines flagged in the report.
- When in doubt it masks, so some harmless values may be masked too.
- At level 2, names are recognised in the fields that hold them (`FirstName`, `username`, SNMP contact and similar), hostnames and domains in the commands that set them. A name written only inside free text can remain visible: pass it with `-w`. Replaced addresses keep no subnet relationship with each other, and interface descriptions are kept (scrubbed of what the tool recognises) rather than blanked.
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
