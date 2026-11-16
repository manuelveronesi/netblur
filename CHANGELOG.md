### Changelog

### 3.3
- `--gui`: a small window to choose files and folders, the level, sensitive words and the output folder, and to read the report
- `install-menu.sh`: right-click entries on macOS (Finder Quick Actions) and Linux (GNOME Files, Nemo, Caja scripts, Dolphin service menu), with `--remove`
- Windows: the Send to entries open the window through `pyw`, with no console; `install-sendto.ps1 -Console` keeps the console
- Tests for the window and the menu installer; on Linux the suite runs under a virtual display

### 3.2
- Asterisk and FreePBX: `key => value` syntax, `register =>` credentials, `Dial(SIP/user:secret@host)` strings, voicemail PINs, dialplan `Set(...password...)=`, `[secret]` sections, `AMPMGRPASS`/`AMPDBPASS` and similar compound names
- FreePBX module data (JSON): keyword/data rows masked by keyword name, also across lines
- SQL dumps: secret columns found through `CREATE TABLE` or the explicit column list of `INSERT`, keyword/data tables, PostgreSQL `COPY` blocks
- TAR, `.tar.gz`, `.tgz` and `.gz` inputs, read in memory like ZIP; nested `.gz` members expanded in memory
- Archives with several files now produce a folder with the same tree (`backup_SANITIZED/...`) instead of flat `archive__file` copies; audio and binary members are skipped and counted; FreePBX call records (CDR/CEL), music on hold, recordings and voicemail are never written out
- Level 2: caller ID names, voicemail names and SIP account names (`username`, `fromuser`, `auth_username`) in Asterisk and FreePBX files; `<number>` parts of caller IDs kept
- Setting names such as `SIPSECRETSIZE` or `passwordlength` are no longer masked; fewer review flags on SQL structure, section headers and JSON keyword names

### 3.1
- Level 2 now blurs the identity of the network too: hostnames (`HOST_n`), domains (`example-n.net`, also as FQDN suffixes), public IPv4 and IPv6 addresses (documentation ranges, consistent per run), MAC addresses (locally administered, format preserved) and user-supplied words (`-w`, `--words-file`)
- `--all-ips`, `--keep-ips`, `--keep-macs`
- `--restore` puts the real values back into a text using the map
- Private addresses, masks, multicast, four-part version numbers and well-known public resolvers are left as they are
- A path given to `-o` without an extension is treated as a directory

### 3.0
- Renamed to netblur. Module `netblur.py`, command `netblur`, installable with pip
- Output control: `-o` for a file or a directory, `-` for standard input and output, directories processed recursively with their structure mirrored
- `--strict` exit code for scripts and CI, `--force` for the output named by `-o` or `-m`
- One JSON map of placeholders shared by every file of a run (`-m`, `--no-map`)
- Fortinet `set type password` no longer flagged for review

### 2.6
- Personal data mode (`--personal`): names, usernames, email addresses and phone numbers replaced with consistent placeholders, with a local map file
- `SEPARATEAUTHID` treated as a secret in 3CX configurations

### 2.5
- 3CX backups: only `<number>Db.xml` is processed, everything else in the archive is skipped
- XML name/value pairs (`<Name>` followed by `<Value>`, as in 3CX `DNProperty`)
- Secret tag names such as `VMPIN`, `licensekey`, `AuthID`; escaped XML elements inside text values
- Settings such as lengths, flags and IP addresses kept readable; fewer false alarms in the review list

### 2.4
- ZIP archives read in memory, sanitized copies only, archive paths ignored

### 2.3
- SNMPv3 `auth-*-key` and `priv-*-key` values, plaintext forms and engine IDs
- `user:password@host` credentials in URLs and in Fortinet backup and automation scripts
- Fortinet multi-part backups (FortiWeb "entire configuration"): text blocks sanitized, encrypted blocks omitted
- Certificate lines and cipher settings no longer flagged for review

### 2.2
- Files with nothing to mask get the `_NO-SECRETS-FOUND` suffix and a warning

### 2.1
- Everything in English: file names, messages, comments

### 2.0
- Multi-vendor rewrite based on syntax families (CLI, key=value, JSON, XML, PEM, hashes)
- Tested on synthetic samples for 19 platforms
- Several files at once from the Send to menu

### 1.1
- Existing copies are never overwritten: a new copy with date and time in its name is created

### 1.0
- First version for Zyxel ATP configurations
