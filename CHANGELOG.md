### Changelog

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
