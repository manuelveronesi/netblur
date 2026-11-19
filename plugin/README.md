### netblur for Claude

Pasting a firewall or PBX configuration into a chat is one of the fastest ways to troubleshoot it, and one of the easiest ways to leak a customer's VPN keys, admin passwords and SNMP communities. This plugin teaches Claude to run [netblur](https://github.com/manuelveronesi/netblur) first and to work only on the sanitized copy.

### What it does

When you ask Claude to analyse, troubleshoot, review or compare a network device or VoIP configuration, a backup or a log, Claude:

- runs netblur on it, at level 1 (passwords, keys, communities, PINs, tokens and hashes) or at level 2 when you want the customer not to be identifiable too (names, usernames, emails, phones, hostnames, domains, public IP addresses, MAC addresses and the words you choose);
- reads only the copy netblur writes next to the original, ending in `_SANITIZED` or `_ANONYMIZED`, and never the original;
- never reads the level 2 map that links placeholders to real values, and gives you the `--restore` command to run yourself.

Supported formats include Fortinet, Cisco IOS and ASA, Zyxel, MikroTik, Juniper, Huawei, Aruba, Extreme, Netgear, TP-Link, Ubiquiti, WatchGuard, pfSense, OPNsense, UniFi, WireGuard, OpenVPN, 3CX, Asterisk and FreePBX, including ZIP and TAR backups.

### What it runs and where data goes

The plugin itself contains only instructions for Claude. netblur is a single Python module (Python 3.9 or later, no dependencies) that runs on the machine where Claude works, writes the sanitized copies next to the originals and never connects to the Internet. If netblur is not installed, Claude asks you before installing the pinned release with pip from the project's GitHub repository. Nothing is sent anywhere by the plugin or by netblur.

netblur protects a file only if it runs before the file reaches the conversation. A file you have already attached or uploaded has already been shared: sanitize it on your computer first, or let Claude Code run netblur locally.

For Claude Code there is also a version with a guard hook that blocks reading a configuration that still contains secrets: see [Use it with Claude](https://github.com/manuelveronesi/netblur#use-it-with-claude).

### Limits

netblur is pattern based, not a parser: new firmware or unusual syntax can slip through, so review the copy before sharing it further. The sanitized copy cannot be restored onto a device.

### License

Apache License 2.0, see [LICENSE](LICENSE).
