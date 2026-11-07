### Security

This tool exists to keep secrets out of shared files, so a secret that is not masked is treated as a security issue.

### Reporting

If you find a syntax that leaves a secret in clear text, report it as described in [CONTRIBUTING.md](CONTRIBUTING.md), always with invented values. If you think the issue should not be public until it is fixed, use GitHub's private vulnerability reporting for this repository instead of a public issue.

### What this tool does not promise

It is a best-effort, pattern-based sanitizer. It does not guarantee that every secret or every piece of personal data is removed. Review every copy before sharing it.
