### Contributing

Thanks for helping make this tool safer.

### Reporting a secret that slipped through

Open an issue with:

- the vendor, product and firmware version
- the line that was not masked, **with every value replaced by an invented one**
- what you expected to be masked

For example:

```
snmp-server user "admin" DefaultRead auth-sha512-key 0123abcdINVENTED
```

Never paste a real configuration, a real secret or a real customer name, not even partially. If the problem is in a structure rather than a single line, describe the structure with invented values.

### Code changes

- Keep the tool dependency-free and compatible with Python 3.9 or later. The supported versions are the ones in the test matrix (`.github/workflows/tests.yml`); when a version can no longer be tested there, raise the minimum in `pyproject.toml`, the matrix and this line together. Dependabot keeps the GitHub Actions up to date and the tests also run once a month on a schedule, so a broken runner image shows up without a push.
- Add a synthetic sample, or extend an existing one, in `tests/samples`. Every secret must contain the word `LEAK`.
- Run `python tests/run_tests.py` and make sure all checks pass.
- Keep code, comments, messages and documentation in English.
