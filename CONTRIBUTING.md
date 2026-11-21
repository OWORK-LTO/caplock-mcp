# Contributing

1. Open an issue describing the problem or proposed change without publishing undisclosed vulnerabilities.
2. Keep security claims aligned with implemented and tested behaviour.
3. Add regression tests for every protocol, trust or verification change.
4. Never add tests that depend on external services or credentials.
5. Keep stdout protocol-clean in proxy code; diagnostics belong on stderr.
6. Do not add a fail-open path or direct-server fallback.
7. Run `pytest -q` and `python -m compileall -q src` before submitting.
8. Document threat-boundary changes and update `SECURITY.md`.

The signing private key, generated lockfiles for real systems and local trust state must never be committed.
