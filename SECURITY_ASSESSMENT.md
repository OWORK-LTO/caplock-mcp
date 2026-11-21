# CAPLOCK 0.3.1 — Verification and security assessment record

Assessment date: 2026-11-20
Scope: source archive `CAPLOCK_OPEN_SOURCE_0.3.1.zip` and its stdio proxy implementation.

## Results completed in this environment

- Automated tests: 24 passed.
- Branch coverage: 83% overall (core 72%; proxy and test modules 100% line coverage under this run).
- Python bytecode compilation: passed.
- Source archive integrity: checked after packaging.
- GitHub Actions YAML syntax: parsed locally; this is not a GitHub-hosted workflow execution.
- Manual adversarial protocol review: identified and fixed unsolicited upstream JSON-RPC response forwarding. Added regression tests for forged response injection, legitimate server-initiated request/response handling and active request-ID collisions.
- Official MCP Python SDK source/API review: current upstream `main` declares Python >=3.11 and exposes stdio transport. This source inspection is not an interoperability test.

## External execution blockers

### Clean, network-independent installation

A new Python 3.13 virtual environment was created. Installing the package and build/test dependencies could not complete because this execution environment cannot resolve `pypi.org` (DNS failure). The package's isolated build backend (`hatchling`) and the `cryptography` dependency are not present in that clean environment. Therefore a clean independent installation is **NOT VERIFIED**. Existing-environment test execution is not a substitute.

### Official MCP SDK interoperability

The official `modelcontextprotocol/python-sdk` repository was inspected. The SDK is not installed in this runtime, and package installation was blocked by the same DNS failure. No real SDK server/client interoperability test was executed. Status: **NOT VERIFIED**.

### GitHub Actions

The intended repository `OWORK-LTO/caplock-mcp` returns 404, and the linked GitHub account currently exposes no owned repositories. The available GitHub integration does not provide repository creation or workflow-dispatch actions. The workflow file can be committed once a repository is created and connected, but a hosted run cannot be triggered from the current access state. Status: **NOT RUN**.

### Independent penetration test

The protocol adversarial tests and source review in this report were performed as part of the implementation work. They are not independent. No external tester, separate security team or contracted penetration-testing engagement is available through this execution environment. Status: **NOT PERFORMED**.

## 0.3.2 addendum

Manual review and runtime probes (not independent) found and fixed: (a) unsigned `tools/list` result members forwarded to the host; (b) any forwarded request exceeding the timeout terminated the proxy. Test suite: 26 passed (24 prior + 2 new) in a harness without the pytest package (stub for `tmp_path`-based tests only; `pytest.raises` match arguments not enforced), so a real pytest run is still required. All blockers above remain open.

## Findings and residual risks

1. **Fixed in 0.3.1 — unsolicited JSON-RPC response injection.** The previous proxy forwarded upstream responses whose IDs did not match an active request. The proxy now rejects unknown/inactive response IDs, tracks server-initiated requests and rejects ID collisions. Regression tests cover the finding.
2. **Residual — no official SDK interoperability evidence.** The proxy still requires validation against the current official MCP SDK and supported protocol versions.
3. **Residual — external assurance absent.** No independent source review, fuzzing campaign or penetration test has been completed.
4. **Residual — runtime scope.** Only stdio transport is implemented. Definition integrity does not prove tool implementation integrity or safe tool behaviour.
5. **Residual — package supply chain.** A clean isolated install, dependency audit and reproducible build have not been completed.

## Assurance conclusion

CAPLOCK 0.3.1 passes its current local automated suite and the added protocol regression tests. It is **not independently security-assessed, not officially SDK-interoperability-verified, not GitHub-CI-verified, and not clean-install-verified**. Do not represent it as production-certified or independently penetration-tested.
