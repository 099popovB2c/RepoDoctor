# RepoDoctor

Zero-dependency repository health checker for docs, secrets, links, CI, binary artifacts, dependency hygiene and open-source readiness.

## v0.4.0

- Baseline/regression workflow via `regression.py`
- Separates **new**, **resolved** and **persistent** findings
- Score delta against a previous JSON report
- CI gate can fail only when new `info`, `warning` or `critical` findings appear
- Optional GitHub Actions workflow-command annotations for new findings
- Regression JSON and Markdown outputs
- Existing SARIF, SAST detection, lockfile/pinning checks, binary checks and opt-in OSV scan retained

```bash
python repodoctor.py . --json reports/baseline.json
python regression.py . --baseline reports/baseline.json
python regression.py . --baseline reports/baseline.json --fail-on-new warning --github-annotations
```

Exit code `3` from `regression.py` means a newly introduced finding met the configured severity gate.
