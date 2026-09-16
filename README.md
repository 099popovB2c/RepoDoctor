# RepoDoctor

Zero-dependency repository health checker for documentation, secrets, CI, dependencies and open-source release readiness.

## v0.3.0

- GitHub Actions permission and full-SHA pinning checks
- CodeQL / common SAST workflow detection
- Dependency lockfile and Python pinning checks
- Committed binary/archive artifact detection
- VERSION/changelog/release-tag readiness checks
- Optional OSV vulnerability lookup for pinned PyPI/npm dependencies (`--osv`)
- SARIF 2.1.0 output for code-scanning pipelines (`--sarif`)
- JSON and Markdown reports retained

```bash
python repodoctor.py .
python repodoctor.py . --json report.json --markdown report.md
python repodoctor.py . --sarif repodoctor.sarif
python repodoctor.py . --osv
python repodoctor.py . --fail-below 85
```

OSV lookup is opt-in and requires network access. Local checks do not upload repository content.
