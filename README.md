# RepoDoctor

RepoDoctor is a **zero-dependency repository health checker** for maintainers who want a fast way to audit documentation, CI, dependency hygiene, release readiness and common security mistakes.

It is designed for local use and CI pipelines. The core scan runs without requiring a hosted service.

## What it checks

RepoDoctor can inspect a repository for issues such as:

- missing or weak open-source documentation
- missing LICENSE / SECURITY / CONTRIBUTING files
- suspicious committed secrets
- broken or risky README links
- large or unexpected binary artifacts
- dependency lockfile / pinning hygiene
- GitHub Actions security problems
- unpinned third-party actions
- overly broad workflow token permissions
- risky `pull_request_target` usage
- CodeQL / SAST presence
- Dependabot / CODEOWNERS presence
- optional OSV vulnerability lookups
- general release/open-source readiness

The goal is not to replace specialist security scanners. RepoDoctor provides a **single repository-level health pass** that combines common maintainability and supply-chain checks.

## How it works

```text
Repository path
      ↓
Static repository scan
      ↓
Documentation / CI / dependency / security checks
      ↓
Findings + score
      ↓
Text / JSON / Markdown / SARIF output
      ↓
Optional regression gate in CI
```

## Quick start

Scan the current repository:

```bash
python repodoctor.py .
```

Save a machine-readable report:

```bash
python repodoctor.py . --json reports/current.json
```

Use the first clean/accepted report as a baseline:

```bash
python repodoctor.py . --json reports/baseline.json
```

Then compare a future state:

```bash
python regression.py . --baseline reports/baseline.json
```

## Regression mode

v0.4.0 adds a baseline/regression workflow that separates findings into:

- **new**
- **resolved**
- **persistent**

This is useful when an existing repository already has known warnings and you only want CI to fail when a pull request introduces something worse.

Example:

```bash
python regression.py . \
  --baseline reports/baseline.json \
  --fail-on-new warning \
  --github-annotations
```

Exit code `3` means a newly introduced finding met the configured severity threshold.

## GitHub Actions security checks

RepoDoctor checks workflow configuration for common supply-chain risks, including:

- third-party actions referenced by mutable tags instead of immutable commit SHAs
- excessive `GITHUB_TOKEN` permissions
- risky workflow trigger patterns
- missing dependency-update automation

These checks are intended to help maintainers spot configuration drift early.

## Dependency and vulnerability checks

RepoDoctor can inspect lockfile/pinning hygiene locally.

An optional OSV lookup can be used for vulnerability information. Network-based vulnerability querying is **opt-in** rather than required for the normal scan.

## SARIF and CI integration

RepoDoctor can produce machine-readable output suitable for automation. SARIF support makes it possible to integrate findings with code-scanning style workflows.

Typical CI strategy:

```text
1. Keep an accepted baseline report
2. Scan the current commit
3. Compare current findings with baseline
4. Fail only on newly introduced warning/critical issues
5. Emit GitHub annotations for developer visibility
```

## What the score means

The health score is a convenience summary of the repository checks. It should be used as a navigation aid, not as proof that a repository is secure.

A high score means RepoDoctor did not detect many of the issues it knows how to check. It does **not** mean:

- the code has no vulnerabilities
- dependencies are always safe
- CI is impossible to exploit
- secrets can never be present
- the project passed a professional security audit

## Privacy and network behavior

The core scan runs locally against the repository you provide.

- no RepoDoctor account
- no analytics
- no hosted backend
- no source-code upload
- optional online checks are explicit

## Current limitations

RepoDoctor is a repository-level heuristic scanner, not a replacement for tools such as dedicated SAST, secret scanners, dependency analyzers or professional review.

Current limitations include:

- heuristic checks can produce false positives/negatives
- branch-protection state may require API permissions outside a local checkout
- vulnerability results depend on the dependency data available
- language-specific package ecosystems are not all equally deep
- generated/vendor code can add noise unless excluded appropriately

## Roadmap

Possible next steps:

- richer ignore/config file
- more package-manager-specific checks
- branch-protection/ruleset audit through authenticated GitHub access
- release-signature verification
- SBOM generation/checking
- richer secret-pattern engine
- HTML report
- GitHub Action packaging for one-line CI installation

## Version

Current release: **v0.4.0**

## Security

See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
