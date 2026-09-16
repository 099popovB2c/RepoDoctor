# RepoDoctor

A zero-dependency repository health checker for open-source projects.

## v0.2.0 checks

- Core community docs, `.gitignore` and test-directory presence
- Common accidental secret patterns and suspicious large files
- Broken relative Markdown links and TODO/FIXME inventory
- GitHub Actions presence
- **Workflow token-permission check**
- **Unpinned third-party GitHub Action detection**
- `pull_request_target` risk warning
- Dependabot/Renovate and CODEOWNERS detection
- Dependency inventory and git working-tree status
- Markdown/JSON reports plus CI-friendly `--fail-below`

```bash
python repodoctor.py .
python repodoctor.py . --json report.json --markdown report.md --fail-below 85
```

RepoDoctor performs static local checks and never uploads repository contents. It complements, rather than replaces, tools such as OpenSSF Scorecard.
