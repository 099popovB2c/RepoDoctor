# RepoDoctor

A zero-dependency repository health checker for open-source projects.

## Checks

- README / LICENSE / SECURITY / CONTRIBUTING / CODE_OF_CONDUCT
- Common accidental secret patterns
- Suspicious large files
- Broken relative Markdown links
- TODO/FIXME count
- package.json / requirements.txt dependency inventory
- Git working-tree status
- Basic GitHub Actions presence
- Health score + Markdown/JSON report

## Run

```bash
python repodoctor.py .
python repodoctor.py /path/to/repo --json reports/report.json --markdown reports/report.md
```

RepoDoctor never uploads repository contents.
