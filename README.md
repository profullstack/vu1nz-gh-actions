# vu1nz-gh-actions

> **GitHub Actions security scanner — detect CI/CD workflow vulnerabilities + AI code review via Claude**

A standalone, open-source security scanner for GitHub Actions workflows. Finds **script injection**,
**unpinned actions**, **pull_request_target abuse**, **secret leaks**, **permission issues**, and
**supply chain risks** in your CI/CD pipelines. Optionally runs AI-powered code review via Claude.

Part of the [vu1nz](https://github.com/profullstack/vu1nz.com) security ecosystem.

---

## Features

- **17 security checks** — comprehensive coverage of OWASP CI/CD top 10 risks
- **AI code review** — optional Claude-powered analysis that explains vulnerabilities in plain English
- **Reusable GitHub Action** — plug into your existing CI/CD pipeline in minutes
- **PR comments** — automatically posts findings as comments on pull requests
- **Configurable severity thresholds** — fail builds on critical, high, or medium findings
- **JSON reports** — machine-readable output for integration with other tools

---

## Quick Start

### CLI

```bash
# Install
pip install vu1nz-gh-actions

# Scan a repository
vu1nz actions scan owner/repo

# Scan with Claude AI code review
export ANTHROPIC_API_KEY=sk-ant-...
vu1nz actions scan owner/repo --claude

# Machine-readable JSON output
vu1nz actions scan owner/repo --json

# Custom GitHub token
vu1nz actions scan owner/repo --token ghp_...
```

### GitHub Actions (CI/CD Integration)

```yaml
name: Actions Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan-actions:
    runs-on: ubuntu-latest
    steps:
      - uses: profullstack/vu1nz-gh-actions/.github/actions/vu1nz-actions-scan@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

### With Claude AI Review

```yaml
      - uses: profullstack/vu1nz-gh-actions/.github/actions/vu1nz-actions-scan@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          claude_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_model: claude-sonnet-4-20250514
          fail_on: high
```

---

## 17 Security Checks

| # | ID | Severity | Category | Description |
|---|-----|----------|----------|-------------|
| 1 | `script_injection_github_context` | CRITICAL | script_injection | User-controlled GitHub context (${{ github.event.* }}) interpolated into run: commands |
| 2 | `pull_request_target_checkout` | CRITICAL | context | pull_request_target checking out PR HEAD — attacker runs code with secrets |
| 3 | `secret_exposure_run_command` | CRITICAL | secrets | Secrets inlined in run: commands (captured in logs) |
| 4 | `untrusted_checkout_self` | HIGH | context | PR head checked out without explicit ref on pull_request_target |
| 5 | `pull_request_target_usage` | HIGH | context | pull_request_target trigger used (runs with repo token + secrets) |
| 6 | `secret_exposure_pr_context` | HIGH | secrets | Secrets exposed to PR context via inherit/secrets: write |
| 7 | `unpinned_action` | HIGH | pinning | Third-party action by mutable ref (tag/branch) instead of commit SHA |
| 8 | `matrix_injection` | HIGH | script_injection | Dynamic matrix values from untrusted context |
| 9 | `untrusted_workflow_call` | HIGH | supply_chain | External workflow by mutable ref instead of commit SHA |
| 10 | `self_hosted_runner` | HIGH | supply_chain | Non-ephemeral self-hosted runner in workflow |
| 11 | `dangerous_deployment_env` | HIGH | deployment | Deployment environment without required reviewers |
| 12 | `write_all_permissions` | MEDIUM | permissions | Workflow has write-all permissions |
| 13 | `unpinned_docker` | MEDIUM | pinning | Container image by tag instead of digest (@sha256:) |
| 14 | `dangerous_artifact_mismatch` | MEDIUM | supply_chain | Artifact upload/download version mismatch |
| 15 | `deploy_on_push_to_main` | MEDIUM | deployment | Deploys on push to main without PR/CI checks |
| 16 | `missing_permissions_top` | LOW | permissions | No top-level permissions: block defined |
| 17 | `secret_exposure_run_command_high` | HIGH | secrets | Secrets via env: in workflow steps |

---

## Output

### Human-readable (default)
```
Scanning profullstack/vu1nz-actions-test...
Found 4 workflow(s). Scanning...

[CRITICAL] Script Injection via GitHub Context
  File: ci.yml (line 12)
  Detail: run: echo "Running tests for PR ${{ github.event.pull_request.title }}"
  Fix: Pass context values as env vars instead of inline

[HIGH] Unpinned Action
  File: deploy.yml (line 15)
  Detail: uses: some-org/deploy-action@v1
  Fix: Pin to commit SHA: some-org/deploy-action@abc123def456...
```

### JSON (--json flag)
```json
{
  "repository": "owner/repo",
  "workflow_count": 4,
  "total_jobs": 7,
  "findings": [...],
  "severity_summary": {
    "critical": 3,
    "high": 9,
    "medium": 6,
    "low": 3
  }
}
```

---

## Requirements

- Python 3.10+
- GitHub token with `actions: read` and `contents: read` permissions
- (Optional) Anthropic API key for Claude AI code review

---

## License

MIT — see [LICENSE](LICENSE).