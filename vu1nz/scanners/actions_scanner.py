"""GitHub Actions scanner — detects workflow vulnerabilities & runs AI-powered code review via Claude API.

Scans:
  - CI/CD security anti-patterns (unpinned actions, script injection, PR context leaks)
  - Dangerous workflow patterns (pull_request_target with checkout, write-all permissions)
  - GitHub token misuse and broad permissions
  - AI code review of workflow logic using Claude (Anthropic API)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table

console = Console()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class WorkflowFinding:
    """A single security issue found in a GitHub Actions workflow."""
    title: str
    severity: str  # critical | high | medium | low | info
    category: str   # script_injection | permission | pinning | secret | context
    file: str
    line: int = 0
    description: str = ""
    code_snippet: str = ""
    recommendation: str = ""
    cwe: str = ""
    ai_generated: bool = False


@dataclass
class ActionsAnalysisResult:
    """Result of a full Actions scan or review."""
    findings: list[WorkflowFinding] = field(default_factory=list)
    workflow_count: int = 0
    total_jobs: int = 0
    ai_summary: str = ""


# ---------------------------------------------------------------------------
# Security check definitions
# ---------------------------------------------------------------------------

WORKFLOW_CHECKS: list[dict[str, Any]] = [
    # === PINNING ===
    {
        "id": "unpinned_action",
        "severity": "high",
        "category": "pinning",
        "title": "Third-party Action Without Pinned Hash",
        "pattern": r"uses:\s+[^@]+@[a-f0-9]{7}(?:$|\s)",
        "description": (
            "Third-party GitHub Action referenced by short commit hash or tag/branch. "
            "Tags and branches are mutable — an attacker could replace the action tag "
            "with a malicious version and compromise your CI/CD pipeline."
        ),
        "recommendation": (
            "Pin all third-party actions to a full commit SHA (40 hex characters). "
            "Use Dependabot or Renovate to automate updates: "
            "'uses: actions/checkout@<full-40-char-sha>'"
        ),
        "cwe": "CWE-829",
    },
    {
        "id": "unpinned_docker",
        "severity": "medium",
        "category": "pinning",
        "title": "Docker Image Without Digest Pin",
        "pattern": r"image:\s+[^@]+:[a-zA-Z0-9._-]+$",
        "description": (
            "Docker container image referenced by tag instead of digest. "
            "Tags can be overwritten, leading to supply chain compromise."
        ),
        "recommendation": "Pin container images to a specific digest: 'image: myimage@sha256:<full-digest>'",
        "cwe": "CWE-829",
    },

    # === SCRIPT INJECTION ===
    {
        "id": "script_injection_github_context",
        "severity": "critical",
        "category": "script_injection",
        "title": "Script Injection via GitHub Context",
        "pattern": r"run:\s*.*\${{.*github\.event\..*}}",
        "description": (
            "User-controlled data from GitHub event context is interpolated directly into a shell script. "
            "An attacker can inject arbitrary commands in a PR by including them in the PR title, "
            "branch name, commit message, or body."
        ),
        "recommendation": (
            "Pass untrusted context values as environment variables in the 'env:' block, "
            "not directly in 'run:' scripts. GitHub Actions escapes env vars properly."
        ),
        "cwe": "CWE-77",
    },
    {
        "id": "script_injection_expression",
        "severity": "high",
        "category": "script_injection",
        "title": "Possible Expression Injection in Script",
        "pattern": r"run:\s*.*\${{",
        "description": (
            "GitHub Actions expression syntax found inside a shell run command. "
            "Expressions inside 'run:' blocks can be exploited for script injection "
            "if the expression contains user-controlled data."
        ),
        "recommendation": (
            "Avoid inline expressions in 'run:' blocks. Store values via 'env:' "
            "or use actions/github-script for safer context-based logic."
        ),
        "cwe": "CWE-77",
    },

    # === PULL REQUEST TARGET ===
    {
        "id": "pull_request_target_checkout",
        "severity": "critical",
        "category": "context",
        "title": "pull_request_target + checkout PR HEAD",
        "pattern": (
            r"pull_request_target\b[\s\S]*?"
            r"(?:actions/checkout|checkout)\b[\s\S]*?"
            r"ref:\s*(?:\${{|\")\s*github\.event\.pull_request\.head"
        ),
        "description": (
            "The workflow triggers on 'pull_request_target' (which runs with full "
            "repository token and secrets) AND checks out the PR's HEAD. "
            "This allows any PR author to execute arbitrary code with repository secrets. "
            "This is one of the most dangerous workflow patterns."
        ),
        "recommendation": (
            "Never check out the PR's HEAD with 'pull_request_target'. "
            "Use 'pull_request' trigger instead, or only check out the base branch. "
            "If you must use 'pull_request_target', do NOT run 'actions/checkout'."
        ),
        "cwe": "CWE-269",
    },
    {
        "id": "pull_request_target_usage",
        "severity": "high",
        "category": "context",
        "title": "pull_request_target Trigger Used",
        "pattern": r"pull_request_target\b",
        "description": (
            "Workflow uses 'pull_request_target' trigger. This trigger runs with "
            "the repository's token and secrets, not the PR author's. "
            "While legitimate for labelers/commenters, it's frequently misused "
            "and can expose secrets to PRs from forked repositories."
        ),
        "recommendation": (
            "Ensure 'pull_request_target' is only used when necessary. "
            "Never check out the PR's HEAD in these workflows. "
            "Consider 'pull_request' + 'issue_comment' as alternatives."
        ),
        "cwe": "CWE-269",
    },

    # === SECRETS ===
    {
        "id": "secret_exposure_pr_context",
        "severity": "high",
        "category": "secret",
        "title": "Secrets Exposed to PR Context",
        "pattern": r"pull_request(?:_target)?\b[\s\S]*?secrets:",
        "description": (
            "Workflow triggers on pull requests and uses secrets. "
            "PRs from forked repositories should NOT have access to secrets. "
            "Use 'pull_request_target' with caution or gate secret access on paths."
        ),
        "recommendation": (
            "Restrict secret usage in PR workflows. Use path filters to limit "
            "when secrets are available, or gate secret access using "
            "'if: github.event.pull_request.head.repo.fork == false'"
        ),
        "cwe": "CWE-200",
    },
    {
        "id": "secret_in_run_command",
        "severity": "critical",
        "category": "secret",
        "title": "Secret Inlined in Run Command",
        "pattern": r"run:\s*.*\${{.*secrets\..*}}",
        "description": (
            "Secrets are interpolated directly into a shell run command. "
            "This can leak the secret in the Actions runtime log (if command fails) "
            "or via process listing. GitHub masks secrets but they can leak via errors."
        ),
        "recommendation": (
            "Pass secrets only via the 'env:' block, never in 'run:' commands. "
            "GitHub Actions properly masks env vars without leaking."
        ),
        "cwe": "CWE-200",
    },

    # === PERMISSIONS ===
    {
        "id": "write_all_permissions",
        "severity": "medium",
        "category": "permission",
        "title": "Workflow Has Write-All Permissions",
        "pattern": r"permissions:\s*write-all",
        "description": (
            "Workflow explicitly sets permissions to 'write-all', granting all "
            "scopes write access. This violates the principle of least privilege "
            "and increases the blast radius of a compromised workflow."
        ),
        "recommendation": (
            "Grant minimal permissions: 'permissions: read-all' or an explicit "
            "permissions block with only required scopes (e.g., 'contents: read')."
        ),
        "cwe": "CWE-272",
    },
    {
        "id": "missing_permissions_top",
        "severity": "low",
        "category": "permission",
        "title": "No Top-Level Workflow Permissions",
        "pattern": r"^(?!.*permissions)",
        "description": (
            "Workflow does not define top-level permissions. By default, GitHub "
            "Actions workflows get read/write permissions on some scopes. "
            "Explicitly defining permissions follows least-privilege best practices."
        ),
        "recommendation": (
            "Add 'permissions: read-all' at the top of the workflow, or a scoped "
            "permissions block: 'permissions: { contents: read }'"
        ),
        "cwe": "CWE-272",
    },

    # === SUPPLY CHAIN ===
    {
        "id": "actions_upload_download_mismatch",
        "severity": "medium",
        "category": "supply_chain",
        "title": "Uploaded Artifact Downloaded Without Validation",
        "pattern": (r"actions/upload-artifact@[\s\S]*?"
                     r"actions/download-artifact@"),
        "description": (
            "Artifact uploaded then downloaded in a later job. Artifacts can be "
            "modified between upload and download by other workflows running "
            "in the same environment."
        ),
        "recommendation": (
            "Validate artifact integrity using checksums, or use "
            "a trusted storage solution with integrity checks."
        ),
        "cwe": "CWE-494",
    },
    {
        "id": "untrusted_workflow_call",
        "severity": "medium",
        "category": "supply_chain",
        "title": "Untrusted Reusable Workflow",
        "pattern": r"uses:\s+[^/]+/[^/]+/.github/workflows/.*@[a-f0-9]{7}(?:$|\s)",
        "description": (
            "Reusable workflow referenced from another repository by short SHA. "
            "If that repository is compromised, your workflows inherit the compromise."
        ),
        "recommendation": (
            "Pin reusable workflow references to full commit SHA, and review "
            "the target workflow before referencing it."
        ),
        "cwe": "CWE-829",
    },

    # === DEPLOYMENT ===
    {
        "id": "dangerous_deployment_env",
        "severity": "high",
        "category": "deployment",
        "title": "Deployment Without Required Reviewers",
        "pattern": r"environment:\s*\n(?![\s\S]*?required_reviewers)",
        "description": (
            "Deployment environment defined without required reviewers. "
            "Anyone with write access to the repo can deploy to production."
        ),
        "recommendation": (
            "Add required reviewers to your deployment environments in "
            "the repository settings, or use 'environment: production' with "
            "protection rules."
        ),
        "cwe": "CWE-732",
    },
    {
        "id": "deploy_on_push_to_main",
        "severity": "medium",
        "category": "deployment",
        "title": "Deploy on Push to Main",
        "pattern": r"on:\s*\n\s+push:\s*\n\s+branches:\s*\n\s+- main",  # multiline YAML format
        "description": (
            "Workflow deploys on push to main without requiring a PR or "
            "CI checks to pass first. This can lead to broken deployments."
        ),
        "recommendation": (
            "Use branch protection rules requiring PR review and CI status "
            "checks before merging to main, or change the trigger to "
            "only deploy on tags/releases."
        ),
        "cwe": "CWE-306",
    },

    # === ACTIONS ===
    {
        "id": "self_hosted_runner",
        "severity": "medium",
        "category": "infrastructure",
        "title": "Self-Hosted Runner Used",
        "pattern": r"runs-on:\s*self-hosted",
        "description": (
            "Workflow uses a self-hosted runner. Self-hosted runners can execute "
            "arbitrary code on your infrastructure and should be carefully secured. "
            "Fork PRs on self-hosted runners are especially dangerous."
        ),
        "recommendation": (
            "Audit all self-hosted runners. Ensure they are isolated, ephemeral, "
            "and not accessible from public fork PRs. Consider GitHub-hosted runners."
        ),
        "cwe": "CWE-668",
    },
    {
        "id": "matrix_injection",
        "severity": "high",
        "category": "script_injection",
        "title": "Matrix Variable Injection in Script",
        "pattern": r"run:\s*.*\${{.*matrix\..*}}",
        "description": (
            "Matrix variables interpolated directly into run commands. If the "
            "matrix values come from user input or are configurable by PR authors, "
            "this can lead to script injection."
        ),
        "recommendation": (
            "Pass matrix values as environment variables instead of inline "
            "in run commands: 'env: { VAR: ${{ matrix.value }} }'"
        ),
        "cwe": "CWE-77",
    },
    {
        "id": "untrusted_checkout_self",
        "severity": "high",
        "category": "context",
        "title": "Checkout PR Head on pull_request_target",
        "pattern": (
            r"pull_request_target\b[\s\S]*?"
            r"actions/checkout@[\s\S]*?"
            r"(?!.*ref:)"
        ),
        "description": (
            "Workflow uses 'pull_request_target' trigger with 'actions/checkout' "
            "but no explicit ref. By default, checkout checks the merge commit "
            "of the PR, not the base branch. This runs untrusted PR code with "
            "full repository permissions."
        ),
        "recommendation": (
            "Explicitly set 'ref: ${{ github.event.pull_request.base.ref }}' "
            "when using 'pull_request_target' with checkout, or use 'ref: main'."
        ),
        "cwe": "CWE-269",
    },
]

# Actions that are considered safe/trustworthy by the community (for pinning checks)
TRUSTED_ACTIONS_PREFIXES = (
    "actions/", "github/", "octokit/", "slackapi/",
    "dependabot/", "renovatebot/", "aws-actions/",
    "google-github-actions/", "azure/", "docker/",
)


# ---------------------------------------------------------------------------
# Actions Scanner
# ---------------------------------------------------------------------------

class ActionsScanner:
    """Scans GitHub Actions workflow files for security issues."""

    def __init__(
        self,
        repo_url: str,
        token: Optional[str] = None,
        claude_api_key: Optional[str] = None,
        claude_model: str = "claude-sonnet-4-20250514",
        output_dir: str = "./reports",
    ):
        self.repo_url = repo_url.rstrip("/")
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        self.claude_api_key = claude_api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.claude_model = claude_model
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Extract owner/repo
        parts = self.repo_url.rstrip("/").split("/")
        if "github.com" in self.repo_url:
            path_parts = [p for p in self.repo_url.split("/") if p][-2:]
            self.owner, self.repo_name = path_parts[0], path_parts[1].replace(".git", "")
        else:
            self.owner, self.repo_name = parts[-2], parts[-1].replace(".git", "")

        self._client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "vu1nz-actions-scanner/1.0",
            },
        )

        self._workflows_cache: list[dict[str, Any]] = []
        self._workflow_contents: dict[str, str] = {}
        self._default_branch: Optional[str] = None

    async def close(self) -> None:
        await self._client.aclose()

    # ── API Methods ─────────────────────────────────────────────────────

    async def list_workflows(self) -> list[dict[str, Any]]:
        """Fetch all workflow files from the repository."""
        if self._workflows_cache:
            return self._workflows_cache

        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        url = f"https://api.github.com/repos/{self.owner}/{self.repo_name}/actions/workflows"

        try:
            resp = await self._client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            self._workflows_cache = data.get("workflows", [])
            return self._workflows_cache
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                console.print(f"[yellow]No workflows found or repo not accessible.[/yellow]")
            else:
                console.print(f"[yellow]GitHub API error: {e.response.status_code}[/yellow]")
            return []
        except Exception as e:
            console.print(f"[yellow]Failed to list workflows: {e}[/yellow]")
            return []

    async def get_workflow_content(self, workflow_path: str) -> str:
        """Fetch workflow file content from GitHub raw content."""
        if workflow_path in self._workflow_contents:
            return self._workflow_contents[workflow_path]

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        # Try default branch first, then main
        default_branch = await self._get_default_branch()
        for branch in (default_branch, "main", "master"):
            raw_url = (
                f"https://raw.githubusercontent.com/"
                f"{self.owner}/{self.repo_name}/{branch}/{workflow_path}"
            )
            try:
                resp = await self._client.get(raw_url, headers=headers, timeout=15.0)
                if resp.status_code == 200:
                    content = resp.text
                    self._workflow_contents[workflow_path] = content
                    return content
            except Exception:
                continue

        return ""

    async def _get_default_branch(self) -> str:
        """Get the default branch of the repository (cached after first fetch)."""
        if self._default_branch:
            return self._default_branch
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            url = f"https://api.github.com/repos/{self.owner}/{self.repo_name}"
            resp = await self._client.get(url, headers=headers)
            if resp.status_code == 200:
                branch = resp.json().get("default_branch", "main")
                self._default_branch = branch
                return branch
        except Exception:
            pass
        self._default_branch = "main"
        return "main"

    # ── Security Scanning ───────────────────────────────────────────────

    async def scan_all_workflows(self) -> ActionsAnalysisResult:
        """Scan all workflow files in the repository."""
        result = ActionsAnalysisResult()
        workflows = await self.list_workflows()

        if not workflows:
            console.print("[yellow]No workflows found to scan.[/yellow]")
            return result

        result.workflow_count = len(workflows)

        console.print(f"[cyan]Found {len(workflows)} workflow(s). Scanning...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {len(workflows)} workflows...[/cyan]",
                total=len(workflows),
            )

            for wf in workflows:
                wf_path = wf.get("path", "")
                wf_name = wf.get("name", wf_path)
                progress.update(task, description=f"[cyan]Scanning {wf_name}[/cyan]")

                content = await self.get_workflow_content(wf_path)
                if content:
                    findings = self._scan_single_workflow(content, wf_path)
                    result.findings.extend(findings)

                    # Count jobs
                    job_count = len(re.findall(r"^\s+[\w_-]+:\s*\n\s+runs-on:", content, re.MULTILINE))
                    result.total_jobs += job_count or 1

                progress.advance(task)

        return result

    def _scan_single_workflow(self, content: str, path: str) -> list[WorkflowFinding]:
        """Run all security checks against a single workflow content."""
        findings: list[WorkflowFinding] = []

        for check in WORKFLOW_CHECKS:
            check_id = check["id"]

            # For missing_permissions_top, check if "permissions:" starts the workflow
            if check_id == "missing_permissions_top":
                if not re.search(r"^permissions:\s", content, re.MULTILINE):
                    findings.append(self._make_finding(check, path, 1, content[:200]))
                continue

            # For deploy_on_push_to_main, match multiline and single-line trigger patterns
            if check_id == "deploy_on_push_to_main":
                multiline_match = re.search(check["pattern"], content, re.MULTILINE)
                singleline_match = re.search(r"on:\s*\[?\s*push\b", content)
                if multiline_match or singleline_match:
                    findings.append(self._make_finding(check, path, 1, content[:300]))
                continue

            # For dangerous_deployment_env: custom logic to handle both
            # "environment: production\n" (single line) and
            # "environment:\n  production\n" (multi-line YAML)
            if check_id == "dangerous_deployment_env":
                env_match = re.search(r"environment:[^\n]*", content)
                if env_match:
                    pos = env_match.start()
                    after = content[pos:]
                    if "required_reviewers" not in after:
                        line_no = content[:pos].count("\n") + 1
                        snippet = content[max(0, pos - 30):pos + 80]
                        findings.append(
                            WorkflowFinding(
                                title=check["title"],
                                severity=check["severity"],
                                category=check["category"],
                                file=path,
                                line=line_no,
                                description=check["description"],
                                code_snippet=snippet.strip()[:300],
                                recommendation=check["recommendation"],
                                cwe=check.get("cwe", ""),
                            )
                        )
                continue

            # For untrusted_checkout_self: custom logic to avoid regex lookahead bug
            # where lazy [\s\S]*? can consume "ref:" to make negative lookahead pass
            if check_id == "untrusted_checkout_self":
                if re.search(r"pull_request_target", content) and re.search(r"actions/checkout@", content):
                    checkout_pos = content.find("actions/checkout@")
                    after_checkout = content[checkout_pos:]
                    if not re.search(r"ref:", after_checkout):
                        # Determine line number from checkout position
                        line_no = content[:checkout_pos].count("\n") + 1
                        snippet = content[max(0, checkout_pos - 30):checkout_pos + 80]
                        findings.append(
                            WorkflowFinding(
                                title=check["title"],
                                severity=check["severity"],
                                category=check["category"],
                                file=path,
                                line=line_no,
                                description=check["description"],
                                code_snippet=snippet.strip()[:300],
                                recommendation=check["recommendation"],
                                cwe=check.get("cwe", ""),
                            )
                        )
                continue

            # For pull_request_target and secret_exposure patterns, use multiline matching
            if any(kw in check_id for kw in ("pull_request_target", "secret_exposure", "upload_download")):
                pattern = check["pattern"]
                match = re.search(pattern, content, re.DOTALL)
                if match:
                    start = max(0, match.start() - 50)
                    snippet = content[start:match.end() + 50]
                    line_no = content[:match.start()].count("\n") + 1
                    findings.append(
                        WorkflowFinding(
                            title=check["title"],
                            severity=check["severity"],
                            category=check["category"],
                            file=path,
                            line=line_no,
                            description=check["description"],
                            code_snippet=snippet.strip()[:300],
                            recommendation=check["recommendation"],
                            cwe=check.get("cwe", ""),
                        )
                    )
                continue

            # Line-by-line checks
            lines = content.split("\n")
            for line_no, line in enumerate(lines, 1):
                match = re.search(check["pattern"], line, re.IGNORECASE)
                if match:
                    findings.append(
                        WorkflowFinding(
                            title=check["title"],
                            severity=check["severity"],
                            category=check["category"],
                            file=path,
                            line=line_no,
                            description=check["description"],
                            code_snippet=line.strip()[:200],
                            recommendation=check["recommendation"],
                            cwe=check.get("cwe", ""),
                        )
                    )

        # Deduplicate by (title, file, line)
        seen: set[tuple[str, str, int]] = set()
        unique: list[WorkflowFinding] = []
        for f in findings:
            key = (f.title, f.file, f.line)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _make_finding(self, check: dict, path: str, line: int, snippet: str) -> WorkflowFinding:
        return WorkflowFinding(
            title=check["title"],
            severity=check["severity"],
            category=check["category"],
            file=path,
            line=line,
            description=check["description"],
            code_snippet=snippet.strip()[:200],
            recommendation=check["recommendation"],
            cwe=check.get("cwe", ""),
        )

    # ── Claude AI Code Review ───────────────────────────────────────────

    async def review_with_claude(
        self,
        workflow_content: str,
        workflow_name: str = "workflow.yml",
    ) -> Optional[str]:
        """Send a workflow file to Claude for deep code review.

        Returns Claude's analysis text, or None if unavailable.
        """
        if not self.claude_api_key:
            console.print("[yellow]No ANTHROPIC_API_KEY set. Skipping Claude review.[/yellow]")
            return None

        prompt = (
            "You are a senior CI/CD security engineer reviewing a GitHub Actions workflow file. "
            "Identify ALL security issues including:\n"
            "1. Script injection vectors (user-controlled data in run commands)\n"
            "2. Secrets exposed to pull requests from forks\n"
            "3. Dangerous trigger usage (pull_request_target, workflow_run)\n"
            "4. Supply chain risks (unpinned actions, untrusted third-party actions)\n"
            "5. Permission issues (write-all, missing read scope)\n"
            "6. Deployment security (missing environment protection)\n"
            "7. Token abuse (GITHUB_TOKEN permissions, token leaks)\n"
            "8. Cache poisoning risks\n\n"
            f"Workflow file: {workflow_name}\n\n"
            "```yaml\n"
            f"{workflow_content[:12000]}\n"
            "```\n\n"
            "For each issue, provide:\n"
            "- **Severity**: critical/high/medium/low\n"
            "- **Line**: line number\n"
            "- **Issue**: description of the vulnerability\n"
            "- **Exploitation**: how an attacker could exploit this\n"
            "- **Fix**: exact code/steps to remediate\n\n"
            "Also provide a one-paragraph overall security assessment.\n"
            "Be specific, technical, and actionable. Focus on REAL exploitable vulnerabilities."
        )

        try:
            console.print(f"[dim]  Sending {workflow_name} to Claude for review...[/dim]")

            from vu1nz.ai.providers import AnthropicClient

            claude = AnthropicClient(
                api_key=self.claude_api_key,
                default_model=self.claude_model,
            )

            response = await claude.chat(
                message=prompt,
                system_prompt=(
                    "You are a CI/CD security expert. Respond with a detailed, technical "
                    "security review. Use markdown formatting. Be thorough — missing an issue "
                    "could lead to a real breach."
                ),
                max_tokens=4096,
            )

            return response.content

        except ImportError:
            console.print("[red]vu1nz.ai.providers.AnthropicClient not available.[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Claude review failed: {e}[/red]")
            return None

    async def claude_review_all(
        self,
        claude_model: str = "claude-sonnet-4-20250514",
        max_files: int = 5,
    ) -> ActionsAnalysisResult:
        """Scan all workflows AND send each to Claude for deep review."""
        result = await self.scan_all_workflows()

        if not self.claude_api_key:
            result.ai_summary = "Claude review skipped: ANTHROPIC_API_KEY not set."
            return result

        workflows = self._workflows_cache[:max_files]
        if not workflows:
            workflows = await self.list_workflows()
            workflows = workflows[:max_files]

        if not workflows:
            return result

        reviews: list[str] = []
        for wf in workflows:
            path = wf.get("path", "")
            name = wf.get("name", path)
            content = await self.get_workflow_content(path)
            if content:
                review = await self.review_with_claude(content, name)
                if review:
                    reviews.append(f"## {name}\n\n{review.strip()}")

                    # Parse AI findings and add them
                    ai_findings = self._parse_claude_findings(review, path)
                    result.findings.extend(ai_findings)
                    result.workflow_count += 1

        if reviews:
            result.ai_summary = "\n\n---\n\n".join(reviews)

        return result

    def _parse_claude_findings(self, review: str, path: str) -> list[WorkflowFinding]:
        """Parse structured findings from Claude's markdown response."""
        findings: list[WorkflowFinding] = []

        # Look for severity-prefixed issues
        severity_pattern = re.compile(
            r"(?:\*\*Severity\*\*|Severity)[:\s]*(critical|high|medium|low)",
            re.IGNORECASE,
        )
        issue_pattern = re.compile(
            r"(?:\*\*Issue\*\*|Issue)[:\s]*[：:](.*?)(?=\n\n|\*\*|$)",
            re.DOTALL,
        )
        fix_pattern = re.compile(
            r"(?:\*\*Fix\*\*|Fix)[:\s]*[：:](.*?)(?=\n\n|\*\*|$)",
            re.DOTALL,
        )
        line_pattern = re.compile(
            r"(?:\*\*Line\*\*|Line)[:\s]*[：:]?\s*(\d+)",
        )

        # Split by severity markers to find individual findings
        parts = re.split(r"\n(?:\d+\.\s*)?(?:\*\*)?Severity(?:\*\*)?[:\s]", review)
        for part in parts[1:]:
            sev_match = re.match(r"\s*(critical|high|medium|low)", part, re.IGNORECASE)
            severity = sev_match.group(1).lower() if sev_match else "medium"

            issue_match = issue_pattern.search(part)
            issue = issue_match.group(1).strip() if issue_match else ""

            fix_match = fix_pattern.search(part)
            fix = fix_match.group(1).strip() if fix_match else ""

            line_match = line_pattern.search(part)
            line = int(line_match.group(1)) if line_match else 0

            if issue:
                findings.append(
                    WorkflowFinding(
                        title=f"Claude AI: {issue[:80].rstrip('.')}",
                        severity=severity,
                        category="ai_review",
                        file=path,
                        line=line,
                        description=issue[:500],
                        code_snippet="",
                        recommendation=fix[:500],
                        ai_generated=True,
                    )
                )

        return findings

    # ── Output & Reporting ──────────────────────────────────────────────

    def print_results(self, result: ActionsAnalysisResult) -> None:
        """Print scan results in a formatted table."""
        if not result.findings and not result.ai_summary:
            console.print("[green]✓ No security issues found in workflows.[/green]")
            return

        # Severity counts
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in result.findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1

        # Summary panel
        summary_lines = [
            f"[bold]Workflows scanned:[/bold] {result.workflow_count}",
            f"[bold]Jobs analyzed:[/bold] {result.total_jobs}",
            f"[bold]Findings:[/bold] {len(result.findings)}",
        ]
        if counts["critical"]:
            summary_lines.append(f"  [red]Critical: {counts['critical']}[/red]")
        if counts["high"]:
            summary_lines.append(f"  [orange]High: {counts['high']}[/orange]")
        if counts["medium"]:
            summary_lines.append(f"  [yellow]Medium: {counts['medium']}[/yellow]")
        if counts["low"]:
            summary_lines.append(f"  [blue]Low: {counts['low']}[/blue]")
        if counts["info"]:
            summary_lines.append(f"  [dim]Info: {counts['info']}[/dim]")

        ai_count = sum(1 for f in result.findings if f.ai_generated)
        if ai_count:
            summary_lines.append(f"[bold]Claude AI findings:[/bold] {ai_count}")

        console.print()
        console.print(Panel(
            "\n".join(summary_lines),
            title="📊 Actions Security Scan Summary",
            border_style="cyan",
        ))

        # Findings table
        if result.findings:
            table = Table(title="Workflow Security Issues", border_style="cyan")
            table.add_column("Severity", style="bold", width=10)
            table.add_column("Category", width=18)
            table.add_column("File")
            table.add_column("Issue", width=60)

            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                result.findings,
                key=lambda f: (severity_order.get(f.severity.lower(), 99), f.file, f.line),
            )

            for f in sorted_findings:
                color = {
                    "critical": "red",
                    "high": "orange",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "dim",
                }.get(f.severity.lower(), "white")

                file_display = f"{f.file}:{f.line}" if f.line else f.file
                ai_tag = " [dim](AI)[/dim]" if f.ai_generated else ""

                table.add_row(
                    f"[{color}]{f.severity.upper()}[/{color}]",
                    f.category.replace("_", " ").title(),
                    file_display,
                    f.title[:70] + ai_tag,
                )

            console.print()
            console.print(table)

        # Claude AI review section
        if result.ai_summary:
            console.print()
            console.print(Panel(
                result.ai_summary[:2000],
                title="🤖 Claude AI Workflow Review",
                border_style="green",
                subtitle="Full review saved to report file",
            ))

    def save_results(self, result: ActionsAnalysisResult, repo_slug: str = "") -> Path:
        """Save scan results to a JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = repo_slug or f"{self.owner}_{self.repo_name}"
        output_file = self.output_dir / f"actions_scan_{slug}_{timestamp}.json"

        data = {
            "repository": self.repo_url,
            "scan_timestamp": datetime.now().isoformat(),
            "workflow_count": result.workflow_count,
            "total_jobs": result.total_jobs,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "file": f.file,
                    "line": f.line,
                    "description": f.description,
                    "code_snippet": f.code_snippet,
                    "recommendation": f.recommendation,
                    "cwe": f.cwe,
                    "ai_generated": f.ai_generated,
                }
                for f in result.findings
            ],
            "ai_summary": result.ai_summary,
        }

        output_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return output_file
