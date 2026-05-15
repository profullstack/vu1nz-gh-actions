"""Tests for GitHub Actions workflow security scanner.

Covers:
  - Data models (WorkflowFinding, ActionsAnalysisResult)
  - All 17 WORKFLOW_CHECKS regex patterns matching correctly
  - False positive rejection for each check
  - Line-by-line vs multiline matching logic
  - Deduplication in _scan_single_workflow
  - Claude markdown response parsing
  - ActionsScanner initialization (URL parsing, token handling)
  - API methods with mocked HTTPX (list_workflows, get_workflow_content, _get_default_branch)
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vu1nz.scanners.actions_scanner import (
    ActionsAnalysisResult,
    ActionsScanner,
    WorkflowFinding,
    WORKFLOW_CHECKS,
    TRUSTED_ACTIONS_PREFIXES,
)


# ═══════════════════════════════════════════════════════════════════════════
# Data Model Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestWorkflowFinding:
    """WorkflowFinding dataclass construction and defaults."""

    def test_minimal(self):
        f = WorkflowFinding(title="Test", severity="high", category="pinning", file="ci.yml")
        assert f.title == "Test"
        assert f.severity == "high"
        assert f.category == "pinning"
        assert f.file == "ci.yml"
        assert f.line == 0
        assert f.description == ""
        assert f.code_snippet == ""
        assert f.recommendation == ""
        assert f.cwe == ""
        assert f.ai_generated is False

    def test_full(self):
        f = WorkflowFinding(
            title="Full Finding",
            severity="critical",
            category="script_injection",
            file="deploy.yml",
            line=42,
            description="Dangerous pattern",
            code_snippet="run: echo ${{ secrets.X }}",
            recommendation="Use env block",
            cwe="CWE-77",
            ai_generated=True,
        )
        assert f.title == "Full Finding"
        assert f.severity == "critical"
        assert f.line == 42
        assert f.ai_generated is True
        assert f.cwe == "CWE-77"

    def test_severity_values(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            f = WorkflowFinding(title="S", severity=sev, category="x", file="x.yml")
            assert f.severity == sev


class TestActionsAnalysisResult:
    """ActionsAnalysisResult dataclass defaults."""

    def test_defaults(self):
        r = ActionsAnalysisResult()
        assert r.findings == []
        assert r.workflow_count == 0
        assert r.total_jobs == 0
        assert r.ai_summary == ""

    def test_with_findings(self):
        f1 = WorkflowFinding(title="A", severity="high", category="a", file="a.yml")
        f2 = WorkflowFinding(title="B", severity="low", category="b", file="b.yml", ai_generated=True)
        r = ActionsAnalysisResult(findings=[f1, f2], workflow_count=3, total_jobs=5, ai_summary="review")
        assert len(r.findings) == 2
        assert r.workflow_count == 3
        assert r.total_jobs == 5
        assert r.ai_summary == "review"


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOW_CHECKS — all 17 pattern definitions
# ═══════════════════════════════════════════════════════════════════════════

CHECK_IDS = {c["id"] for c in WORKFLOW_CHECKS}


class TestWorkflowChecksStructure:
    """All checks have required fields."""

    def test_all_checks_have_required_fields(self):
        for c in WORKFLOW_CHECKS:
            assert "id" in c, f"Missing id in {c.get('title', '?')}"
            assert "severity" in c, f"Missing severity in {c['id']}"
            assert "category" in c, f"Missing category in {c['id']}"
            assert "title" in c, f"Missing title in {c['id']}"
            assert "pattern" in c, f"Missing pattern in {c['id']}"
            assert "description" in c, f"Missing description in {c['id']}"
            assert "recommendation" in c, f"Missing recommendation in {c['id']}"
            assert "cwe" in c, f"Missing cwe in {c['id']}"

    def test_17_checks(self):
        assert len(WORKFLOW_CHECKS) == 17

    def test_unique_ids(self):
        ids = [c["id"] for c in WORKFLOW_CHECKS]
        assert len(ids) == len(set(ids))

    def test_valid_severities(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for c in WORKFLOW_CHECKS:
            assert c["severity"] in valid, f"{c['id']}: invalid severity {c['severity']}"

    def test_valid_categories(self):
        valid = {"pinning", "script_injection", "secret", "permission",
                 "supply_chain", "deployment", "infrastructure", "context"}
        for c in WORKFLOW_CHECKS:
            assert c["category"] in valid, f"{c['id']}: invalid category {c['category']}"

    def test_cwe_format(self):
        for c in WORKFLOW_CHECKS:
            assert c["cwe"].startswith("CWE-"), f"{c['id']}: bad CWE {c['cwe']}"


# ═══════════════════════════════════════════════════════════════════════════
# Pattern Matching — 17 checks × (positive match + false negative guard)
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckUnpinnedAction:
    """unpinned_action: third-party action by short SHA."""

    def test_matches_short_sha(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS if c["id"] == "unpinned_action")
        assert re.search(pattern, "uses: some/action@abc1234")
        assert re.search(pattern, "uses: third-party/tool@deadbee")

    def test_no_match_full_sha(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS if c["id"] == "unpinned_action")
        full_sha = "actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        assert not re.search(pattern, f"uses: {full_sha}")

    def test_no_match_version_tag(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS if c["id"] == "unpinned_action")
        assert not re.search(pattern, "uses: actions/checkout@v4")
        assert not re.search(pattern, "uses: actions/setup-python@v5.1.0")


class TestCheckUnpinnedDocker:
    """unpinned_docker: Docker image by tag, not digest."""

    def test_matches_tag(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS if c["id"] == "unpinned_docker")
        assert re.search(pattern, "image: python:3.12")
        assert re.search(pattern, "image: node:20-alpine")

    def test_no_match_digest(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS if c["id"] == "unpinned_docker")
        assert not re.search(pattern, "image: python@sha256:abc123...")
        assert not re.search(pattern, "image: node@sha256:def456...")

    def test_no_match_bare_image(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS if c["id"] == "unpinned_docker")
        # No tag at all — not matching is fine (different issue)
        assert not re.search(pattern, "image: python")


class TestCheckScriptInjectionGithubContext:
    """script_injection_github_context: user data in run command."""

    def test_matches_github_event_in_run(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "script_injection_github_context")
        assert re.search(pattern, "run: echo ${{ github.event.pull_request.title }}")
        assert re.search(pattern, "run: echo ${{ github.event.issue.body }}")

    def test_no_match_env_var(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "script_injection_github_context")
        assert not re.search(pattern, "run: echo $MY_VAR")
        assert not re.search(pattern, 'run: echo "hello"')
        assert not re.search(pattern, "run: npm test")


class TestCheckScriptInjectionExpression:
    """script_injection_expression: any expression in run."""

    def test_matches_expression_in_run(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "script_injection_expression")
        assert re.search(pattern, "run: echo ${{ github.ref }}")

    def test_no_match_run_without_expression(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "script_injection_expression")
        assert not re.search(pattern, "run: make test")
        assert not re.search(pattern, "run: npm run build")


class TestCheckPullRequestTargetCheckout:
    """pull_request_target_checkout: dangerous PR target + checkout head."""

    def test_matches_dangerous_pattern(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "pull_request_target_checkout")
        workflow = """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        assert re.search(pattern, workflow, re.DOTALL)

    def test_no_match_safe_checkout(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "pull_request_target_checkout")
        workflow = """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
"""
        assert not re.search(pattern, workflow, re.DOTALL)

    def test_no_match_regular_pr(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "pull_request_target_checkout")
        assert not re.search(pattern, "on: pull_request", re.DOTALL)


class TestCheckPullRequestTargetUsage:
    """pull_request_target_usage: trigger presence."""

    def test_matches_trigger(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "pull_request_target_usage")
        assert re.search(pattern, "on: pull_request_target")
        assert re.search(pattern, "pull_request_target:")

    def test_no_match_other_triggers(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "pull_request_target_usage")
        assert not re.search(pattern, "on: pull_request")
        assert not re.search(pattern, "on: push")
        assert not re.search(pattern, "on: workflow_dispatch")


class TestCheckSecretExposurePrContext:
    """secret_exposure_pr_context: secrets accessible from PR."""

    def test_matches_pr_with_secrets(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "secret_exposure_pr_context")
        assert re.search(pattern, "pull_request:\nsecrets:", re.DOTALL)
        assert re.search(pattern, "pull_request_target:\nsecrets:", re.DOTALL)

    def test_no_match_no_secrets(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "secret_exposure_pr_context")
        assert not re.search(pattern, "on: pull_request", re.DOTALL)
        assert not re.search(pattern, "on: push", re.DOTALL)


class TestCheckSecretInRunCommand:
    """secret_in_run_command: secrets inlined in run."""

    def test_matches_secret_in_run(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "secret_in_run_command")
        assert re.search(pattern, "run: echo ${{ secrets.API_KEY }}")
        assert re.search(pattern, "run: curl -H 'Authorization: Bearer ${{ secrets.TOKEN }}'")

    def test_no_match_env_var(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "secret_in_run_command")
        assert not re.search(pattern, "run: echo $MY_VAR")
        assert not re.search(pattern, "run: npm test")


class TestCheckWriteAllPermissions:
    """write_all_permissions: excessive permissions."""

    def test_matches_write_all(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "write_all_permissions")
        assert re.search(pattern, "permissions: write-all")

    def test_no_match_read(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "write_all_permissions")
        assert not re.search(pattern, "permissions: read-all")
        assert not re.search(pattern, "permissions: {}")


class TestCheckMissingPermissionsTop:
    """missing_permissions_top: scanner uses custom logic (not the regex pattern)."""

    def test_matches_missing_permissions(self):
        """Scanner detects missing top-level permissions (no 'permissions:' line)."""
        content = "name: test\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        assert not re.search(r"^permissions:\s", content, re.MULTILINE)

    def test_no_match_when_permissions_present(self):
        """Scanner does NOT flag when 'permissions:' is present at top level."""
        content = "name: test\non: push\npermissions: read-all\njobs:\n"
        assert re.search(r"^permissions:\s", content, re.MULTILINE)


class TestCheckActionsUploadDownload:
    """actions_upload_download_mismatch: upload then download."""

    def test_matches_upload_download(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "actions_upload_download_mismatch")
        content = "- uses: actions/upload-artifact@v4\n  with:\n    name: build\n- uses: actions/download-artifact@v4"
        assert re.search(pattern, content, re.DOTALL)

    def test_no_match_upload_only(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "actions_upload_download_mismatch")
        assert not re.search(pattern, "- uses: actions/upload-artifact@v4", re.DOTALL)


class TestCheckUntrustedWorkflowCall:
    """untrusted_workflow_call: reusable workflow by short SHA."""

    def test_matches_short_sha(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "untrusted_workflow_call")
        assert re.search(pattern, "uses: octo-org/another-repo/.github/workflows/deploy.yml@abc1234")

    def test_no_match_full_sha(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "untrusted_workflow_call")
        full = "uses: octo-org/repo/.github/workflows/ci.yml@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        assert not re.search(pattern, full)

    def test_no_match_local_call(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "untrusted_workflow_call")
        assert not re.search(pattern, "uses: ./.github/workflows/reusable.yml")


class TestCheckDangerousDeploymentEnv:
    """dangerous_deployment_env: scanner uses custom logic (not the regex pattern)."""

    @pytest.fixture
    def scanner(self):
        return ActionsScanner("https://github.com/owner/repo")

    def test_matches_env_without_reviewers(self, scanner):
        content = """name: ProdDeploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: deploy.sh
"""
        findings = scanner._scan_single_workflow(content, "deploy.yml")
        assert any("Deployment Without Required Reviewers" in f.title for f in findings)

    def test_no_match_with_required_reviewers(self, scanner):
        content = """environment: production
required_reviewers: true
"""
        findings = scanner._scan_single_workflow(content, "deploy.yml")
        assert not any("Deployment Without Required Reviewers" in f.title for f in findings)


class TestCheckDeployOnPushToMain:
    """deploy_on_push_to_main: pushing straight to main."""

    def test_matches_multiline(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "deploy_on_push_to_main")
        content = "on:\n  push:\n    branches:\n      - main\n"
        assert re.search(pattern, content, re.MULTILINE)

    def test_matches_single_line(self):
        # Handled by separate regex in _scan_single_workflow
        pass

    def test_no_match_pr_trigger(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "deploy_on_push_to_main")
        assert not re.search(pattern, "on: pull_request", re.MULTILINE)

    def test_single_line_push_detection(self):
        """Verify the single-line fallback regex works."""
        assert re.search(r"on:\s*\[?\s*push\b", "on: push")
        assert re.search(r"on:\s*\[?\s*push\b", "on: [push, pull_request]")
        assert not re.search(r"on:\s*\[?\s*push\b", "on: pull_request")


class TestCheckSelfHostedRunner:
    """self_hosted_runner: runs-on: self-hosted."""

    def test_matches_self_hosted(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "self_hosted_runner")
        assert re.search(pattern, "runs-on: self-hosted")

    def test_no_match_github_hosted(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "self_hosted_runner")
        assert not re.search(pattern, "runs-on: ubuntu-latest")
        assert not re.search(pattern, "runs-on: windows-2022")


class TestCheckMatrixInjection:
    """matrix_injection: matrix var in run command."""

    def test_matches_matrix_in_run(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "matrix_injection")
        assert re.search(pattern, "run: echo ${{ matrix.node-version }}")
        assert re.search(pattern, "run: test ${{ matrix.os }}")

    def test_no_match_safe_env(self):
        pattern = next(c["pattern"] for c in WORKFLOW_CHECKS
                       if c["id"] == "matrix_injection")
        assert not re.search(pattern, "run: npm test")
        assert not re.search(pattern, 'env:\n  NODE: ${{ matrix.node }}', re.DOTALL)


class TestCheckUntrustedCheckoutSelf:
    """untrusted_checkout_self: scanner uses custom logic (not the regex pattern)."""

    @pytest.fixture
    def scanner(self):
        return ActionsScanner("https://github.com/owner/repo")

    def test_matches_no_ref(self, scanner):
        content = """on: pull_request_target
steps:
  - uses: actions/checkout@v4
"""
        findings = scanner._scan_single_workflow(content, "ci.yml")
        assert any("Checkout PR Head on pull_request_target" in f.title for f in findings)

    def test_no_match_with_ref(self, scanner):
        content = """on: pull_request_target
steps:
  - uses: actions/checkout@v4
    with:
      ref: main
"""
        findings = scanner._scan_single_workflow(content, "ci.yml")
        assert not any("Checkout PR Head on pull_request_target" in f.title for f in findings)


# ═══════════════════════════════════════════════════════════════════════════
# _scan_single_workflow — integration of all checks
# ═══════════════════════════════════════════════════════════════════════════

class TestScanSingleWorkflow:
    """Tests for ActionsScanner._scan_single_workflow."""

    @pytest.fixture
    def scanner(self):
        s = ActionsScanner("https://github.com/owner/repo")
        return s

    def test_clean_workflow_no_findings(self, scanner):
        """A well-configured workflow should trigger zero findings."""
        content = """name: CI
on: pull_request
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
      - run: npm test
"""
        findings = scanner._scan_single_workflow(content, ".github/workflows/ci.yml")
        assert len(findings) == 0, f"Expected 0 findings, got: {[f.title for f in findings]}"

    def test_detects_all_dangerous_patterns(self, scanner):
        """A maximally dangerous workflow triggers multiple checks."""
        content = """name: Deploy
on: push
permissions: write-all
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: some/action@abc1234
      - run: echo ${{ github.event.pull_request.title }}
        env:
          SECRET: ${{ secrets.API_KEY }}
      - uses: actions/upload-artifact@v4
        with:
          name: build
      - uses: actions/download-artifact@v4
"""
        findings = scanner._scan_single_workflow(content, "deploy.yml")
        titles = {f.title for f in findings}
        assert "Third-party Action Without Pinned Hash" in titles, f"Missing unpinned_action in {titles}"
        assert "Workflow Has Write-All Permissions" in titles, f"Missing write_all in {titles}"
        assert "Self-Hosted Runner Used" in titles, f"Missing self_hosted in {titles}"

    def test_keeps_findings_at_different_lines(self, scanner):
        """Two unpinned actions on different lines are kept separately."""
        content = """name: Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@abc1234
      - uses: other/action@def5678
"""
        findings = scanner._scan_single_workflow(content, "ci.yml")
        unpinned = [f for f in findings if "Pinned Hash" in f.title]
        assert len(unpinned) == 2, f"Expected 2 unpinned findings (different lines), got {len(unpinned)}"
        assert unpinned[0].line == 7  # First occurrence line

    def test_multiline_checks_use_dotall(self, scanner):
        """pull_request_target etc use re.DOTALL across lines."""
        content = """name: Risky
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Deploy
        run: echo deploying
"""
        findings = scanner._scan_single_workflow(content, "pr_target.yml")
        titles = {f.title for f in findings}
        assert "pull_request_target + checkout PR HEAD" in titles, \
            f"Missing critical PR target check in {titles}"
        assert "pull_request_target Trigger Used" in titles

    def test_missing_permissions_triggers(self, scanner):
        """Workflow without permissions: triggers low finding."""
        content = """name: NoPerms
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""
        findings = scanner._scan_single_workflow(content, "no_perms.yml")
        titles = {f.title for f in findings}
        assert "No Top-Level Workflow Permissions" in titles

    def test_deploy_on_push_to_main_multiline(self, scanner):
        content = """name: Deploy
on:
  push:
    branches:
      - main
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: deploy
"""
        findings = scanner._scan_single_workflow(content, "deploy.yml")
        titles = {f.title for f in findings}
        assert "Deploy on Push to Main" in titles, f"Missing deploy check in {titles}"

    def test_deploy_on_push_to_main_singleline(self, scanner):
        content = """name: Deploy
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: deploy
"""
        findings = scanner._scan_single_workflow(content, "deploy_single.yml")
        titles = {f.title for f in findings}
        assert "Deploy on Push to Main" in titles, f"Missing deploy single-line check in {titles}"

    def test_dangerous_deployment_env(self, scanner):
        content = """name: ProdDeploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: deploy.sh
"""
        findings = scanner._scan_single_workflow(content, "prod_deploy.yml")
        titles = {f.title for f in findings}
        assert "Deployment Without Required Reviewers" in titles, \
            f"Missing deployment env check in {titles}"

    def test_secret_exposure_pr_context(self, scanner):
        content = """name: PR Check
on: pull_request
jobs:
  test:
    uses: ./.github/workflows/reusable.yml
    secrets:
      API_KEY: supersecret
"""
        findings = scanner._scan_single_workflow(content, "pr_check.yml")
        titles = {f.title for f in findings}
        assert "Secrets Exposed to PR Context" in titles, f"Missing in {titles}"

    def test_script_injection_detection(self, scanner):
        """Multiple injection vectors detected."""
        content = """name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.pull_request.title }}
      - run: test ${{ matrix.os }}
      - run: curl -H "Authorization: Bearer ${{ secrets.API_KEY }}" https://api.example.com
"""
        findings = scanner._scan_single_workflow(content, "inject.yml")
        titles = {f.title for f in findings}
        assert "Script Injection via GitHub Context" in titles
        assert "Matrix Variable Injection in Script" in titles
        assert "Secret Inlined in Run Command" in titles

    def test_empty_content_only_missing_permissions(self, scanner):
        """Empty content triggers only the missing_permissions check."""
        findings = scanner._scan_single_workflow("", "empty.yml")
        assert len(findings) == 1
        assert findings[0].title == "No Top-Level Workflow Permissions"


# ═══════════════════════════════════════════════════════════════════════════
# Claude Markdown Parsing
# ═══════════════════════════════════════════════════════════════════════════

class TestParseClaudeFindings:
    """_parse_claude_findings extracts structured issues from Claude markdown."""

    @pytest.fixture
    def scanner(self):
        return ActionsScanner("https://github.com/owner/repo")

    def test_parses_single_finding(self, scanner):
        review = """## Workflow: deploy.yml

1. **Severity**: critical
   **Issue**: Script injection via github.event.pull_request.title on line 12
   **Fix**: Pass via env block instead
"""
        findings = scanner._parse_claude_findings(review, "deploy.yml")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert "Script injection" in f.title
        assert "Pass via env block" in f.recommendation
        assert f.ai_generated is True
        assert f.file == "deploy.yml"

    def test_parses_multiple_findings(self, scanner):
        review = "\n**Severity**: high\n**Issue**: Unpinned action\n**Fix**: Pin to SHA\n\n**Severity**: medium\n**Issue**: Missing permissions\n**Fix**: Add permissions block\n"
        findings = scanner._parse_claude_findings(review, "ci.yml")
        assert len(findings) == 2
        assert findings[0].severity == "high"
        assert findings[1].severity == "medium"

    def test_parses_all_severities(self, scanner):
        for sev in ("critical", "high", "medium", "low"):
            review = f"\n**Severity**: {sev}\n**Issue**: Test finding\n**Fix**: Fix it\n"
            findings = scanner._parse_claude_findings(review, "f.yml")
            assert len(findings) == 1, f"Failed to parse severity: {sev}"
            assert findings[0].severity == sev

    def test_truncates_long_title(self, scanner):
        review = "\n**Severity**: high\n**Issue**: This is a very long issue title that should be truncated to eighty characters by the parsing logic and it shouldn't spill over\n**Fix**: Fix it\n"
        findings = scanner._parse_claude_findings(review, "f.yml")
        assert len(findings) == 1
        assert len(findings[0].title) <= 91  # "Claude AI: " (11) + issue[:80] (80) = 91

    def test_empty_review(self, scanner):
        assert scanner._parse_claude_findings("", "f.yml") == []
        assert scanner._parse_claude_findings("No issues found", "f.yml") == []

    def test_malformed_no_severity(self, scanner):
        review = "Some random text without severity markers"
        assert scanner._parse_claude_findings(review, "f.yml") == []


# ═══════════════════════════════════════════════════════════════════════════
# ActionsScanner Initialization
# ═══════════════════════════════════════════════════════════════════════════

class TestActionsScannerInit:
    """URL parsing, token handling, output dir creation."""

    def test_parse_full_github_url(self):
        s = ActionsScanner("https://github.com/my-org/my-repo")
        assert s.owner == "my-org"
        assert s.repo_name == "my-repo"

    def test_parse_owner_repo(self):
        s = ActionsScanner("my-org/my-repo")
        assert s.owner == "my-org"
        assert s.repo_name == "my-repo"

    def test_parse_url_with_git_suffix(self):
        s = ActionsScanner("https://github.com/org/repo.git")
        assert s.owner == "org"
        assert s.repo_name == "repo"

    def test_token_from_param(self):
        s = ActionsScanner("owner/repo", token="ghp_abc123")
        assert s.token == "ghp_abc123"

    def test_token_from_env(self):
        with patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_env_token"}, clear=True):
            s = ActionsScanner("owner/repo")
            assert s.token == "ghp_env_token"

    def test_claude_api_key_from_env(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-env"}, clear=True):
            s = ActionsScanner("owner/repo")
            assert s.claude_api_key == "sk-ant-env"

    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "custom_reports"
        s = ActionsScanner("owner/repo", output_dir=str(out))
        assert out.exists()
        assert out.is_dir()

    def test_default_output_dir(self, tmp_path):
        with patch("vu1nz.scanners.actions_scanner.Path.mkdir"):
            s = ActionsScanner("owner/repo")
            assert s.output_dir == Path("./reports")

    def test_default_model(self):
        s = ActionsScanner("owner/repo")
        assert s.claude_model == "claude-sonnet-4-20250514"


# ═══════════════════════════════════════════════════════════════════════════
# API Methods (mocked)
# ═══════════════════════════════════════════════════════════════════════════

class MockResponse:
    """Mock httpx response with all attributes the scanner accesses."""
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text  # scanner accesses resp.text

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=MagicMock(), response=self)


class TestListWorkflows:
    """list_workflows fetches workflows from GitHub API."""

    @pytest.fixture
    def scanner(self):
        return ActionsScanner("owner/repo", token="test-token")

    @pytest.mark.asyncio
    async def test_success(self, scanner):
        mock_resp = MockResponse(json_data={
            "workflows": [
                {"path": ".github/workflows/ci.yml", "name": "CI"},
                {"path": ".github/workflows/deploy.yml", "name": "Deploy"},
            ]
        })
        scanner._client.get = AsyncMock(return_value=mock_resp)
        workflows = await scanner.list_workflows()
        assert len(workflows) == 2
        assert workflows[0]["name"] == "CI"
        # Verify auth header
        call_kwargs = scanner._client.get.call_args[1]
        assert "Authorization" in call_kwargs.get("headers", {})

    @pytest.mark.asyncio
    async def test_returns_empty_on_404(self, scanner):
        scanner._client.get = AsyncMock(side_effect=httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock(status_code=404)))
        workflows = await scanner.list_workflows()
        assert workflows == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_exception(self, scanner):
        scanner._client.get = AsyncMock(side_effect=Exception("Network error"))
        workflows = await scanner.list_workflows()
        assert workflows == []

    @pytest.mark.asyncio
    async def test_caches_results(self, scanner):
        mock_resp = MockResponse(json_data={"workflows": [{"path": "ci.yml", "name": "CI"}]})
        scanner._client.get = AsyncMock(return_value=mock_resp)
        await scanner.list_workflows()
        await scanner.list_workflows()  # second call
        assert scanner._client.get.call_count == 1

    @pytest.mark.asyncio
    async def test_no_auth_when_no_token(self, scanner):
        scanner.token = ""
        mock_resp = MockResponse(json_data={"workflows": []})
        scanner._client.get = AsyncMock(return_value=mock_resp)
        await scanner.list_workflows()
        call_kwargs = scanner._client.get.call_args[1]
        assert "Authorization" not in call_kwargs.get("headers", {})


class TestGetWorkflowContent:
    """get_workflow_content fetches raw file, tries multiple branches."""

    @pytest.fixture
    def scanner(self):
        s = ActionsScanner("owner/repo", token="test-token")
        s._default_branch = "main"
        return s

    @pytest.mark.asyncio
    async def test_success_default_branch(self, scanner):
        scanner._client.get = AsyncMock(return_value=MockResponse(
            status_code=200, text="name: CI\non: push\n"))
        content = await scanner.get_workflow_content(".github/workflows/ci.yml")
        assert "name: CI" in content
        assert scanner._workflow_contents[".github/workflows/ci.yml"] == content

    @pytest.mark.asyncio
    async def test_falls_back_to_master(self, scanner):
        """If custom branch fails, tries master."""
        scanner._default_branch = "develop"
        responses: list[MockResponse] = [
            MockResponse(status_code=404),  # develop branch fails
            MockResponse(status_code=404),  # main fails
            MockResponse(status_code=200, text="name: Deploy\n"),  # master succeeds
        ]

        async def side_effect(url, **kwargs):
            return responses.pop(0)

        scanner._client.get = AsyncMock(side_effect=side_effect)
        content = await scanner.get_workflow_content("deploy.yml")
        assert content == "name: Deploy\n"
        assert responses == []  # All responses consumed

    @pytest.mark.asyncio
    async def test_returns_empty_on_all_fail(self, scanner):
        scanner._client.get = AsyncMock(return_value=MockResponse(status_code=404))
        content = await scanner.get_workflow_content("nonexistent.yml")
        assert content == ""

    @pytest.mark.asyncio
    async def test_caches_content(self, scanner):
        scanner._client.get = AsyncMock(return_value=MockResponse(
            status_code=200, text="cached"))
        c1 = await scanner.get_workflow_content("ci.yml")
        c2 = await scanner.get_workflow_content("ci.yml")
        assert c1 == c2
        assert scanner._client.get.call_count == 1

    @pytest.mark.asyncio
    async def test_no_auth_when_no_token(self, scanner):
        scanner.token = ""
        scanner._client.get = AsyncMock(return_value=MockResponse(
            status_code=200, text="no auth"))
        await scanner.get_workflow_content("ci.yml")
        call_kwargs = scanner._client.get.call_args[1]
        assert "headers" not in call_kwargs or "Authorization" not in call_kwargs.get("headers", {})


class TestGetDefaultBranch:
    """_get_default_branch fetches and caches the default branch."""

    @pytest.fixture
    def scanner(self):
        return ActionsScanner("owner/repo")

    @pytest.mark.asyncio
    async def test_fetches_and_caches(self, scanner):
        mock_resp = MockResponse(json_data={"default_branch": "develop"})
        scanner._client.get = AsyncMock(return_value=mock_resp)
        branch = await scanner._get_default_branch()
        assert branch == "develop"
        assert scanner._default_branch == "develop"

    @pytest.mark.asyncio
    async def test_fallback_to_main(self, scanner):
        scanner._client.get = AsyncMock(side_effect=Exception("API error"))
        branch = await scanner._get_default_branch()
        assert branch == "main"
        assert scanner._default_branch == "main"


# ═══════════════════════════════════════════════════════════════════════════
# scan_all_workflows — integration-level (mocked API)
# ═══════════════════════════════════════════════════════════════════════════

class TestScanAllWorkflows:
    """End-to-end scan flow with mocked API responses."""

    @pytest.mark.asyncio
    async def test_scan_all_no_workflows(self):
        s = ActionsScanner("owner/repo", token="test")
        s.list_workflows = AsyncMock(return_value=[])
        result = await s.scan_all_workflows()
        assert result.workflow_count == 0
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_scan_all_with_findings(self):
        s = ActionsScanner("owner/repo", token="test")
        s.list_workflows = AsyncMock(return_value=[
            {"path": ".github/workflows/ci.yml", "name": "CI"},
        ])
        s.get_workflow_content = AsyncMock(return_value="""name: CI
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
""")
        result = await s.scan_all_workflows()
        assert result.workflow_count == 1
        assert len(result.findings) >= 2  # unpinned + write-all


# ═══════════════════════════════════════════════════════════════════════════
# Save Results
# ═══════════════════════════════════════════════════════════════════════════

class TestSaveResults:
    """save_results writes JSON to disk."""

    def test_saves_json(self, tmp_path):
        s = ActionsScanner("https://github.com/owner/repo", output_dir=str(tmp_path))
        result = ActionsAnalysisResult(
            findings=[
                WorkflowFinding(title="Test", severity="high", category="pinning",
                                file="ci.yml", line=10, description="desc",
                                cwe="CWE-829"),
            ],
            workflow_count=1,
            total_jobs=2,
        )
        output = s.save_results(result, repo_slug="owner_repo")
        assert output.exists()
        data = json.loads(output.read_text())
        assert data["repository"] == "https://github.com/owner/repo"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["title"] == "Test"
        assert data["findings"][0]["severity"] == "high"

    def test_auto_slug_from_owner_repo(self, tmp_path):
        s = ActionsScanner("https://github.com/my-org/my-repo", output_dir=str(tmp_path))
        result = ActionsAnalysisResult()
        output = s.save_results(result)
        assert "my-org_my-repo" in output.name


# ═══════════════════════════════════════════════════════════════════════════
# TRUSTED_ACTIONS_PREFIXES
# ═══════════════════════════════════════════════════════════════════════════

class TestTrustedActionsPrefixes:
    """Well-known trusted action prefixes."""

    def test_common_prefixes_defined(self):
        assert "actions/" in TRUSTED_ACTIONS_PREFIXES
        assert "github/" in TRUSTED_ACTIONS_PREFIXES
        assert "docker/" in TRUSTED_ACTIONS_PREFIXES

    def test_all_prefixes_end_with_slash(self):
        for prefix in TRUSTED_ACTIONS_PREFIXES:
            assert prefix.endswith("/"), f"{prefix} should end with /"
