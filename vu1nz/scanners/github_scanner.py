"""Lightweight GitHub scanner for PR security review (gh-actions edition)."""

from __future__ import annotations

import os
from typing import Optional

import httpx


class GitHubScanner:
    """Fetch PR diffs and analyze them with AI."""

    def __init__(
        self,
        repo: str,
        token: Optional[str] = None,
    ):
        self.repo = repo  # "owner/repo"
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        self.client = httpx.AsyncClient(timeout=30.0)

    # ── HTTP helpers ───────────────────────────────────────────────

    def _auth_headers(self, extra: Optional[dict] = None) -> dict:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if extra:
            headers.update(extra)
        return headers

    # ── PR diff ────────────────────────────────────────────────────

    async def get_pr_diff(self, pr_number: int) -> str:
        """Fetch the unified diff for a pull request."""
        url = f"https://api.github.com/repos/{self.repo}/pulls/{pr_number}"
        headers = self._auth_headers({"Accept": "application/vnd.github.v3.diff"})
        try:
            resp = await self.client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.text
            print(f"PR diff API returned {resp.status_code}")
            return ""
        except Exception as e:
            print(f"Failed to fetch PR diff: {e}")
            return ""

    # ── AI analysis ────────────────────────────────────────────────

    async def analyze_diff_with_ai(self, diff: str, ai) -> str:
        """Send the diff to an AI client for security review."""
        prompt = f"""You are an expert security engineer reviewing a pull request.

Diff:
```
{diff[:15000]}
```

Find: SQLi, XSS, RCE, command injection, hardcoded secrets, IDOR,
auth/authz flaws, CSRF, SSRF, insecure crypto, path traversal,
dependency risks, CI/CD supply-chain issues.

For each finding give: severity (critical/high/medium/low), file, line,
issue description, fix suggestion.

If there are NO security issues, say so clearly.

Respond in markdown with a findings table:
| Severity | File | Line | Issue | Suggestion |
"""
        try:
            resp = await ai.chat(
                prompt,
                system_prompt="You are an expert security code reviewer. Be thorough but avoid false positives.",
            )
            return resp.content if hasattr(resp, "content") else str(resp)
        except Exception as e:
            print(f"AI analysis failed: {e}")
            return ""

    # ── Parse AI output ────────────────────────────────────────────

    @staticmethod
    def parse_ai_findings(analysis: str) -> list[dict]:
        """Extract structured findings from the AI markdown response."""
        findings: list[dict] = []
        severities = ("critical", "high", "medium", "low")

        for line in analysis.split("\n"):
            lower = line.lower()
            for sev in severities:
                if sev in lower and "|" in line:
                    cols = [c.strip() for c in line.split("|")]
                    cols = [c for c in cols if c]  # drop empty from leading |
                    findings.append(
                        {
                            "severity": sev,
                            "file": cols[1] if len(cols) > 1 else "N/A",
                            "line": cols[2] if len(cols) > 2 else "",
                            "issue": cols[3] if len(cols) > 3 else line.strip()[:120],
                            "suggestion": cols[4] if len(cols) > 4 else "",
                        }
                    )
                    break

        # Deduplicate
        seen: set[str] = set()
        unique: list[dict] = []
        for f in findings:
            key = f"{f['file']}:{f['issue'][:50]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ── Cleanup ────────────────────────────────────────────────────

    async def close(self):
        await self.client.aclose()
