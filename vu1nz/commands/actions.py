"""CLI commands for GitHub Actions security scanning and Claude AI code review."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="actions",
    help="🔐 GitHub Actions security scanner — workflow vulns + Claude AI code review",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    repo: str = typer.Argument(
        ...,
        help="GitHub repository (owner/repo or full URL)",
    ),
    token: str = typer.Option(
        None, "--token", "-t",
        help="GitHub personal access token (or GITHUB_TOKEN env var)",
    ),
    claude: bool = typer.Option(
        False, "--claude", "-c",
        help="Enable code review via Claude API (requires ANTHROPIC_API_KEY)",
    ),
    claude_model: str = typer.Option(
        "claude-sonnet-4-20250514",
        "--claude-model", "-m",
        help="Claude model for code review",
    ),
    max_files: int = typer.Option(
        5, "--max-files", "-n",
        help="Max workflow files to send for Claude review",
    ),
    output: str = typer.Option(
        "./reports", "--output", "-o",
        help="Output directory for reports",
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j",
        help="Print results as JSON instead of formatted output",
    ),
):
    """Scan a repository's GitHub Actions workflows for security vulnerabilities.

    Detects script injection, secret leaks, permission issues, unpinned actions,
    supply chain risks, and other CI/CD security anti-patterns.

    Example:

        vu1nz actions scan owner/repo

        vu1nz actions scan https://github.com/owner/repo --claude

        vu1nz actions scan owner/repo --token ghp_xxxx --claude --json
    """
    asyncio.run(_run_scan(
        repo=repo,
        token=token,
        claude=claude,
        claude_model=claude_model,
        max_files=max_files,
        output_dir=output,
        json_output=json_output,
    ))


@app.command()
def review(
    repo: str = typer.Argument(
        ...,
        help="GitHub repository (owner/repo or full URL)",
    ),
    workflow: str = typer.Argument(
        ...,
        help="Workflow file path (e.g., .github/workflows/deploy.yml)",
    ),
    token: str = typer.Option(
        None, "--token", "-t",
        help="GitHub personal access token",
    ),
    claude_model: str = typer.Option(
        "claude-sonnet-4-20250514",
        "--claude-model", "-m",
        help="Claude model for code review",
    ),
):
    """Deep code review of a single workflow file using Claude AI.

    Example:

        vu1nz actions review owner/repo .github/workflows/deploy.yml

        vu1nz actions review owner/repo .github/workflows/ci.yml -m claude-3-5-sonnet-20241022
    """
    asyncio.run(_run_review(
        repo=repo,
        workflow_path=workflow,
        token=token,
        claude_model=claude_model,
    ))


@app.command()
def list(
    repo: str = typer.Argument(
        ...,
        help="GitHub repository (owner/repo or full URL)",
    ),
    token: str = typer.Option(
        None, "--token", "-t",
        help="GitHub personal access token",
    ),
):
    """List all workflow files in a repository."""
    asyncio.run(_run_list(
        repo=repo,
        token=token,
    ))


# ── Implementation ──────────────────────────────────────────────────────


def _normalize_repo(repo: str) -> str:
    """Normalize repo input to full URL."""
    repo = repo.strip().rstrip("/").removesuffix(".git")
    if "github.com" in repo:
        return repo
    if "/" in repo and not repo.startswith("http"):
        return f"https://github.com/{repo}"
    return repo


async def _run_scan(
    repo: str,
    token: Optional[str],
    claude: bool,
    claude_model: str,
    max_files: int,
    output_dir: str,
    json_output: bool,
) -> None:
    repo_url = _normalize_repo(repo)

    from vu1nz.scanners.actions_scanner import ActionsScanner

    scanner = ActionsScanner(
        repo_url=repo_url,
        token=token or os.getenv("GITHUB_TOKEN"),
        claude_api_key=os.getenv("ANTHROPIC_API_KEY"),
        claude_model=claude_model,
        output_dir=output_dir,
    )

    try:
        console.print(f"[bold cyan]🔐 Scanning workflows in[/bold cyan] [cyan]{repo_url}[/cyan]")

        if claude:
            console.print("[dim]Claude AI review enabled.[/dim]")
            result = await scanner.claude_review_all(
                claude_model=claude_model,
                max_files=max_files,
            )
        else:
            result = await scanner.scan_all_workflows()

        if json_output:
            data = {
                "repository": repo_url,
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
            console.print(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            scanner.print_results(result)

        # Save report
        output_path = scanner.save_results(result, repo_url.split("/")[-1])
        console.print(f"\n[dim]Report saved to: {output_path}[/dim]")

    finally:
        await scanner.close()


async def _run_review(
    repo: str,
    workflow_path: str,
    token: Optional[str],
    claude_model: str,
) -> None:
    repo_url = _normalize_repo(repo)

    from vu1nz.scanners.actions_scanner import ActionsScanner

    scanner = ActionsScanner(
        repo_url=repo_url,
        token=token or os.getenv("GITHUB_TOKEN"),
        claude_api_key=os.getenv("ANTHROPIC_API_KEY"),
        claude_model=claude_model,
    )

    try:
        console.print(f"[bold green]🤖 Claude AI review of[/bold green] [green]{workflow_path}[/green] in {repo_url}")

        content = await scanner.get_workflow_content(workflow_path)
        if not content:
            console.print(f"[red]Could not fetch workflow file: {workflow_path}[/red]")
            console.print("[yellow]Make sure the file path is correct and the repository is accessible.[/yellow]")
            return

        # Print file info
        lines = content.count("\n") + 1
        console.print(f"[dim]File: {workflow_path} ({lines} lines)[/dim]")

        # Run scanner checks first
        checks = scanner._scan_single_workflow(content, workflow_path)
        if checks:
            table = Table(title="Automated Security Checks")
            table.add_column("Severity", style="bold", width=10)
            table.add_column("Issue")
            for c in checks[:10]:
                color = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue", "info": "dim"}
                table.add_row(
                    f"[{color.get(c.severity.lower(), 'white')}]{c.severity.upper()}[/]",
                    c.title[:70],
                )
            console.print()
            console.print(table)

        # Claude review
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            console.print("[yellow]ANTHROPIC_API_KEY not set. Install with: export ANTHROPIC_API_KEY='sk-ant-...'[/yellow]")
            return

        review = await scanner.review_with_claude(content, workflow_path)
        if review:
            console.print()
            console.print(Panel(review[:3000], title="🤖 Claude Review", border_style="green"))
            if len(review) > 3000:
                console.print("[dim]Review truncated. Full text saved to report.[/dim]")

    finally:
        await scanner.close()


async def _run_list(
    repo: str,
    token: Optional[str],
) -> None:
    repo_url = _normalize_repo(repo)

    from vu1nz.scanners.actions_scanner import ActionsScanner

    scanner = ActionsScanner(
        repo_url=repo_url,
        token=token or os.getenv("GITHUB_TOKEN"),
    )

    try:
        console.print(f"[bold cyan]Workflows in[/bold cyan] [cyan]{repo_url}[/cyan]")

        workflows = await scanner.list_workflows()
        if not workflows:
            console.print("[yellow]No workflows found.[/yellow]")
            return

        table = Table(title=f"Workflows ({len(workflows)})")
        table.add_column("Name")
        table.add_column("Path")
        table.add_column("State")
        table.add_column("Last Run")

        for wf in workflows:
            state = "✅ Active" if wf.get("state") == "active" else "❌ Disabled"
            last_run = "—"
            if wf.get("updated_at"):
                last_run = wf["updated_at"][:10]
            table.add_row(
                wf.get("name", "Unnamed"),
                wf.get("path", ""),
                state,
                last_run,
            )

        console.print()
        console.print(table)

    finally:
        await scanner.close()
