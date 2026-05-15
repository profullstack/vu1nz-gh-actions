"""PR review command — AI-powered GitHub PR security review."""

import asyncio
import json
import os
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="review-pr",
    help="AI-powered GitHub PR security review (Anthropic Claude)",
    no_args_is_help=True,
)
console = Console()


@app.command()
def main(
    repo: str = typer.Argument(..., help="GitHub repo (owner/repo)"),
    pr_number: int = typer.Argument(..., help="PR number"),
    token: str = typer.Option(None, "--token", help="GitHub token"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        help="Exit non-zero if findings at this severity or above: none, low, medium, high, critical",
    ),
):
    """Review a GitHub PR for security vulnerabilities using AI."""
    asyncio.run(_review_pr(repo, pr_number, token, json_output, fail_on))


async def _review_pr(
    repo: str,
    pr_number: int,
    token: Optional[str],
    json_output: bool,
    fail_on: str,
):
    from vu1nz.ai.providers import AnthropicClient
    from vu1nz.scanners.github_scanner import GitHubScanner

    scanner = GitHubScanner(repo=repo, token=token or os.getenv("GITHUB_TOKEN"))

    try:
        # ── Fetch diff ─────────────────────────────────────────────
        console.print(f"[bold cyan]Reviewing PR #{pr_number} in {repo}...[/bold cyan]")
        diff = await scanner.get_pr_diff(pr_number)

        if not diff:
            console.print("[red]Failed to fetch PR diff (empty or inaccessible)[/red]")
            raise typer.Exit(1)

        console.print(f"[dim]Diff size: {len(diff)} bytes[/dim]")

        # ── AI analysis ────────────────────────────────────────────
        ai = AnthropicClient()
        if not ai.is_available():
            console.print("[red]ANTHROPIC_API_KEY not set — cannot run AI review[/red]")
            raise typer.Exit(1)

        console.print("[dim]Analyzing with Claude...[/dim]")
        analysis = await scanner.analyze_diff_with_ai(diff, ai=ai)

        if not analysis:
            console.print("[yellow]AI analysis returned no results[/yellow]")
            raise typer.Exit(0)

        # ── Parse findings ─────────────────────────────────────────
        findings = scanner.parse_ai_findings(analysis)

        # ── Output ─────────────────────────────────────────────────
        if json_output:
            result = {
                "repository": repo,
                "pr_number": pr_number,
                "findings_count": len(findings),
                "findings": findings,
                "analysis": analysis,
            }
            print(json.dumps(result, indent=2))
        else:
            console.print(
                Panel(analysis, title=f"Security Analysis — PR #{pr_number}", border_style="cyan")
            )

            if findings:
                table = Table(title="Vulnerabilities Found")
                table.add_column("Severity", style="bold")
                table.add_column("File")
                table.add_column("Issue")
                table.add_column("Suggestion")

                for f in findings:
                    color = {
                        "critical": "red",
                        "high": "yellow",
                        "medium": "cyan",
                        "low": "green",
                    }.get(f.get("severity", "low"), "white")
                    table.add_row(
                        f"[{color}]{f.get('severity', 'low').upper()}[/{color}]",
                        f.get("file", "N/A"),
                        f.get("issue", "N/A"),
                        f.get("suggestion", "N/A"),
                    )
                console.print(table)
            else:
                console.print("[green]No security issues found[/green]")

        # ── Fail threshold ─────────────────────────────────────────
        if fail_on != "none" and findings:
            order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            threshold = order.get(fail_on, 3)
            worst = max(order.get(f.get("severity", "").lower(), 0) for f in findings)
            if worst >= threshold:
                console.print(
                    f"[red]Findings at or above {fail_on.upper()} severity — failing[/red]"
                )
                raise typer.Exit(1)

    finally:
        await scanner.close()
