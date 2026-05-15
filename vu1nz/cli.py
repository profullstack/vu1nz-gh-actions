"""vu1nz-gh-actions CLI entry point."""

import typer

from vu1nz.commands.actions import app as actions_app
from vu1nz.commands.review_pr import app as review_pr_app

app = typer.Typer(
    name="vu1nz",
    help="🔐 GitHub Actions security scanner + AI-powered PR security review",
    no_args_is_help=True,
)

app.add_typer(
    actions_app,
    name="actions",
    help="🔐 GitHub Actions security scanner — workflow vulns + Claude AI code review",
)

app.add_typer(
    review_pr_app,
    name="review-pr",
    help="🔍 AI-powered GitHub PR security review (Anthropic Claude)",
)


def cli_entry():
    """Entry point for the vu1nz CLI."""
    app()


if __name__ == "__main__":
    app()
