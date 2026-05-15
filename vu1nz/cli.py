"""vu1nz-gh-actions CLI entry point."""

import typer

from vu1nz.commands.actions import app as actions_app

app = typer.Typer(
    name="vu1nz",
    help="🔐 GitHub Actions security scanner — detect workflow vulns + AI code review",
    no_args_is_help=True,
)

app.add_typer(
    actions_app,
    name="actions",
    help="🔐 GitHub Actions security scanner — workflow vulns + Claude AI code review",
)


def cli_entry():
    """Entry point for the vu1nz CLI."""
    app()


if __name__ == "__main__":
    app()
