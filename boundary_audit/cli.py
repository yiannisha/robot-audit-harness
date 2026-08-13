"""Command-line interface for live evidence bundles and replay."""

import shutil
from pathlib import Path

import typer

from . import __version__
from .live import enrich_live_run

app = typer.Typer(add_completion=False, help="Differential network-behavior auditing for black-box devices.")
runs_app = typer.Typer(help="Inspect immutable run artifacts.")
policy_app = typer.Typer(help="Manage generated policies.")
app.add_typer(runs_app, name="runs")
app.add_typer(policy_app, name="policy")
ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "runs"


@app.command()
def doctor() -> None:
    """Check host capabilities without changing system state."""
    typer.echo("boundary-audit %s" % __version__)
    for name in ("ip", "tcpdump", "tshark", "nft", "dnsmasq"):
        typer.echo("%-10s %s" % (name, shutil.which(name) or "not found (Linux backend)"))
@runs_app.command("list")
def runs_list() -> None:
    if not RUNS.exists():
        typer.echo("no runs")
        return
    for path in sorted(RUNS.iterdir()):
        if path.is_dir():
            typer.echo(path.name)


@app.command("enrich-live")
def enrich_live(run_id: str) -> None:
    """Derive normalized flows and analysis from a captured live PCAP."""
    path = RUNS / run_id
    if not path.is_dir():
        raise typer.BadParameter("run not found: %s" % run_id)
    enrich_live_run(path)
    typer.echo(path)


@policy_app.command("generate")
def policy_generate(run_id: str) -> None:
    path = RUNS / run_id
    if not path.is_dir():
        raise typer.BadParameter("run not found: %s" % run_id)
    typer.echo(path / "generated-policy.nft")


if __name__ == "__main__":
    app()
