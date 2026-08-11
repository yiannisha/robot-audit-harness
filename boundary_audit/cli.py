"""Command-line interface for deterministic and host-backed workflows."""

import shutil
from pathlib import Path

import typer

from . import __version__
from .dashboard import write_dashboard
from .live import enrich_live_run
from .models import NetworkMode
from .reports import write_reports
from .runner import run_experiment
from .scenarios import load_all
from .dut_simulator import DutSimulator
from .web_app import serve

app = typer.Typer(add_completion=False, help="Differential network-behavior auditing for black-box devices.")
scenarios_app = typer.Typer(help="Inspect scenario definitions.")
lab_app = typer.Typer(help="Manage the lab.")
runs_app = typer.Typer(help="Inspect immutable run artifacts.")
policy_app = typer.Typer(help="Manage generated policies.")
app.add_typer(scenarios_app, name="scenarios")
app.add_typer(lab_app, name="lab")
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
    typer.echo("virtual backend: available (no root or external Internet required)")


@scenarios_app.command("list")
def scenarios_list() -> None:
    for name, action in sorted(load_all(ROOT / "scenarios").items()):
        typer.echo("%-18s %-16s repeats=%d" % (name, action.category.value, action.repeats))


@scenarios_app.command("show")
def scenarios_show(name: str) -> None:
    actions = load_all(ROOT / "scenarios")
    if name not in actions:
        raise typer.BadParameter("unknown scenario: %s" % name)
    typer.echo(actions[name].json(indent=2))


@app.command()
def run(scenario: str, mode: NetworkMode = NetworkMode.OBSERVE, repeats: int = 3) -> None:
    """Run a scenario against the deterministic virtual backend."""
    names = sorted(load_all(ROOT / "scenarios")) if scenario == "full_matrix" else [scenario]
    for name in names:
        output = run_experiment(name, mode, RUNS, DutSimulator.from_config(network_enabled=False), repeats=repeats)
        write_reports(output)
        typer.echo("wrote %s" % output)


@runs_app.command("list")
def runs_list() -> None:
    if not RUNS.exists():
        typer.echo("no runs")
        return
    for path in sorted(RUNS.iterdir()):
        if path.is_dir():
            typer.echo(path.name)


@app.command()
def report(run_id: str) -> None:
    path = RUNS / run_id
    if not path.is_dir():
        raise typer.BadParameter("run not found: %s" % run_id)
    write_reports(path)
    typer.echo(path / "report.html")


@app.command("enrich-live")
def enrich_live(run_id: str) -> None:
    """Derive flows and reports from a captured live PCAP."""
    path = RUNS / run_id
    if not path.is_dir():
        raise typer.BadParameter("run not found: %s" % run_id)
    enrich_live_run(path)
    write_reports(path)
    typer.echo(path / "report.html")


@app.command()
def dashboard(output: Path = Path("dashboard.html")) -> None:
    """Build a standalone index across all retained runs."""
    typer.echo(write_dashboard(RUNS, output))


@app.command("dashboard-serve")
def dashboard_serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve the live dashboard and run-deployment web app."""
    serve(ROOT, host, port)


@policy_app.command("generate")
def policy_generate(run_id: str) -> None:
    path = RUNS / run_id
    if not path.is_dir():
        raise typer.BadParameter("run not found: %s" % run_id)
    typer.echo(path / "generated-policy.nft")


@lab_app.command("up")
def lab_up() -> None:
    typer.echo("virtual lab ready: gateway=10.77.0.1 dut=10.77.0.2")


@lab_app.command("status")
def lab_status() -> None:
    typer.echo("backend=virtual status=ready gateway=10.77.0.1 dut=10.77.0.2")


@lab_app.command("down")
def lab_down() -> None:
    typer.echo("virtual backend has no persistent resources to remove")


if __name__ == "__main__":
    app()
