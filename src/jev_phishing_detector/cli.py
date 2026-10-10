"""Interface de linha de comando: jev-phishing."""

from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Annotated, Optional

import typer

from .config import Settings, load_settings
from .models import MailProvider, ProviderError
from .storage import StateStore, TrustStore

app = typer.Typer(help="Detector de phishing para Gmail e Microsoft usando o Jev.", no_args_is_help=True)
trust_app = typer.Typer(help="Gerencia enderecos e dominios confiaveis.", no_args_is_help=True)
auth_app = typer.Typer(help="Conecta as contas de email.", no_args_is_help=True)
app.add_typer(trust_app, name="trust")
app.add_typer(auth_app, name="auth")

log = logging.getLogger("jev_phishing_detector")


class ProviderName(str, Enum):
    google = "google"
    microsoft = "microsoft"


def _fail(message: str) -> typer.Exit:
    typer.secho(message, fg=typer.colors.RED, err=True)
    return typer.Exit(1)


@trust_app.command("add")
def trust_add(
    value: Annotated[str, typer.Argument(help="Endereco (ana@empresa.com) ou dominio (empresa.com)")],
    note: Annotated[str, typer.Option("--note", "-n", help="Observacao")] = "",
) -> None:
    """Adiciona um endereco ou dominio confiavel."""
    try:
        entry = TrustStore(load_settings().db_path).add(value, note)
    except ValueError as exc:
        raise _fail(str(exc))
    kind = "dominio" if entry.kind == "domain" else "endereco"
    typer.echo(f"Adicionado {kind} confiavel: {entry.value}")


@trust_app.command("remove")
def trust_remove(value: str) -> None:
    """Remove um endereco ou dominio confiavel."""
    if not TrustStore(load_settings().db_path).remove(value):
        raise _fail(f"Nao encontrado na lista: {value}")
    typer.echo(f"Removido: {value}")


@trust_app.command("list")
def trust_list() -> None:
    """Lista os enderecos e dominios confiaveis."""
    entries = TrustStore(load_settings().db_path).list()
    if not entries:
        typer.echo("Lista vazia. Use: jev-phishing trust add empresa.com")
        return
    for entry in entries:
        kind = "dominio " if entry.kind == "domain" else "endereco"
        typer.echo(f"{kind}  {entry.value}" + (f"  # {entry.note}" if entry.note else ""))


@auth_app.command("google")
def auth_google() -> None:
    """Autoriza o acesso a uma conta Gmail / Google Workspace."""
    from .providers import gmail

    settings = load_settings()
    if not settings.google_client_secrets.exists():
        raise _fail(
            f"Arquivo de credenciais OAuth nao encontrado: {settings.google_client_secrets}\n"
            "Baixe o JSON do cliente OAuth (tipo Desktop) no Google Cloud Console."
        )
    try:
        account = gmail.authorize(settings.google_client_secrets, settings.google_token_path)
    except ProviderError as exc:
        raise _fail(str(exc))
    typer.echo(f"Conta Google conectada: {account}")


@auth_app.command("microsoft")
def auth_microsoft() -> None:
    """Autoriza o acesso a uma conta Outlook.com / Microsoft 365."""
    from .providers import microsoft

    settings = load_settings()
    if not settings.ms_client_id:
        raise _fail("Defina MS_CLIENT_ID no .env (Application ID do app registrado no Entra ID).")
    try:
        account = microsoft.authorize(
            settings.ms_client_id, settings.ms_tenant, settings.ms_token_cache_path, typer.echo
        )
    except ProviderError as exc:
        raise _fail(str(exc))
    typer.echo(f"Conta Microsoft conectada: {account}")


def _build_providers(settings: Settings, only: list[ProviderName]) -> list[MailProvider]:
    wanted = {p.value for p in only} or {"google", "microsoft"}
    explicit = bool(only)
    providers: list[MailProvider] = []
    if "google" in wanted and (explicit or settings.google_token_path.exists()):
        from .providers.gmail import GmailProvider

        providers.append(GmailProvider.from_token(settings.google_token_path, settings.quarantine_label))
    if "microsoft" in wanted and (explicit or settings.ms_token_cache_path.exists()):
        from .providers.microsoft import MicrosoftProvider

        providers.append(
            MicrosoftProvider.from_cache(
                settings.ms_client_id, settings.ms_tenant,
                settings.ms_token_cache_path, settings.quarantine_label,
            )
        )
    return providers


@app.command()
def run(
    once: Annotated[bool, typer.Option("--once", help="Executa um unico ciclo e sai")] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Analisa e mostra o veredito sem alterar os emails")
    ] = False,
    provider: Annotated[
        Optional[list[ProviderName]],
        typer.Option("--provider", "-p", help="Limita a um provedor (padrao: todos os conectados)"),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Monitora as caixas de entrada e isola emails suspeitos."""
    from .analysis.jev import JevAnalyzer
    from .pipeline import Pipeline

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    for noisy in ("httpx", "httpcore", "googleapiclient", "msal", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    settings = load_settings()
    if not settings.jev_api_key:
        raise _fail("Defina JEV_API_KEY no .env.")
    try:
        providers = _build_providers(settings, provider or [])
    except ProviderError as exc:
        raise _fail(str(exc))
    if not providers:
        raise _fail(
            "Nenhuma conta conectada. Rode `jev-phishing auth google` e/ou `jev-phishing auth microsoft`."
        )

    analyzer = JevAnalyzer(
        settings.jev_api_key, settings.jev_base_url, settings.jev_model, settings.phishing_threshold
    )
    pipeline = Pipeline(
        providers, analyzer, TrustStore(settings.db_path), StateStore(settings.db_path),
        dry_run=dry_run,
    )
    accounts = ", ".join(f"{p.name}:{p.account}" for p in providers)
    log.info("Monitorando %s%s", accounts, " (dry-run)" if dry_run else "")
    try:
        while True:
            log.info("Ciclo: %s", pipeline.run_once())
            if once:
                break
            time.sleep(settings.poll_interval_seconds)
    except KeyboardInterrupt:
        log.info("Encerrado.")
    finally:
        analyzer.close()


@app.command()
def status() -> None:
    """Mostra as contas conectadas e o total de emails processados."""
    settings = load_settings()
    typer.echo(f"Google:    {'conectado' if settings.google_token_path.exists() else 'nao conectado'}")
    typer.echo(f"Microsoft: {'conectado' if settings.ms_token_cache_path.exists() else 'nao conectado'}")
    typer.echo(f"Confiaveis: {len(TrustStore(settings.db_path).list())} entradas")
    labels = {"trusted": "confiaveis (sem analise)", "clean": "limpos", "quarantined": "isolados"}
    for outcome, count in sorted(StateStore(settings.db_path).stats().items()):
        typer.echo(f"  {labels.get(outcome, outcome)}: {count}")
