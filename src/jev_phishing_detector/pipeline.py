"""Orquestra um ciclo: buscar emails novos, filtrar confiaveis, analisar e isolar suspeitos."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

from .models import AnalysisError, Analyzer, EmailMessage, MailProvider, ProviderError
from .storage import StateStore, TrustStore

log = logging.getLogger(__name__)


@dataclass
class CycleReport:
    fetched: int = 0
    trusted: int = 0
    clean: int = 0
    quarantined: int = 0
    errors: int = 0

    def __str__(self) -> str:
        return (
            f"{self.fetched} novos | {self.trusted} confiaveis | {self.clean} limpos | "
            f"{self.quarantined} suspeitos | {self.errors} erros"
        )


class Pipeline:
    def __init__(
        self,
        providers: Sequence[MailProvider],
        analyzer: Analyzer,
        trust: TrustStore,
        state: StateStore,
        first_run_lookback: timedelta = timedelta(hours=1),
        dry_run: bool = False,
    ) -> None:
        self.providers = providers
        self.analyzer = analyzer
        self.trust = trust
        self.state = state
        self.first_run_lookback = first_run_lookback
        self.dry_run = dry_run

    def run_once(self) -> CycleReport:
        report = CycleReport()
        for provider in self.providers:
            self._run_provider(provider, report)
        return report

    def _run_provider(self, provider: MailProvider, report: CycleReport) -> None:
        started = datetime.now(timezone.utc)
        since = self.state.get_cursor(provider.name, provider.account) or (
            started - self.first_run_lookback
        )
        try:
            messages = provider.fetch_new(since)
        except ProviderError as exc:
            log.error("[%s:%s] falha ao buscar emails: %s", provider.name, provider.account, exc)
            report.errors += 1
            return

        failed = False
        for message in messages:
            if self.state.is_processed(provider.name, provider.account, message.id):
                continue
            report.fetched += 1
            if not self._handle(provider, message, report):
                failed = True

        if self.dry_run:
            return
        # Com falhas o cursor fica parado para que os emails pendentes sejam buscados de novo.
        self.state.set_cursor(provider.name, provider.account, since if failed else started)

    def _handle(self, provider: MailProvider, message: EmailMessage, report: CycleReport) -> bool:
        tag = f"[{provider.name}:{provider.account}]"
        if self.trust.is_trusted(message.sender_address):
            if message.authenticated:
                log.info("%s confiavel, sem analise: %s", tag, message.sender_address)
                report.trusted += 1
                self._mark(provider, message, "trusted")
                return True
            # Remetente da lista, mas o provedor nao atestou o dominio: pode ser forjado.
            log.warning(
                "%s %s esta na lista de confiaveis mas nao passou na autenticacao (%s); analisando",
                tag, message.sender_address, message.auth_summary,
            )

        try:
            verdict = self.analyzer.analyze(message)
        except AnalysisError as exc:
            log.error("%s analise falhou para %r: %s", tag, message.subject, exc)
            report.errors += 1
            return False

        if not verdict.suspicious:
            log.info("%s limpo (%.0f%%): %r", tag, verdict.probability * 100, message.subject)
            report.clean += 1
            self._mark(provider, message, "clean", verdict.probability)
            return True

        log.warning(
            "%s SUSPEITO (%.0f%%, %s) de %s: %r | %s",
            tag, verdict.probability * 100, verdict.category, message.sender_address,
            message.subject, "; ".join(verdict.reasons) or "sem detalhes",
        )
        report.quarantined += 1
        if self.dry_run:
            return True
        try:
            provider.quarantine(message, verdict)
        except ProviderError as exc:
            log.error("%s falha ao isolar %r: %s", tag, message.subject, exc)
            report.errors += 1
            return False
        self._mark(provider, message, "quarantined", verdict.probability)
        return True

    def _mark(
        self, provider: MailProvider, message: EmailMessage, outcome: str,
        probability: float | None = None,
    ) -> None:
        if not self.dry_run:
            self.state.mark_processed(
                provider.name, provider.account, message.id, outcome, probability
            )
