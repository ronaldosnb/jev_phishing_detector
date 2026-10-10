"""Tipos e contratos compartilhados por todos os modulos."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class Link:
    text: str
    url: str


@dataclass(frozen=True)
class EmailMessage:
    id: str
    provider: str  # "google" | "microsoft"
    account: str  # endereco da caixa monitorada
    sender_address: str  # endereco do From, em minusculas
    sender_name: str
    reply_to: str | None
    subject: str
    body_text: str
    links: tuple[Link, ...]
    attachment_names: tuple[str, ...]
    received_at: datetime  # timezone-aware (UTC)
    # True somente se o provedor atestou o remetente (ver mailparse.parse_auth_results).
    # A lista de confiaveis so e aplicada quando isto e True.
    authenticated: bool
    auth_summary: str  # ex.: "spf=pass dkim=pass dmarc=pass"

    @property
    def sender_domain(self) -> str:
        return self.sender_address.rsplit("@", 1)[-1]


@dataclass(frozen=True)
class Verdict:
    suspicious: bool
    probability: float  # 0-1, probabilidade de phishing
    category: str
    reasons: tuple[str, ...] = ()


class AnalysisError(Exception):
    """A analise nao pode ser concluida; o email deve ser reprocessado depois."""


class ProviderError(Exception):
    """Falha ao falar com o provedor de email."""


class Analyzer(Protocol):
    def analyze(self, message: EmailMessage) -> Verdict:
        """Levanta AnalysisError se nao for possivel obter um veredito."""
        ...


class MailProvider(Protocol):
    name: str  # "google" | "microsoft"
    account: str

    def fetch_new(self, since: datetime) -> list[EmailMessage]:
        """Mensagens da caixa de entrada recebidas a partir de `since` (pode repetir ja vistas)."""
        ...

    def quarantine(self, message: EmailMessage, verdict: Verdict) -> None:
        """Marca a mensagem com o aviso de phishing e a retira da caixa de entrada."""
        ...
