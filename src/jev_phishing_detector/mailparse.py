"""Utilitarios de parsing compartilhados pelos provedores."""

from __future__ import annotations

import re
from email.utils import parseaddr
from html.parser import HTMLParser

from .models import Link

_SKIP_TAGS = {"script", "style", "head", "title"}
_BLOCK_TAGS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table"}
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_HEADER_FROM_RE = re.compile(r"header\.from\s*=\s*([^\s;()]+)", re.IGNORECASE)


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[Link] = []
        self._skip = 0
        self._href: str | None = None
        self._anchor: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")
        elif tag == "a":
            self._href = dict(attrs).get("href") or None
            self._anchor = []

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._href:
            if self._href.lower().startswith(("http://", "https://")):
                self.links.append(Link(" ".join("".join(self._anchor).split()), self._href))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._href:
            self._anchor.append(data)


def _collapse(text: str) -> str:
    lines = (" ".join(line.split()) for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def html_to_text_and_links(html: str) -> tuple[str, tuple[Link, ...]]:
    parser = _Extractor()
    parser.feed(html or "")
    parser.close()
    return _collapse("".join(parser.parts)), tuple(parser.links)


def links_from_text(text: str) -> tuple[Link, ...]:
    return tuple(Link("", url.rstrip(".,;")) for url in _URL_RE.findall(text or ""))


def parse_address(value: str | None) -> tuple[str, str]:
    """Retorna (nome, endereco em minusculas) de um cabecalho como From/Reply-To."""
    name, address = parseaddr(value or "")
    return name, address.strip().lower()


def parse_auth_results(headers: list[str], from_domain: str) -> tuple[bool, str]:
    """Interpreta cabecalhos Authentication-Results adicionados pelo provedor de destino.

    Passe apenas o(s) cabecalho(s) do topo, inseridos pelo proprio provedor (Google/Microsoft);
    cabecalhos mais abaixo podem ter sido forjados pelo remetente.

    O remetente e considerado autenticado somente com dmarc=pass e header.from (quando
    presente) no mesmo dominio do From. SPF/DKIM sozinhos nao bastam: passam para o
    dominio do envelope/assinatura, que pode ser diferente do From exibido ao usuario.
    """
    from_domain = from_domain.lower()
    results: dict[str, str] = {}
    aligned = True
    for header in headers:
        for mechanism, outcome in _RESULT_RE.findall(header):
            results.setdefault(mechanism.lower(), outcome.lower())
        match = _HEADER_FROM_RE.search(header)
        if match:
            claimed = match.group(1).lower()
            aligned = aligned and (
                claimed == from_domain
                or from_domain.endswith("." + claimed)
                or claimed.endswith("." + from_domain)
            )
    summary = " ".join(f"{k}={results[k]}" for k in ("spf", "dkim", "dmarc") if k in results)
    return results.get("dmarc") == "pass" and aligned, summary or "sem resultado de autenticacao"
