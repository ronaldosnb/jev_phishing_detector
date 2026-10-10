"""Provedor Google (Gmail API v1)."""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime
from pathlib import Path

import httplib2
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from ..mailparse import (
    html_to_text_and_links,
    links_from_text,
    parse_address,
    parse_auth_results,
)
from ..models import EmailMessage, Link, ProviderError, Verdict

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
MAX_MESSAGES_PER_FETCH = 200
SAFETY_MARGIN_SECONDS = 60
TRUSTED_AUTHSERV_ID = "mx.google.com"
_RELOGIN = "Execute `jev-phishing auth google` para autorizar o acesso ao Gmail."


def _save_token(credentials: Credentials, token_path: Path) -> None:
    token_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(credentials.to_json())
    os.chmod(token_path, 0o600)


def _wrap(exc: Exception) -> ProviderError:
    if isinstance(exc, HttpError):
        return ProviderError(f"Erro na API do Gmail (HTTP {exc.resp.status}).")
    return ProviderError(f"Falha de comunicacao com o Gmail ({type(exc).__name__}).")


_TRANSPORT_ERRORS = (HttpError, httplib2.HttpLib2Error, OSError)


def _profile_email(service) -> str:
    try:
        profile = service.users().getProfile(userId="me").execute()
    except _TRANSPORT_ERRORS as exc:
        raise _wrap(exc) from exc
    return profile["emailAddress"]


def authorize(client_secrets: Path, token_path: Path) -> str:
    """Autorizacao interativa (navegador local); salva o token e devolve o email da conta."""
    flow = InstalledAppFlow.from_client_secrets_file(str(client_secrets), SCOPES)
    credentials = flow.run_local_server(port=0)
    _save_token(credentials, token_path)
    service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
    return _profile_email(service)


def load_credentials(token_path: Path) -> Credentials:
    if not token_path.exists():
        raise ProviderError(f"Token do Google nao encontrado. {_RELOGIN}")
    try:
        credentials = Credentials.from_authorized_user_file(str(token_path), SCOPES)
    except (ValueError, OSError) as exc:
        raise ProviderError(f"Token do Google invalido. {_RELOGIN}") from exc
    if not credentials.valid:
        if not (credentials.expired or not credentials.token) or not credentials.refresh_token:
            raise ProviderError(f"Token do Google sem permissao de renovacao. {_RELOGIN}")
        try:
            credentials.refresh(Request())
        except (GoogleAuthError, httplib2.HttpLib2Error, OSError) as exc:
            raise ProviderError(f"Nao foi possivel renovar o token do Google. {_RELOGIN}") from exc
        _save_token(credentials, token_path)
    return credentials


def _decode(data: str | None) -> str:
    if not data:
        return ""
    raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    return raw.decode("utf-8", errors="replace")


def _walk(part: dict, html: list[str], plain: list[str], attachments: list[str]) -> None:
    filename = part.get("filename")
    if filename:
        attachments.append(filename)
    else:
        mime = part.get("mimeType", "")
        data = (part.get("body") or {}).get("data")
        if mime == "text/html" and data:
            html.append(_decode(data))
        elif mime == "text/plain" and data:
            plain.append(_decode(data))
    for child in part.get("parts") or []:
        _walk(child, html, plain, attachments)


def _headers(payload: dict) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for header in payload.get("headers") or []:
        result.setdefault(header["name"].lower(), []).append(header["value"])
    return result


def _trusted_auth_headers(values: list[str]) -> list[str]:
    return [v for v in values if v.split(";", 1)[0].strip().lower() == TRUSTED_AUTHSERV_ID]


def _to_message(raw: dict, account: str) -> EmailMessage:
    payload = raw.get("payload") or {}
    headers = _headers(payload)

    def first(name: str) -> str | None:
        values = headers.get(name)
        return values[0] if values else None

    sender_name, sender_address = parse_address(first("from"))
    _, reply_to = parse_address(first("reply-to"))

    html: list[str] = []
    plain: list[str] = []
    attachments: list[str] = []
    _walk(payload, html, plain, attachments)
    links: tuple[Link, ...]
    if html:
        body_text, links = html_to_text_and_links("\n".join(html))
    else:
        body_text = "\n".join(plain)
        links = links_from_text(body_text)

    from_domain = sender_address.rsplit("@", 1)[-1]
    trusted = _trusted_auth_headers(headers.get("authentication-results", []))
    if trusted:
        authenticated, summary = parse_auth_results(trusted, from_domain)
    else:
        authenticated, summary = False, "sem resultado de autenticacao"

    received = datetime.fromtimestamp(int(raw.get("internalDate", 0)) / 1000, tz=UTC)
    return EmailMessage(
        id=raw["id"],
        provider="google",
        account=account,
        sender_address=sender_address,
        sender_name=sender_name,
        reply_to=reply_to or None,
        subject=first("subject") or "",
        body_text=body_text,
        links=links,
        attachment_names=tuple(attachments),
        received_at=received,
        authenticated=authenticated,
        auth_summary=summary,
    )


class GmailProvider:
    name = "google"

    def __init__(self, service, account: str, quarantine_label: str) -> None:
        self._service = service
        self.account = account
        self._label_name = quarantine_label
        self._label_id: str | None = None

    @classmethod
    def from_token(cls, token_path: Path, quarantine_label: str) -> GmailProvider:
        credentials = load_credentials(token_path)
        service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
        return cls(service, _profile_email(service), quarantine_label)

    def _list_ids(self, since: datetime) -> list[str]:
        after = int(since.timestamp()) - SAFETY_MARGIN_SECONDS
        ids: list[str] = []
        token = None
        messages = self._service.users().messages()
        while len(ids) < MAX_MESSAGES_PER_FETCH:
            response = messages.list(
                userId="me",
                q=f"in:inbox after:{after}",
                pageToken=token,
                maxResults=min(100, MAX_MESSAGES_PER_FETCH - len(ids)),
            ).execute()
            ids.extend(m["id"] for m in response.get("messages") or [])
            token = response.get("nextPageToken")
            if not token:
                break
        return ids[:MAX_MESSAGES_PER_FETCH]

    def fetch_new(self, since: datetime) -> list[EmailMessage]:
        try:
            ids = self._list_ids(since)
            found: list[EmailMessage] = []
            for message_id in ids:
                try:
                    raw = (
                        self._service.users()
                        .messages()
                        .get(userId="me", id=message_id, format="full")
                        .execute()
                    )
                except HttpError as exc:
                    if exc.resp.status == 404:
                        continue
                    raise
                found.append(_to_message(raw, self.account))
        except _TRANSPORT_ERRORS as exc:
            raise _wrap(exc) from exc
        found.sort(key=lambda m: m.received_at)
        return found

    def _ensure_label(self) -> str:
        if self._label_id:
            return self._label_id
        labels = self._service.users().labels()
        existing = labels.list(userId="me").execute().get("labels") or []
        for label in existing:
            if label.get("name") == self._label_name:
                self._label_id = label["id"]
                return self._label_id
        body = {
            "name": self._label_name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
            "color": {"backgroundColor": "#cc3a21", "textColor": "#ffffff"},
        }
        self._label_id = labels.create(userId="me", body=body).execute()["id"]
        return self._label_id

    def quarantine(self, message: EmailMessage, verdict: Verdict) -> None:
        try:
            label_id = self._ensure_label()
            self._service.users().messages().modify(
                userId="me",
                id=message.id,
                body={"addLabelIds": [label_id], "removeLabelIds": ["INBOX"]},
            ).execute()
        except _TRANSPORT_ERRORS as exc:
            raise _wrap(exc) from exc
