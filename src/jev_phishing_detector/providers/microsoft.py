"""Provedor Microsoft (Outlook.com e Microsoft 365) via Microsoft Graph."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import msal

from ..mailparse import (
    html_to_text_and_links,
    links_from_text,
    parse_address,
    parse_auth_results,
)
from ..models import EmailMessage, ProviderError, Verdict

SCOPES = ["Mail.ReadWrite", "User.Read"]
GRAPH = "https://graph.microsoft.com/v1.0"

MAX_MESSAGES = 200
PAGE_SIZE = 50
TIMEOUT = 20.0
MAX_RETRIES = 2
OVERLAP = timedelta(seconds=60)
_SELECT = (
    "id,subject,from,replyTo,receivedDateTime,body,hasAttachments,internetMessageHeaders"
)

# patchavel nos testes
_sleep = time.sleep

_AUTH_HINT = "Execute `jev-phishing auth microsoft` para autorizar a conta."


def _save_cache(cache: msal.SerializableTokenCache, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(cache.serialize())
    os.chmod(path, 0o600)


def _load_cache(path: Path) -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    try:
        cache.deserialize(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return cache


def _app(client_id: str, tenant: str, cache) -> msal.PublicClientApplication:
    return msal.PublicClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant or 'common'}",
        token_cache=cache,
    )


def authorize(
    client_id: str,
    tenant: str,
    cache_path: Path,
    prompt: Callable[[str], None] = print,
) -> str:
    """Fluxo device code; salva o cache e devolve o email/UPN da conta."""
    cache = _load_cache(cache_path)
    app = _app(client_id, tenant, cache)
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise ProviderError(
            f"Nao foi possivel iniciar a autorizacao Microsoft: {flow.get('error', 'erro')}"
        )
    prompt(flow["message"])
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise ProviderError(
            f"Autorizacao Microsoft falhou: {result.get('error', 'erro')}"
        )
    _save_cache(cache, cache_path)
    claims = result.get("id_token_claims") or {}
    account = claims.get("preferred_username") or claims.get("email")
    if not account:
        accounts = app.get_accounts()
        account = accounts[0].get("username") if accounts else ""
    return str(account or "")


class TokenSource:
    def __init__(self, client_id: str, tenant: str, cache_path: Path) -> None:
        self._path = cache_path
        self._cache = _load_cache(cache_path)
        self._app = _app(client_id, tenant, self._cache)
        accounts = self._app.get_accounts()
        self._account = accounts[0] if accounts else None

    @property
    def account(self) -> str:
        return self._account.get("username", "") if self._account else ""

    def get(self) -> str:
        if self._account is None:
            raise ProviderError(f"Conta Microsoft nao autorizada. {_AUTH_HINT}")
        result = self._app.acquire_token_silent(SCOPES, account=self._account)
        if self._cache.has_state_changed:
            _save_cache(self._cache, self._path)
        if not result or "access_token" not in result:
            erro = (result or {}).get("error", "sem token")
            raise ProviderError(f"Falha ao renovar o acesso Microsoft ({erro}). {_AUTH_HINT}")
        return result["access_token"]


def _graph_error(response: httpx.Response) -> str:
    try:
        code = response.json().get("error", {}).get("code", "")
    except ValueError:
        code = ""
    return f"HTTP {response.status_code}" + (f" ({code})" if code else "")


def _parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00")[:32])
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


class MicrosoftProvider:
    name = "microsoft"

    def __init__(
        self,
        token: Callable[[], str],
        account: str,
        quarantine_label: str,
        client: httpx.Client | None = None,
    ) -> None:
        self._token = token
        self.account = account
        self._label = quarantine_label
        self._client = client or httpx.Client(timeout=TIMEOUT)
        self._folder_id: str | None = None

    @classmethod
    def from_cache(
        cls, client_id: str, tenant: str, cache_path: Path, quarantine_label: str
    ) -> "MicrosoftProvider":
        source = TokenSource(client_id, tenant, cache_path)
        return cls(source.get, source.account, quarantine_label)

    # --- HTTP ---

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        json: dict | None = None,
        headers: dict | None = None,
        ok: tuple[int, ...] = (),
    ) -> httpx.Response:
        if not url.startswith("http"):
            url = GRAPH + url
        refreshed = False
        retries = 0
        while True:
            hdrs = {"Authorization": f"Bearer {self._token()}", **(headers or {})}
            try:
                r = self._client.request(
                    method, url, params=params, json=json, headers=hdrs, timeout=TIMEOUT
                )
            except httpx.HTTPError as exc:
                raise ProviderError(
                    f"Falha de rede ao acessar o Microsoft Graph: {type(exc).__name__}"
                ) from exc
            if r.status_code in (429, 503) and retries < MAX_RETRIES:
                retries += 1
                try:
                    wait = float(r.headers.get("Retry-After", ""))
                except ValueError:
                    wait = 2.0 * retries
                _sleep(min(max(wait, 0.0), 60.0))
                continue
            if r.status_code == 401 and not refreshed:
                refreshed = True
                continue
            if r.is_success or r.status_code in ok:
                return r
            raise ProviderError(f"Microsoft Graph recusou a requisicao: {_graph_error(r)}")

    # --- leitura ---

    def fetch_new(self, since: datetime) -> list[EmailMessage]:
        start = (since.astimezone(timezone.utc) - OVERLAP).strftime("%Y-%m-%dT%H:%M:%SZ")
        params = {
            "$filter": f"receivedDateTime ge {start}",
            "$orderby": "receivedDateTime asc",
            "$top": str(PAGE_SIZE),
            "$select": _SELECT,
            # $expand com $select e valido na v1.0 para a colecao attachments
            "$expand": "attachments($select=name)",
        }
        headers = {"Prefer": 'outlook.body-content-type="html", IdType="ImmutableId"'}
        url: str | None = "/me/mailFolders/inbox/messages"
        messages: list[EmailMessage] = []
        while url and len(messages) < MAX_MESSAGES:
            r = self._request("GET", url, params=params, headers=headers)
            params = None  # nextLink ja traz a query completa
            data = r.json()
            for item in data.get("value", []):
                messages.append(self._build(item))
                if len(messages) >= MAX_MESSAGES:
                    break
            url = data.get("@odata.nextLink")
        return messages

    def _build(self, item: dict) -> EmailMessage:
        addr = (item.get("from") or {}).get("emailAddress") or {}
        sender = (addr.get("address") or "").strip().lower()
        name = addr.get("name") or ""
        reply = None
        if item.get("replyTo"):
            reply = (item["replyTo"][0].get("emailAddress") or {}).get("address") or None
            reply = reply.strip().lower() if reply else None

        body = item.get("body") or {}
        content = body.get("content") or ""
        if (body.get("contentType") or "").lower() == "html":
            text, links = html_to_text_and_links(content)
        else:
            text, links = content, links_from_text(content)

        from_domain = parse_address(sender)[1].rsplit("@", 1)[-1]
        # so o primeiro Authentication-Results (inserido pela borda da Microsoft)
        auth_headers = [
            h.get("value", "")
            for h in item.get("internetMessageHeaders") or []
            if (h.get("name") or "").lower() == "authentication-results"
        ][:1]
        authenticated, summary = (
            parse_auth_results(auth_headers, from_domain)
            if auth_headers
            else (False, "sem resultado de autenticacao")
        )

        return EmailMessage(
            id=item["id"],
            provider="microsoft",
            account=self.account,
            sender_address=sender,
            sender_name=name,
            reply_to=reply,
            subject=item.get("subject") or "",
            body_text=text,
            links=links,
            attachment_names=tuple(
                a["name"] for a in item.get("attachments") or [] if a.get("name")
            ),
            received_at=_parse_time(item["receivedDateTime"]),
            authenticated=authenticated,
            auth_summary=summary,
        )

    # --- quarentena ---

    _PREFER = {"Prefer": 'IdType="ImmutableId"'}

    def _ensure_category(self) -> None:
        r = self._request("GET", "/me/outlook/masterCategories", ok=(403,))
        if r.status_code == 403:
            return
        if any(c.get("displayName") == self._label for c in r.json().get("value", [])):
            return
        self._request(
            "POST",
            "/me/outlook/masterCategories",
            json={"displayName": self._label, "color": "preset0"},
            ok=(403, 409),
        )

    def _ensure_folder(self) -> str:
        if self._folder_id:
            return self._folder_id
        escaped = self._label.replace("'", "''")
        r = self._request(
            "GET",
            "/me/mailFolders",
            params={"$filter": f"displayName eq '{escaped}'", "$top": "10"},
        )
        for folder in r.json().get("value", []):
            if folder.get("displayName") == self._label:
                self._folder_id = folder["id"]
                return self._folder_id
        r = self._request("POST", "/me/mailFolders", json={"displayName": self._label})
        self._folder_id = r.json()["id"]
        return self._folder_id

    def quarantine(self, message: EmailMessage, verdict: Verdict) -> None:
        self._ensure_category()
        path = f"/me/messages/{message.id}"
        r = self._request("GET", path, params={"$select": "categories"}, headers=self._PREFER)
        categories = list(r.json().get("categories") or [])
        if self._label not in categories:
            categories.append(self._label)
            self._request(
                "PATCH", path, json={"categories": categories}, headers=self._PREFER
            )
        folder = self._ensure_folder()
        self._request(
            "POST", f"{path}/move", json={"destinationId": folder}, headers=self._PREFER
        )
