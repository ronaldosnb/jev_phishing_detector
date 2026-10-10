import json
from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
import pytest

from jev_phishing_detector.models import ProviderError, Verdict
from jev_phishing_detector.providers import microsoft as ms
from jev_phishing_detector.providers.microsoft import MicrosoftProvider, TokenSource

LABEL = "Suspeita de Phishing"
VERDICT = Verdict(True, 0.9, "phishing")
SINCE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    waits = []
    monkeypatch.setattr(ms, "_sleep", waits.append)
    return waits


def make(handler, token=lambda: "tok"):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return MicrosoftProvider(token, "me@outlook.com", LABEL, client=client)


def msg(id="m1", html=True, headers=None, **extra):
    base = {
        "id": id,
        "subject": "Oi",
        "from": {"emailAddress": {"name": "Banco", "address": "Aviso@Banco.com"}},
        "receivedDateTime": "2026-01-01T12:30:00Z",
        "body": {"contentType": "html", "content": '<p>Veja <a href="https://x.com/a">aqui</a></p>'},
        "internetMessageHeaders": headers or [],
    }
    if not html:
        base["body"] = {"contentType": "text", "content": "acesse https://y.com/b."}
    base.update(extra)
    return base


def auth(value):
    return {"name": "Authentication-Results", "value": value}


def page(items, next_link=None):
    d = {"value": items}
    if next_link:
        d["@odata.nextLink"] = next_link
    return httpx.Response(200, json=d)


def test_fetch_request_shape():
    seen = []

    def h(req):
        seen.append(req)
        return page([])

    make(h).fetch_new(SINCE)
    req = seen[0]
    assert req.url.path == "/v1.0/me/mailFolders/inbox/messages"
    q = parse_qs(req.url.query.decode())
    assert q["$filter"] == ["receivedDateTime ge 2026-01-01T11:59:00Z"]
    assert q["$orderby"] == ["receivedDateTime asc"]
    assert q["$top"] == ["50"]
    assert "internetMessageHeaders" in q["$select"][0]
    assert q["$expand"] == ["attachments($select=name)"]
    assert req.headers["Authorization"] == "Bearer tok"
    assert 'IdType="ImmutableId"' in req.headers["Prefer"]
    assert 'outlook.body-content-type="html"' in req.headers["Prefer"]


def test_pagination():
    calls = []

    def h(req):
        calls.append(str(req.url))
        if len(calls) == 1:
            return page([msg("a")], "https://graph.microsoft.com/v1.0/next?page=2")
        return page([msg("b")])

    out = make(h).fetch_new(SINCE)
    assert [m.id for m in out] == ["a", "b"]
    assert calls[1] == "https://graph.microsoft.com/v1.0/next?page=2"


def test_html_body_and_fields():
    m = make(lambda r: page([msg(replyTo=[{"emailAddress": {"address": "R@x.com"}}])])).fetch_new(SINCE)[0]
    assert m.sender_address == "aviso@banco.com"
    assert m.sender_name == "Banco"
    assert m.reply_to == "r@x.com"
    assert m.provider == "microsoft" and m.account == "me@outlook.com"
    assert "Veja aqui" in m.body_text
    assert [(l.text, l.url) for l in m.links] == [("aqui", "https://x.com/a")]
    assert m.received_at == datetime(2026, 1, 1, 12, 30, tzinfo=timezone.utc)


def test_text_body_links():
    m = make(lambda r: page([msg(html=False)])).fetch_new(SINCE)[0]
    assert m.body_text.startswith("acesse")
    assert [l.url for l in m.links] == ["https://y.com/b"]
    assert m.reply_to is None


def test_attachments():
    m = make(lambda r: page([msg(attachments=[{"name": "a.pdf"}, {"name": "b.exe"}])])).fetch_new(SINCE)[0]
    assert m.attachment_names == ("a.pdf", "b.exe")


def test_auth_first_header_pass():
    h = [auth("spf=pass; dkim=pass; dmarc=pass header.from=banco.com; compauth=pass")]
    m = make(lambda r: page([msg(headers=h)])).fetch_new(SINCE)[0]
    assert m.authenticated is True
    assert "dmarc=pass" in m.auth_summary


def test_auth_later_injected_header_ignored():
    h = [auth("dmarc=fail header.from=banco.com"), auth("dmarc=pass header.from=banco.com")]
    m = make(lambda r: page([msg(headers=h)])).fetch_new(SINCE)[0]
    assert m.authenticated is False


def test_auth_no_header():
    m = make(lambda r: page([msg(headers=[{"name": "Subject", "value": "x"}])])).fetch_new(SINCE)[0]
    assert m.authenticated is False


class Graph:
    def __init__(self, categories=None, folders=None, msg_cats=None, master_status=200):
        self.categories = categories if categories is not None else []
        self.folders = folders if folders is not None else []
        self.msg_cats = msg_cats or []
        self.master_status = master_status
        self.log = []

    def __call__(self, req):
        p, m = req.url.path.removeprefix("/v1.0"), req.method
        body = json.loads(req.content) if req.content else None
        self.log.append((m, p, body))
        if p == "/me/outlook/masterCategories":
            if self.master_status != 200:
                return httpx.Response(self.master_status, json={"error": {"code": "ErrorAccessDenied"}})
            if m == "GET":
                return httpx.Response(200, json={"value": [{"displayName": c} for c in self.categories]})
            return httpx.Response(201, json=body)
        if p == "/me/mailFolders":
            if m == "GET":
                return httpx.Response(200, json={"value": self.folders})
            return httpx.Response(201, json={"id": "newfolder", "displayName": body["displayName"]})
        if p == "/me/messages/m1" and m == "GET":
            return httpx.Response(200, json={"categories": self.msg_cats})
        if p == "/me/messages/m1" and m == "PATCH":
            return httpx.Response(200, json={})
        if p == "/me/messages/m1/move":
            return httpx.Response(201, json={"id": "m1"})
        return httpx.Response(404)

    def calls(self, method, path):
        return [b for (m, p, b) in self.log if m == method and p == path]


def message():
    return make(lambda r: page([msg()])).fetch_new(SINCE)[0]


def test_quarantine_existing():
    g = Graph(categories=[LABEL], folders=[{"id": "f1", "displayName": LABEL}])
    make(g).quarantine(message(), VERDICT)
    assert not g.calls("POST", "/me/outlook/masterCategories")
    assert not g.calls("POST", "/me/mailFolders")
    assert g.calls("PATCH", "/me/messages/m1") == [{"categories": [LABEL]}]
    assert g.calls("POST", "/me/messages/m1/move") == [{"destinationId": "f1"}]
    order = [(m, p) for m, p, _ in g.log]
    assert order.index(("PATCH", "/me/messages/m1")) < order.index(("POST", "/me/messages/m1/move"))


def test_quarantine_creates_both():
    g = Graph()
    make(g).quarantine(message(), VERDICT)
    assert g.calls("POST", "/me/outlook/masterCategories") == [{"displayName": LABEL, "color": "preset0"}]
    assert g.calls("POST", "/me/mailFolders") == [{"displayName": LABEL}]
    assert g.calls("POST", "/me/messages/m1/move") == [{"destinationId": "newfolder"}]


def test_folder_filter_escapes_quotes():
    seen = []

    def h(req):
        if req.url.path.endswith("/mailFolders") and req.method == "GET":
            seen.append(parse_qs(req.url.query.decode())["$filter"][0])
        return Graph()(req)

    p = make(h)
    p._label = "O'Brien"
    p._ensure_folder()
    assert seen == ["displayName eq 'O''Brien'"]


def test_categories_merged_no_duplicates():
    g = Graph(categories=[LABEL], folders=[{"id": "f1", "displayName": LABEL}], msg_cats=["Azul", LABEL])
    make(g).quarantine(message(), VERDICT)
    assert not g.calls("PATCH", "/me/messages/m1")
    g2 = Graph(categories=[LABEL], folders=[{"id": "f1", "displayName": LABEL}], msg_cats=["Azul"])
    make(g2).quarantine(message(), VERDICT)
    assert g2.calls("PATCH", "/me/messages/m1") == [{"categories": ["Azul", LABEL]}]


def test_master_categories_403_tolerated():
    g = Graph(master_status=403, folders=[{"id": "f1", "displayName": LABEL}])
    make(g).quarantine(message(), VERDICT)
    assert g.calls("PATCH", "/me/messages/m1") == [{"categories": [LABEL]}]
    assert g.calls("POST", "/me/messages/m1/move")


def test_retry_after_429(no_sleep):
    n = []

    def h(req):
        n.append(1)
        if len(n) == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        return page([msg()])

    assert len(make(h).fetch_new(SINCE)) == 1
    assert no_sleep == [3.0]


def test_401_refreshes_token():
    tokens = iter(["old", "new"])
    auths = []

    def h(req):
        auths.append(req.headers["Authorization"])
        if len(auths) == 1:
            return httpx.Response(401, json={"error": {"code": "InvalidAuthenticationToken"}})
        return page([])

    make(h, token=lambda: next(tokens)).fetch_new(SINCE)
    assert auths == ["Bearer old", "Bearer new"]


def test_500_provider_error():
    def h(req):
        return httpx.Response(500, json={"error": {"code": "boom"}})

    with pytest.raises(ProviderError, match="500.*boom"):
        make(h).fetch_new(SINCE)


def test_persistent_401_is_error():
    with pytest.raises(ProviderError, match="401"):
        make(lambda r: httpx.Response(401)).fetch_new(SINCE)


def test_token_source_no_account(tmp_path):
    ts = TokenSource("cid", "common", tmp_path / "cache.json")
    assert ts.account == ""
    with pytest.raises(ProviderError, match="jev-phishing auth microsoft"):
        ts.get()


def test_token_source_refresh_failure(tmp_path, monkeypatch):
    class FakeApp:
        def __init__(self, *a, **k):
            pass

        def get_accounts(self):
            return [{"username": "u@x.com"}]

        def acquire_token_silent(self, scopes, account):
            return {"error": "invalid_grant"}

    monkeypatch.setattr(ms.msal, "PublicClientApplication", FakeApp)
    ts = TokenSource("cid", "common", tmp_path / "c.json")
    assert ts.account == "u@x.com"
    with pytest.raises(ProviderError, match="invalid_grant"):
        ts.get()


def test_token_source_saves_cache_0600(tmp_path, monkeypatch):
    path = tmp_path / "c.json"

    class FakeApp:
        def __init__(self, client_id, authority, token_cache):
            self.cache = token_cache

        def get_accounts(self):
            return [{"username": "u@x.com"}]

        def acquire_token_silent(self, scopes, account):
            self.cache.add({"client_id": "cid", "scope": scopes, "token_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                            "response": {"access_token": "AT", "expires_in": 3600, "refresh_token": "RT", "id_token_claims": {}}})
            return {"access_token": "AT"}

    monkeypatch.setattr(ms.msal, "PublicClientApplication", FakeApp)
    ts = TokenSource("cid", "common", path)
    assert ts.get() == "AT"
    assert path.exists() and oct(path.stat().st_mode & 0o777) == "0o600"


def test_authorize_device_flow(tmp_path, monkeypatch):
    class FakeApp:
        def __init__(self, client_id, authority, token_cache):
            self.cache = token_cache

        def initiate_device_flow(self, scopes):
            return {"user_code": "ABC", "message": "va em https://microsoft.com/devicelogin"}

        def acquire_token_by_device_flow(self, flow):
            return {"access_token": "AT", "id_token_claims": {"preferred_username": "me@outlook.com"}}

    monkeypatch.setattr(ms.msal, "PublicClientApplication", FakeApp)
    shown = []
    path = tmp_path / "sub" / "c.json"
    assert ms.authorize("cid", "common", path, shown.append) == "me@outlook.com"
    assert shown == ["va em https://microsoft.com/devicelogin"]
    assert oct(path.stat().st_mode & 0o777) == "0o600"
