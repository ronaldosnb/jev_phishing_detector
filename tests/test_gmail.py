import base64
from datetime import UTC, datetime

import httplib2
import pytest
from googleapiclient.errors import HttpError

from jev_phishing_detector.models import ProviderError, Verdict
from jev_phishing_detector.providers.gmail import GmailProvider, load_credentials

SINCE = datetime(2026, 1, 1, tzinfo=UTC)
VERDICT = Verdict(suspicious=True, probability=0.9, category="phishing")


def b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def http_error(status: int) -> HttpError:
    return HttpError(httplib2.Response({"status": status}), b"{}")


class Call:
    def __init__(self, fn):
        self.fn = fn

    def execute(self):
        result = self.fn()
        if isinstance(result, Exception):
            raise result
        return result


class FakeMessages:
    def __init__(self):
        self.pages: list = [{"messages": []}]
        self.raw: dict = {}
        self.calls: list[tuple[str, dict]] = []

    def list(self, **kw):
        self.calls.append(("list", kw))
        return Call(lambda: self.pages[int(kw.get("pageToken") or 0)])

    def get(self, **kw):
        self.calls.append(("get", kw))
        return Call(lambda: self.raw[kw["id"]])

    def modify(self, **kw):
        self.calls.append(("modify", kw))
        return Call(lambda: {})


class FakeLabels:
    def __init__(self):
        self.items: list[dict] = []
        self.calls: list[tuple[str, dict]] = []

    def list(self, **kw):
        self.calls.append(("list", kw))
        return Call(lambda: {"labels": list(self.items)})

    def create(self, **kw):
        self.calls.append(("create", kw))

        def run():
            label = {"id": "Label_9", "name": kw["body"]["name"]}
            self.items.append(label)
            return label

        return Call(run)


class FakeService:
    def __init__(self):
        self.msgs = FakeMessages()
        self.lbls = FakeLabels()

    def users(self):
        return self

    def messages(self):
        return self.msgs

    def labels(self):
        return self.lbls


def raw_message(mid="m1", payload=None, headers=None, internal="1767225600000"):
    base = [
        {"name": "From", "value": "Banco X <Aviso@Banco.com>"},
        {"name": "Reply-To", "value": "outro@evil.com"},
        {"name": "Subject", "value": "Ola"},
    ]
    payload = dict(payload or {"mimeType": "text/plain", "body": {"data": b64("oi")}})
    payload["headers"] = base + (headers or [])
    return {"id": mid, "internalDate": internal, "payload": payload}


def provider(service=None):
    service = service or FakeService()
    return service, GmailProvider(service, "me@gmail.com", "Phishing")


def fetch_one(raw):
    svc, prov = provider()
    svc.msgs.pages = [{"messages": [{"id": raw["id"]}]}]
    svc.msgs.raw = {raw["id"]: raw}
    return prov.fetch_new(SINCE)[0]


def test_query_and_pagination():
    svc, prov = provider()
    svc.msgs.pages = [
        {"messages": [{"id": "a"}], "nextPageToken": "1"},
        {"messages": [{"id": "b"}]},
    ]
    svc.msgs.raw = {"a": raw_message("a", internal="2000"), "b": raw_message("b", internal="1000")}
    result = prov.fetch_new(SINCE)
    lists = [kw for name, kw in svc.msgs.calls if name == "list"]
    assert lists[0]["q"] == f"in:inbox after:{int(SINCE.timestamp()) - 60}"
    assert lists[1]["pageToken"] == "1"
    assert [m.id for m in result] == ["b", "a"]  # mais antiga primeiro
    gets = [kw for name, kw in svc.msgs.calls if name == "get"]
    assert all(kw["format"] == "full" for kw in gets)


def test_basic_fields():
    msg = fetch_one(raw_message())
    assert msg.provider == "google"
    assert msg.account == "me@gmail.com"
    assert msg.sender_address == "aviso@banco.com"
    assert msg.sender_name == "Banco X"
    assert msg.reply_to == "outro@evil.com"
    assert msg.subject == "Ola"
    assert msg.received_at == datetime(2026, 1, 1, tzinfo=UTC)
    assert msg.body_text == "oi"


def test_html_only_with_links():
    html = '<p>Clique <a href="https://evil.com/x">aqui</a></p>'
    msg = fetch_one(raw_message(payload={"mimeType": "text/html", "body": {"data": b64(html)}}))
    assert "Clique aqui" in msg.body_text
    assert [(link.text, link.url) for link in msg.links] == [("aqui", "https://evil.com/x")]


def test_plain_only_links():
    text = "veja https://evil.com/a, ok"
    msg = fetch_one(raw_message(payload={"mimeType": "text/plain", "body": {"data": b64(text)}}))
    assert msg.body_text == text
    assert [link.url for link in msg.links] == ["https://evil.com/a"]


def test_multipart_nested_with_attachment():
    payload = {
        "mimeType": "multipart/mixed",
        "body": {},
        "parts": [
            {
                "mimeType": "multipart/alternative",
                "body": {},
                "parts": [
                    {"mimeType": "text/plain", "body": {"data": b64("texto simples")}},
                    {"mimeType": "text/html", "body": {"data": b64("<p>versao <b>html</b></p>")}},
                ],
            },
            {"mimeType": "application/pdf", "filename": "fatura.pdf", "body": {"attachmentId": "x"}},
        ],
    }
    msg = fetch_one(raw_message(payload=payload))
    assert msg.body_text == "versao html"
    assert msg.attachment_names == ("fatura.pdf",)


@pytest.mark.parametrize("text", ["a", "ab", "abc", "abcd", "ação"])
def test_base64url_without_padding(text):
    msg = fetch_one(
        raw_message(payload={"mimeType": "text/plain", "body": {"data": b64(text)}})
    )
    assert msg.body_text == text


def test_bad_charset_does_not_fail():
    bad = base64.urlsafe_b64encode(b"ol\xe1 mundo").decode().rstrip("=")
    msg = fetch_one(raw_message(payload={"mimeType": "text/plain", "body": {"data": bad}}))
    assert "mundo" in msg.body_text


def auth(value):
    return {"name": "Authentication-Results", "value": value}


GOOD = "mx.google.com;\n spf=pass smtp.mailfrom=banco.com;\n dmarc=pass header.from=banco.com"


def test_authenticated_with_google_header():
    msg = fetch_one(raw_message(headers=[auth(GOOD)]))
    assert msg.authenticated is True
    assert "dmarc=pass" in msg.auth_summary


def test_spoofed_header_ignored():
    spoof = "evil.example; dmarc=pass header.from=banco.com"
    msg = fetch_one(raw_message(headers=[auth(spoof)]))
    assert msg.authenticated is False


def test_spoofed_pass_does_not_override_google_fail():
    spoof = "evil.example; dmarc=pass header.from=banco.com"
    fail = "mx.google.com; dmarc=fail header.from=banco.com"
    msg = fetch_one(raw_message(headers=[auth(spoof), auth(fail)]))
    assert msg.authenticated is False
    assert "dmarc=fail" in msg.auth_summary


def test_dmarc_fail():
    msg = fetch_one(raw_message(headers=[auth("mx.google.com; dmarc=fail header.from=banco.com")]))
    assert msg.authenticated is False


def test_no_auth_header():
    assert fetch_one(raw_message()).authenticated is False


def test_get_404_is_skipped():
    svc, prov = provider()
    svc.msgs.pages = [{"messages": [{"id": "gone"}, {"id": "ok"}]}]
    svc.msgs.raw = {"gone": http_error(404), "ok": raw_message("ok")}
    assert [m.id for m in prov.fetch_new(SINCE)] == ["ok"]


def test_http_error_wrapped():
    svc, prov = provider()
    svc.msgs.pages = [http_error(500)]
    with pytest.raises(ProviderError, match="500"):
        prov.fetch_new(SINCE)


def test_get_non_404_wrapped():
    svc, prov = provider()
    svc.msgs.pages = [{"messages": [{"id": "x"}]}]
    svc.msgs.raw = {"x": http_error(403)}
    with pytest.raises(ProviderError, match="403"):
        prov.fetch_new(SINCE)


def quarantine(svc, prov):
    msg = fetch_one_with(svc, prov)
    prov.quarantine(msg, VERDICT)
    return msg


def fetch_one_with(svc, prov):
    svc.msgs.pages = [{"messages": [{"id": "m1"}]}]
    svc.msgs.raw = {"m1": raw_message()}
    return prov.fetch_new(SINCE)[0]


def test_quarantine_creates_label_when_missing():
    svc, prov = provider()
    quarantine(svc, prov)
    creates = [kw for name, kw in svc.lbls.calls if name == "create"]
    assert len(creates) == 1
    body = creates[0]["body"]
    assert body["name"] == "Phishing"
    assert body["labelListVisibility"] == "labelShow"
    assert body["messageListVisibility"] == "show"
    assert body["color"] == {"backgroundColor": "#cc3a21", "textColor": "#ffffff"}
    modify = [kw for name, kw in svc.msgs.calls if name == "modify"][0]
    assert modify["id"] == "m1"
    assert modify["body"] == {"addLabelIds": ["Label_9"], "removeLabelIds": ["INBOX"]}


def test_quarantine_reuses_existing_label_and_caches():
    svc, prov = provider()
    svc.lbls.items = [{"id": "Label_1", "name": "Outro"}, {"id": "Label_7", "name": "Phishing"}]
    msg = quarantine(svc, prov)
    prov.quarantine(msg, VERDICT)  # idempotente
    assert not [c for c in svc.lbls.calls if c[0] == "create"]
    assert len([c for c in svc.lbls.calls if c[0] == "list"]) == 1
    modifies = [kw for name, kw in svc.msgs.calls if name == "modify"]
    assert len(modifies) == 2
    assert all(m["body"] == {"addLabelIds": ["Label_7"], "removeLabelIds": ["INBOX"]} for m in modifies)


def test_quarantine_http_error_wrapped():
    svc, prov = provider()
    svc.lbls.items = [{"id": "L", "name": "Phishing"}]
    msg = fetch_one_with(svc, prov)
    svc.msgs.modify = lambda **kw: Call(lambda: http_error(403))
    with pytest.raises(ProviderError, match="403"):
        prov.quarantine(msg, VERDICT)


def test_load_credentials_missing_token(tmp_path):
    with pytest.raises(ProviderError, match="jev-phishing auth google"):
        load_credentials(tmp_path / "nao_existe.json")
