from datetime import datetime, timedelta, timezone

import pytest

from jev_phishing_detector.models import AnalysisError, EmailMessage, ProviderError, Verdict
from jev_phishing_detector.pipeline import Pipeline
from jev_phishing_detector.storage import StateStore, TrustStore


def make_message(id="m1", sender="ana@empresa.com", authenticated=True):
    return EmailMessage(
        id=id, provider="google", account="eu@gmail.com", sender_address=sender,
        sender_name="Ana", reply_to=None, subject=f"assunto {id}", body_text="corpo",
        links=(), attachment_names=(), received_at=datetime.now(timezone.utc),
        authenticated=authenticated, auth_summary="dmarc=pass" if authenticated else "dmarc=fail",
    )


class FakeProvider:
    name = "google"
    account = "eu@gmail.com"

    def __init__(self, messages, fail_quarantine=False):
        self.messages = messages
        self.fail_quarantine = fail_quarantine
        self.quarantined = []
        self.since = []

    def fetch_new(self, since):
        self.since.append(since)
        return list(self.messages)

    def quarantine(self, message, verdict):
        if self.fail_quarantine:
            raise ProviderError("boom")
        self.quarantined.append(message.id)


class FakeAnalyzer:
    def __init__(self, probability=0.1, error=False):
        self.probability = probability
        self.error = error
        self.calls = []

    def analyze(self, message):
        self.calls.append(message.id)
        if self.error:
            raise AnalysisError("jev fora do ar")
        return Verdict(self.probability >= 0.7, self.probability, "outro", ("motivo",))


@pytest.fixture
def stores(tmp_path):
    db = tmp_path / "db.sqlite3"
    return TrustStore(db), StateStore(db)


def build(stores, provider, analyzer, **kwargs):
    trust, state = stores
    return Pipeline([provider], analyzer, trust, state, **kwargs)


def test_trusted_authenticated_sender_skips_jev(stores):
    stores[0].add("empresa.com")
    provider, analyzer = FakeProvider([make_message()]), FakeAnalyzer(0.99)
    report = build(stores, provider, analyzer).run_once()
    assert analyzer.calls == [] and provider.quarantined == []
    assert (report.trusted, report.fetched) == (1, 1)


def test_trusted_but_unauthenticated_sender_is_still_analyzed(stores):
    stores[0].add("empresa.com")
    provider, analyzer = FakeProvider([make_message(authenticated=False)]), FakeAnalyzer(0.95)
    report = build(stores, provider, analyzer).run_once()
    assert analyzer.calls == ["m1"] and provider.quarantined == ["m1"]
    assert report.trusted == 0 and report.quarantined == 1


def test_clean_message_is_left_alone_and_not_reanalyzed(stores):
    provider, analyzer = FakeProvider([make_message(sender="x@fora.com")]), FakeAnalyzer(0.1)
    pipeline = build(stores, provider, analyzer)
    assert pipeline.run_once().clean == 1
    assert pipeline.run_once().fetched == 0
    assert analyzer.calls == ["m1"] and provider.quarantined == []


def test_analysis_failure_leaves_email_untouched_and_retries(stores):
    provider, analyzer = FakeProvider([make_message(sender="x@fora.com")]), FakeAnalyzer(error=True)
    pipeline = build(stores, provider, analyzer)
    report = pipeline.run_once()
    assert report.errors == 1 and provider.quarantined == []
    analyzer.error, analyzer.probability = False, 0.9
    assert pipeline.run_once().quarantined == 1
    # O cursor nao avancou apos a falha: a segunda busca cobre a mesma janela.
    assert provider.since[1] == provider.since[0]


def test_quarantine_failure_is_retried(stores):
    provider = FakeProvider([make_message(sender="x@fora.com")], fail_quarantine=True)
    pipeline = build(stores, provider, FakeAnalyzer(0.9))
    assert pipeline.run_once().errors == 1
    provider.fail_quarantine = False
    pipeline.run_once()
    assert provider.quarantined == ["m1"]


def test_cursor_advances_after_clean_cycle(stores):
    provider = FakeProvider([make_message(sender="x@fora.com")])
    pipeline = build(stores, provider, FakeAnalyzer(0.1), first_run_lookback=timedelta(hours=2))
    before = datetime.now(timezone.utc)
    pipeline.run_once()
    pipeline.run_once()
    assert before - provider.since[0] >= timedelta(hours=2) - timedelta(seconds=5)
    assert provider.since[1] >= before


def test_dry_run_changes_nothing(stores):
    provider = FakeProvider([make_message(sender="x@fora.com")])
    pipeline = build(stores, provider, FakeAnalyzer(0.9), dry_run=True)
    assert pipeline.run_once().quarantined == 1
    assert provider.quarantined == []
    assert stores[1].stats() == {} and stores[1].get_cursor("google", "eu@gmail.com") is None


def test_fetch_failure_is_reported(stores):
    class Broken(FakeProvider):
        def fetch_new(self, since):
            raise ProviderError("sem rede")

    assert build(stores, Broken([]), FakeAnalyzer()).run_once().errors == 1
