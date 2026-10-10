from datetime import UTC, datetime, timedelta, timezone

import pytest

from jev_phishing_detector.storage import StateStore, TrustStore


@pytest.fixture
def trust(tmp_path):
    return TrustStore(tmp_path / "db.sqlite3")


def test_normalizacao(trust):
    e = trust.add("  Pessoa@Empresa.COM ")
    assert (e.value, e.kind) == ("pessoa@empresa.com", "address")
    assert e.added_at.tzinfo is not None
    assert trust.add("@Empresa.com").value == "empresa.com"
    assert trust.add("empresa.com").kind == "domain"
    assert len(trust.list()) == 2


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "a b@x.com", "a@@x.com", "a@b@x.com", "localhost", "a@localhost",
     "*.empresa.com", "a*@empresa.com", "@", "a@x..com"],
)
def test_validacao(trust, bad):
    with pytest.raises(ValueError):
        trust.add(bad)
    assert trust.list() == []


def test_duplicado_atualiza_nota(trust):
    first = trust.add("empresa.com", "a")
    second = trust.add("EMPRESA.com", "b")
    assert second.note == "b"
    assert second.added_at == first.added_at
    assert [(e.value, e.note) for e in trust.list()] == [("empresa.com", "b")]


def test_remove(trust):
    trust.add("empresa.com")
    assert trust.remove("@Empresa.com") is True
    assert trust.remove("empresa.com") is False
    assert trust.remove("invalido") is False


def test_lista_ordenada(trust):
    trust.add("z.com")
    trust.add("b@x.com")
    trust.add("a.com")
    assert [e.value for e in trust.list()] == ["b@x.com", "a.com", "z.com"]


def test_is_trusted(trust):
    trust.add("empresa.com")
    trust.add("fulano@outra.com")
    assert trust.is_trusted("a@empresa.com")
    assert trust.is_trusted("A@Mail.Empresa.com")
    assert trust.is_trusted("fulano@outra.com")
    assert not trust.is_trusted("beltrano@outra.com")
    assert not trust.is_trusted("a@notempresa.com")
    assert not trust.is_trusted("a@empresa.com.evil.io")
    assert not trust.is_trusted("a@com")
    assert not trust.is_trusted("sem-arroba")
    assert not trust.is_trusted("")
    assert not trust.is_trusted("a@@empresa.com")


def test_persistencia(tmp_path):
    path = tmp_path / "db.sqlite3"
    TrustStore(path).add("empresa.com", "n")
    other = TrustStore(path)
    assert other.is_trusted("x@empresa.com")
    assert other.list()[0].note == "n"


def test_cursor(tmp_path):
    path = tmp_path / "db.sqlite3"
    s = StateStore(path)
    assert s.get_cursor("google", "a@x.com") is None
    when = datetime(2026, 1, 2, 12, 0, tzinfo=timezone(timedelta(hours=-3)))
    s.set_cursor("google", "a@x.com", when)
    got = StateStore(path).get_cursor("google", "a@x.com")
    assert got == when
    assert got.utcoffset() == timedelta(0)
    assert s.get_cursor("microsoft", "a@x.com") is None
    s.set_cursor("google", "a@x.com", datetime(2026, 2, 1, tzinfo=UTC))
    assert s.get_cursor("google", "a@x.com") == datetime(2026, 2, 1, tzinfo=UTC)


def test_processed_idempotente_e_stats(tmp_path):
    s = StateStore(tmp_path / "db.sqlite3")
    assert not s.is_processed("google", "a@x.com", "1")
    s.mark_processed("google", "a@x.com", "1", "trusted")
    s.mark_processed("google", "a@x.com", "1", "trusted")
    s.mark_processed("google", "a@x.com", "2", "quarantined", 0.9)
    s.mark_processed("microsoft", "a@x.com", "1", "clean", 0.1)
    assert s.is_processed("google", "a@x.com", "1")
    assert not s.is_processed("microsoft", "a@x.com", "2")
    assert s.stats() == {"trusted": 1, "quarantined": 1, "clean": 1}
    s.mark_processed("google", "a@x.com", "1", "clean", 0.2)
    assert s.stats() == {"quarantined": 1, "clean": 2}


def test_endereco_com_underscore_e_aceito(tmp_path):
    store = TrustStore(tmp_path / "db.sqlite3")
    store.add("joao_silva@empresa.com")
    assert store.is_trusted("joao_silva@empresa.com")
    assert not store.is_trusted("joaoXsilva@empresa.com")
