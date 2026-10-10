from jev_phishing_detector.mailparse import (
    html_to_text_and_links,
    links_from_text,
    parse_address,
    parse_auth_results,
)


def test_html_extracts_text_and_links_and_skips_scripts():
    html = (
        "<html><head><style>p{}</style></head><body><p>Ola   mundo</p>"
        "<script>evil()</script>"
        '<a href="https://evil.example/login">https://banco.com.br</a>'
        '<a href="mailto:a@b.com">mail</a></body></html>'
    )
    text, links = html_to_text_and_links(html)
    assert "Ola mundo" in text
    assert "evil()" not in text and "p{}" not in text
    assert [(link.text, link.url) for link in links] == [
        ("https://banco.com.br", "https://evil.example/login")
    ]


def test_links_from_text_strips_trailing_punctuation():
    links = links_from_text("veja https://a.example/x. e http://b.example/y, ok")
    assert [link.url for link in links] == ["https://a.example/x", "http://b.example/y"]


def test_parse_address():
    assert parse_address('"Ana Silva" <Ana@Empresa.COM>') == ("Ana Silva", "ana@empresa.com")
    assert parse_address(None) == ("", "")


def test_auth_pass_aligned():
    ok, summary = parse_auth_results(
        ["mx.google.com; dkim=pass header.i=@empresa.com; spf=pass smtp.mailfrom=x@empresa.com; "
         "dmarc=pass (p=REJECT) header.from=empresa.com"],
        "empresa.com",
    )
    assert ok and summary == "spf=pass dkim=pass dmarc=pass"


def test_auth_dmarc_fail_or_missing_is_not_authenticated():
    assert not parse_auth_results(["mx; spf=pass; dkim=pass; dmarc=fail header.from=empresa.com"], "empresa.com")[0]
    # SPF/DKIM passam para o dominio do atacante; sem DMARC nao ha garantia sobre o From.
    assert not parse_auth_results(["mx; spf=pass smtp.mailfrom=evil.io; dkim=pass header.d=evil.io"], "empresa.com")[0]
    assert parse_auth_results([], "empresa.com") == (False, "sem resultado de autenticacao")


def test_auth_pass_for_other_domain_is_not_authenticated():
    assert not parse_auth_results(["mx; dmarc=pass header.from=evil.io"], "empresa.com")[0]
    assert not parse_auth_results(["mx; dmarc=pass header.from=notempresa.com"], "empresa.com")[0]
