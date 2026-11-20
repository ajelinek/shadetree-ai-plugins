"""Tests for the shared _domain helpers."""

import importlib

import pytest

_domain = importlib.import_module("shadetree_ai_plugins_email_domain_reputation._domain")


@pytest.mark.parametrize("host,org", [
    ("mail.shop.com.pl", "shop.com.pl"), ("a.b.co.th", "b.co.th"),
    ("x.firm.org.br", "firm.org.br"), ("m.co.ke", "m.co.ke"),
    ("a.b.com.ru", "b.com.ru"), ("a.b.gob.mx", "b.gob.mx"),
    ("mail.example.co.uk", "example.co.uk"), ("a.b.example.com", "example.com"),
])
def test_org_domain_multi_part_suffixes(host, org):
    assert _domain.org_domain(host) == org


def test_org_domain_is_approximate_for_cctlds_only():
    assert _domain.org_domain_is_approximate("example.io")
    assert _domain.org_domain_is_approximate("user@shop.example.co.uk")
    assert not _domain.org_domain_is_approximate("mail.example.com")
    assert not _domain.org_domain_is_approximate("example.online")


def test_aligned_modes():
    assert _domain.aligned("mail.example.com.pl", "example.com.pl", "r")
    assert not _domain.aligned("mail.example.com.pl", "example.com.pl", "s")
    assert not _domain.aligned("a.com.pl", "b.com.pl", "r")
    assert _domain.aligned("Example.COM.", "user@example.com", "s")
    assert not _domain.aligned("", "example.com")


def test_bare_domain_is_lenient_and_never_raises():
    assert _domain.bare_domain(" User@Example.COM. ") == "example.com"
    assert _domain.bare_domain(None) == ""
    assert _domain.bare_domain("not a domain") == "not a domain"


def test_is_valid_domain():
    assert _domain.is_valid_domain("mail.example.co.uk")
    assert not _domain.is_valid_domain("not a domain")
    assert not _domain.is_valid_domain("nodots")


@pytest.mark.parametrize("value", ["a@@example.com", "x@-example.com", "x@y..com", "x@localhost",
    "https://example.com", "x@example.com\nInjected", ".x@example.com", "x..y@example.com"])
def test_invalid_addresses_rejected(value):
    with pytest.raises(ValueError):
        _domain.normalize_email(value)


@pytest.mark.parametrize("value", ["", "localhost", "192.0.2.1", "example.com/path",
                                   "exa mple.com", "-bad.example.com"])
def test_invalid_domains_rejected(value):
    with pytest.raises(ValueError):
        _domain.normalize_domain(value)


def test_address_normalization_preserves_local_part():
    assert _domain.normalize_email("Person+tag@EXAMPLE.COM") == "Person+tag@example.com"
    assert _domain.domain_from_arg("Person@example.com") == "example.com"
    assert _domain.domain_from_arg("Adam@Shadetreeit.biz") == "shadetreeit.biz"
    assert _domain.domain_from_arg("bücher.example") == "xn--bcher-kva.example"


@pytest.mark.parametrize("selectors", [["bad;selector"], ["x."], ["a" * 64], ["x"] * 21, [""]])
def test_invalid_or_excessive_selectors_rejected(selectors):
    with pytest.raises(ValueError):
        _domain.validate_selectors(selectors)


def test_selectors_are_lowercased_and_deduplicated():
    assert _domain.validate_selectors(["S2024", "s2024", "mail.k1"]) == ["s2024", "mail.k1"]
    assert _domain.validate_selectors(None) == []
