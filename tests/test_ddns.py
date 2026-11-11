"""Dynamic DNS through Azure DNS (the library's Keeper): this network's public IPv4 address asked of the name servers the
plugin names, each host's A record set read, and written (with its etag, its TTL and metadata kept) only where it differs
(every host on Update DNS now); only for hosts in the subscription's zones."""
from __future__ import annotations

import pytest

from conftest import HOME, settings_of
from plugin_platform_azure import PUBLIC_IPV4


def test_its_name_servers_are_named_by_the_plugin():
    assert PUBLIC_IPV4 == (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
                           ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))


def test_a_pass_writes_only_the_hosts_that_differ(made, env):
    env(settings_of(AZURE_DDNS_HOSTS="home.example.com, new.example.com, @.example.com, other.org"))
    p, fake = made()
    etag = fake.zones[("dns-rg", "example.com")][("home", "A")]["etag"]
    out = p.ddns_update(force=False)  # the zones read first (a refresh), then the pass
    assert [(h["host"], h["result"]) for h in out] == [
        ("home.example.com", "set (was 198.51.100.7)"), ("new.example.com", "made (was none)"), ("example.com", "set (was 20.1.2.3)")]
    puts = [r for r in fake.requests if r["method"] == "PUT"]
    assert [r["path"].rsplit("/", 2)[-2:] for r in puts] == [["A", "home"], ["A", "new"], ["A", "@"]]
    assert puts[0]["headers"]["If-Match"] == etag and puts[1]["headers"]["If-None-Match"] == "*"
    assert puts[0]["body"] == {"properties": {"TTL": 300, "ARecords": [{"ipv4Address": HOME}]}}
    assert puts[1]["body"] == {"properties": {"TTL": 300, "ARecords": [{"ipv4Address": HOME}]}}
    assert puts[2]["body"] == {"properties": {"TTL": 3600, "metadata": {"owner": "me"}, "ARecords": [{"ipv4Address": HOME}]}}
    st = p.status()
    assert "other.org is in none of the account's domains" in st["problem"]
    table = next(t for t in st["tables"] if t["title"] == "Dynamic DNS")
    assert [r[:2] for r in table["rows"]] == [["home.example.com", HOME], ["new.example.com", HOME], ["example.com", HOME]]
    calls = len(fake.requests)
    p.ddns_update(force=False)
    assert [r["method"] for r in fake.requests[calls:]] == ["GET", "GET", "GET"]  # current: read, nothing written
    p.ddns_update(force=True)
    assert [r["method"] for r in fake.requests[calls + 3:]] == ["GET", "PUT", "GET", "PUT", "GET", "PUT"]


def test_a_host_that_cannot_be_kept_says_why(made, env):
    env(settings_of(AZURE_DDNS_HOSTS="lb.example.com, www.example.com"))
    p, fake = made()
    out = p.ddns_update()
    assert out[0]["ok"] is False and "alias record set" in out[0]["result"]
    assert out[1]["ok"] is False and "is a CNAME" in out[1]["result"]
    assert not any(r["method"] == "PUT" for r in fake.requests)


def test_no_address_found_writes_nothing(made, env):
    env(settings_of(ddns=True))
    p, fake = made(public=(None, "neither OpenDNS nor Google answered with a public IPv4 address"))
    out = p.ddns_update()
    assert out[0]["ok"] is False and out[0]["result"].startswith("this network's address was not found: neither OpenDNS nor Google")
    assert not any(r["method"] == "PUT" for r in fake.requests)


def test_hosts_in_no_zone_of_the_subscription_are_refused(made, env):
    env(settings_of(AZURE_DDNS_HOSTS="home.example.org"))
    p, fake = made()
    with pytest.raises(ValueError, match="no Dynamic DNS host is in the subscription's Azure DNS zones"):
        p.ddns_update()
