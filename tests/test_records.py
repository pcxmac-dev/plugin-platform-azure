"""Azure DNS's record sets: read from Azure's answers, a record's value in a zone file's words, and the plans a change is
made of (what is kept, what is replaced, what is refused before anything is sent)."""
from __future__ import annotations

import pytest

from plugin_platform_azure import records as recs
from plugin_platform_azure.records import Refusal


def rs(name, rtype, field, records, ttl=3600, etag="e1", target=None, metadata=None):
    props = {"TTL": ttl, field: records, "metadata": metadata or {}}
    if target:
        props["targetResource"] = {"id": target}
    return recs.parse("example.com", "dns-rg", {"name": name, "type": f"Microsoft.Network/dnszones/{rtype}", "etag": etag,
                                                "properties": props})


def test_record_sets_are_read_from_azures_answers():
    a = rs("@", "A", "ARecords", [{"ipv4Address": "20.1.2.3"}, {"ipv4Address": "20.1.2.4"}], metadata={"k": "v"})
    assert (a.name, a.type, a.ttl, a.values, a.metadata, a.etag) == ("@", "A", 3600, ["20.1.2.3", "20.1.2.4"], {"k": "v"}, "e1")
    cname = rs("www", "CNAME", "CNAMERecord", {"cname": "web.example.net"})
    assert cname.values == ["web.example.net"] and cname.records == [{"cname": "web.example.net"}]
    txt = rs("@", "TXT", "TXTRecords", [{"value": ["a" * 255, "b"]}])
    assert txt.values == ["a" * 255 + "b"]
    assert rs("@", "MX", "MXRecords", [{"preference": 10, "exchange": "mx.example.com"}]).values == ["10 mx.example.com"]
    assert rs("_s._tcp", "SRV", "SRVRecords", [{"priority": 1, "weight": 2, "port": 3, "target": "t.example.com"}]).values == ["1 2 3 t.example.com"]
    assert rs("@", "CAA", "caaRecords", [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}]).values == ["0 issue letsencrypt.org"]
    assert rs("@", "SOA", "SOARecord", {"host": "ns1.", "email": "h.", "serialNumber": 1}).own.startswith("the zone's own SOA")
    assert rs("@", "NS", "NSRecords", [{"nsdname": "ns1."}]).unwritable.startswith("the zone's own name servers")
    assert rs("sub", "NS", "NSRecords", [{"nsdname": "ns1."}]).unwritable == ""
    assert "alias record set (of ip1)" in rs("lb", "A", "ARecords", [], target="/x/publicIPAddresses/ip1").unwritable
    assert "Traffic Manager link" in rs("tm", "A", "ARecords", []).unwritable


def test_names_and_values_are_taken_in_their_forms():
    assert recs.relative_name("home.example.com", "example.com") == "home"
    assert recs.relative_name("example.com.", "example.com") == "@" and recs.relative_name("@", "example.com") == "@"
    assert recs.relative_name("*.Dev", "example.com") == "*.dev" and recs.relative_name("_dmarc", "example.com") == "_dmarc"
    for bad in ("", "a..b", "a.*", "-x" * 200):
        with pytest.raises(ValueError):
            recs.relative_name(bad, "example.com")
    assert recs.record_of("MX", "10 Mail.Example.com.") == {"preference": 10, "exchange": "mail.example.com"}
    assert recs.record_of("CAA", '0 issue "letsencrypt.org"') == {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}
    assert recs.record_of("TXT", "x" * 300) == {"value": ["x" * 255, "x" * 45]}  # each TXT string at most 255 characters
    assert recs.record_of("TXT", '"v=spf1 -all"') == {"value": ["v=spf1 -all"]} and recs.relative_name("@.example.com", "example.com") == "@"
    assert recs.record_of("AAAA", "2001:DB8::1") == {"ipv6Address": "2001:db8::1"}
    for rtype, bad in (("A", "1.2.3"), ("MX", "mail.example.com"), ("SRV", "1 2 3"), ("CNAME", "nodot"), ("CAA", "0 bad-tag! x")):
        with pytest.raises(ValueError):
            recs.record_of(rtype, bad)
    with pytest.raises(Refusal, match="SOA"):
        recs.record_type("SOA")
    assert recs.ttl_of("2147483647") == 2_147_483_647
    with pytest.raises(ValueError):
        recs.ttl_of("0")


def test_setting_replaces_or_adds_and_keeps_the_rest():
    a = rs("@", "A", "ARecords", [{"ipv4Address": "20.1.2.3"}, {"ipv4Address": "20.1.2.4"}], ttl=600, metadata={"k": "v"})
    plan = recs.plan_set("example.com", "dns-rg", "@", "A", "20.1.2.9", a, [])
    assert plan.records == [{"ipv4Address": "20.1.2.9"}] and plan.said == "set @ A 20.1.2.9 (it was 20.1.2.3, 20.1.2.4)"
    assert plan.body() == {"properties": {"TTL": 600, "metadata": {"k": "v"}, "ARecords": [{"ipv4Address": "20.1.2.9"}]}}
    assert (plan.etag, plan.new) == ("e1", False)
    mx = rs("@", "MX", "MXRecords", [{"preference": 10, "exchange": "mx1.example.com"}])
    plan = recs.plan_set("example.com", "dns-rg", "@", "MX", "20 mx2.example.com", mx, ["A"])
    assert plan.records == [{"preference": 10, "exchange": "mx1.example.com"}, {"preference": 20, "exchange": "mx2.example.com"}]
    same = recs.plan_set("example.com", "dns-rg", "@", "MX", "10 MX1.example.com", mx, [])
    assert same.changed is False and same.said.endswith("nothing written")
    assert recs.plan_set("example.com", "dns-rg", "@", "MX", "10 mx1.example.com", mx, [], ttl=60).said == "@ MX 10 mx1.example.com: TTL 60"
    new = recs.plan_set("example.com", "dns-rg", "blog", "CNAME", "web.example.net", None, [])
    assert new.new and new.body() == {"properties": {"TTL": 3600, "CNAMERecord": {"cname": "web.example.net"}}}
    with pytest.raises(Refusal, match="stands alone"):
        recs.plan_set("example.com", "dns-rg", "www", "CNAME", "web.example.net", None, ["A"])
    full = rs("@", "TXT", "TXTRecords", [{"value": [str(i)]} for i in range(400)])
    with pytest.raises(Refusal, match="at most 400"):
        recs.plan_set("example.com", "dns-rg", "@", "TXT", "one more", full, [])


def test_removing_names_the_record_and_the_last_deletes_the_set():
    txt = rs("@", "TXT", "TXTRecords", [{"value": ["v=spf1 -all"]}, {"value": ["verify=1"]}])
    plan = recs.plan_remove("example.com", "dns-rg", "@", "TXT", "verify=1", txt)
    assert plan.records == [{"value": ["v=spf1 -all"]}] and plan.said == "removed @ TXT verify=1 (1 TXT record kept)"
    with pytest.raises(Refusal, match="name the one to remove"):
        recs.plan_remove("example.com", "dns-rg", "@", "TXT", "", txt)
    with pytest.raises(Refusal, match="no TXT record at @ holding nope"):
        recs.plan_remove("example.com", "dns-rg", "@", "TXT", "nope", txt)
    one = rs("home", "A", "ARecords", [{"ipv4Address": "198.51.100.7"}])
    gone = recs.plan_remove("example.com", "dns-rg", "home", "A", "198.51.100.7", one)
    assert gone.records is None and gone.said.endswith("(its record set deleted)") and gone.etag == "e1"
    with pytest.raises(Refusal, match="no A record set at away"):
        recs.plan_remove("example.com", "dns-rg", "away", "A", "1.2.3.4", None)
    with pytest.raises(Refusal, match="the zone's own"):
        recs.plan_remove("example.com", "dns-rg", "@", "NS", "ns1.", rs("@", "NS", "NSRecords", [{"nsdname": "ns1."}]))


def test_a_dynamic_dns_host_holds_this_networks_address_alone():
    held = rs("home", "A", "ARecords", [{"ipv4Address": "198.51.100.7"}, {"ipv4Address": "198.51.100.8"}], ttl=120, metadata={"m": "1"})
    plan = recs.plan_address("example.com", "dns-rg", "home", "93.184.216.34", held)
    assert plan.body() == {"properties": {"TTL": 120, "metadata": {"m": "1"}, "ARecords": [{"ipv4Address": "93.184.216.34"}]}}
    made = recs.plan_address("example.com", "dns-rg", "new", "93.184.216.34", None)
    assert made.new and made.ttl == recs.TTL_DDNS and made.said == "made"
