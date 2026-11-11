"""Network security groups' rules: read from Azure's answers, checked as typed, sent as the reference's body, and the risk
of a change (what opens a VM to the whole internet, or cuts this PC off from it) said in words."""
from __future__ import annotations

import pytest

from plugin_platform_azure import rules as r


def make(**kw):
    base = {"name": "x", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "ports": "22", "source": "*",
            "destination": "*", "priority": 300}
    return r.rule_of(**{**base, **kw})


def test_a_rule_is_read_from_azures_answer():
    got = r.parse({"name": "web", "properties": {"protocol": "*", "access": "Allow", "direction": "Inbound", "priority": 100,
                                                 "destinationPortRanges": ["80", "443"], "sourceAddressPrefixes": ["1.2.3.4", "5.6.7.0/24"],
                                                 "destinationApplicationSecurityGroups": [{"id": "/x/applicationSecurityGroups/web-asg"}],
                                                 "description": "web"}})
    assert (got.ports, got.sources, got.destinations, got.protocol) == (["80", "443"], ["1.2.3.4", "5.6.7.0/24"], ["web-asg"], "*")
    assert r.shown(["*"]) == "any" and r.shown([]) == "any"


def test_a_rule_as_typed_is_checked_and_sent_as_the_references_body():
    one = make(ports="22", source="203.0.113.7", description="home")
    assert r.body(one) == {"properties": {"protocol": "Tcp", "access": "Allow", "direction": "Inbound", "priority": 300,
                                          "sourcePortRange": "*", "destinationPortRange": "22", "sourceAddressPrefix": "203.0.113.7",
                                          "destinationAddressPrefix": "*", "description": "home"}}
    many = make(ports="80 443", source="10.0.0.0/8, 192.168.0.0/16", destination="VirtualNetwork", protocol="*")
    assert r.body(many)["properties"]["destinationPortRanges"] == ["80", "443"]
    assert r.body(many)["properties"]["sourceAddressPrefixes"] == ["10.0.0.0/8", "192.168.0.0/16"]
    assert r.body(many)["properties"]["destinationAddressPrefix"] == "VirtualNetwork"
    assert make(direction="outbound", access="deny", protocol="udp").direction == "Outbound"
    for kw, why in (({"name": "-bad"}, "not a rule name"), ({"priority": 5000}, "100 to 4096"), ({"ports": "1-2-3"}, "not a port"),
                    ({"ports": "*, 22"}, "stands alone"), ({"source": "Internet, 1.2.3.4"}, "not an IP address"),
                    ({"protocol": "gre"}, "one of"), ({"description": "x" * 141}, "140")):
        with pytest.raises(ValueError, match=why):
            make(**kw)


def test_the_risk_of_adding_a_rule():
    assert r.risk_of_adding(make(), []) == "it opens SSH (port 22) to the whole internet"
    assert r.risk_of_adding(make(ports="3389", source="Internet"), []) == "it opens RDP (port 3389) to the whole internet"
    assert r.risk_of_adding(make(ports="*", source="0.0.0.0/0"), []) == "it opens every port to the whole internet"
    assert r.risk_of_adding(make(ports="20-25", source="::/0"), []) == "it opens SSH (port 22) and Telnet (port 23) to the whole internet"
    assert r.risk_of_adding(make(ports="5432", source="Internet"), []) == "it opens PostgreSQL (port 5432) to the whole internet"
    assert r.risk_of_adding(make(ports="2375-2376"), []) == "it opens Docker's API (port 2375) and Docker's API (TLS) (port 2376) to the whole internet"
    assert r.risk_of_adding(make(source="203.0.113.7"), ["vm1"]) == ""  # SSH from one address: no risk
    assert r.risk_of_adding(make(ports="443"), ["vm1"]) == ""  # HTTPS to the world: what it is for
    assert r.risk_of_adding(make(protocol="Udp"), []) == ""  # port 22 over UDP is not SSH
    assert r.risk_of_adding(make(direction="Outbound"), ["vm1"]) == ""
    assert "cuts this PC off" in r.risk_of_adding(make(access="Deny", source="10.0.0.0/8"), ["vm1"])
    assert r.risk_of_adding(make(access="Deny"), []) == ""  # a group attached to no VM cuts no one off


def test_a_source_left_empty_is_refused_never_taken_as_everywhere():
    """An empty Source opened the whole internet unasked (the audit, 2026-11-11): it must be named, * or Internet."""
    with pytest.raises(ValueError, match="no source given"):
        make(source="")
    with pytest.raises(ValueError, match="no source given"):
        make(source=None)
    assert make(destination="").destinations == ["*"]  # a destination may be left as any


def test_the_risk_of_removing_a_rule():
    ssh = make(source="203.0.113.7")
    assert r.risk_of_removing(ssh, ["vm1", "vm2"]).startswith("it is the rule letting SSH (port 22) in to vm1, vm2")
    assert r.risk_of_removing(ssh, []) == ""
    assert r.risk_of_removing(make(ports="80"), ["vm1"]) == ""
    assert r.risk_of_removing(make(ports="*", protocol="*"), ["vm1"]).startswith("it is the rule letting SSH (port 22) and RDP")
    # a Deny ahead of an Allow from everywhere: removing it opens what the Allow lets in
    deny = make(name="deny-db", access="Deny", ports="5432", priority=200)
    allow = make(name="allow-db", ports="5432", source="*", priority=300)
    assert r.risk_of_removing(deny, [], others=[deny, allow]) == "without it, a later rule opens PostgreSQL (port 5432) to the whole internet"
    assert r.risk_of_removing(deny, [], others=[deny]) == ""  # nothing behind it opens anything
    earlier = make(name="allow-db", ports="5432", source="*", priority=100)
    assert r.risk_of_removing(deny, [], others=[deny, earlier]) == ""  # the Allow came first anyway: nothing changes
