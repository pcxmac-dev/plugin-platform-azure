"""The platform's page makes the free changes through the plugin's forms (liminal-platform draws status.forms): each form's
fields are its hook's arguments in order, each change is confirmed by the user with the exact change named, and the hook
sends exactly the request Azure's reference gives (method, path, api-version, headers, body). A powered-off VM still bills,
so its form is refused once and sent only when the second confirmation accepts that; a risky security rule likewise. Over
the stand-ins alone."""
from __future__ import annotations

import inspect

import pytest

from conftest import SUB, FakeAzure, settings_of, ssh_key
from plugin_platform_azure.page import ACCEPT_BILLED, ACCEPT_RISKY
from plugin_platform_azure.records import Refusal

ARM = f"/subscriptions/{SUB}"


def page_args(form: dict, values: dict, accepted=()) -> list:
    """What the platform's page sends for a form (platform.js argsOf): the fields' values in order, a field whose `when` is
    unmet or left empty null (the hook's default), a number as a number, an accept field true only once accepted."""
    now = {**{x["name"]: x.get("value") for x in form["fields"]}, **values}
    out = []
    for x in form["fields"]:
        if x["type"] == "accept":
            out.append(x["name"] in accepted)
            continue
        shown = all(str(now.get(k) or "") in [str(v) for v in vs] for k, vs in (x.get("when") or {}).items())
        v = now.get(x["name"])
        out.append(None if not shown or v in (None, "") else int(v) if x["type"] == "number" else v)
    return out


def forms_of(p) -> dict:
    return {f["id"]: f for f in p.status()["forms"]}


def row_button(p, table: str, label_start: str) -> dict:
    t = next(t for t in p.status()["tables"] if t["title"] == table)
    return next(c for r in t["rows"] for c in r if isinstance(c, dict) and c.get("form") and c.get("label", "").startswith(label_start))


def last(fake: FakeAzure, method: str) -> dict:
    return [r for r in fake.requests if r["method"] == method and r["host"] == "management.azure.com"][-1]


@pytest.fixture
def read(made, env):
    env(settings_of())
    p, fake = made()
    p.refresh()
    return p, fake


def test_every_form_is_its_hooks_arguments_in_order_and_confirmed(read):
    p, fake = read
    forms = forms_of(p)
    assert set(forms) == {"vm:start", "vm:restart", "vm:deallocate", "vm:poweroff", "rule-add:web-rg/subnet-nsg",
                          "rule-remove:web-rg/subnet-nsg", "rule-add:web-rg/web1-nsg", "rule-remove:web-rg/web1-nsg",
                          "record-set:dns-rg/example.com", "record-remove:dns-rg/example.com", "key-add", "key-remove"}
    hooks = p.interface()["hooks"]
    for f in forms.values():
        assert f["hook"] in hooks
        assert [x["name"] for x in f["fields"]] == list(inspect.signature(getattr(p, f["hook"])).parameters), f["id"]
        assert all(x["type"] in ("text", "number", "choice", "fixed", "accept") for x in f["fields"])
        assert f["confirm"]["words"] and f["confirm"]["yes"]
    assert "STILL BILLED" in forms["vm:poweroff"]["confirm"]["words"] and "asked once more" in forms["vm:poweroff"]["confirm"]["words"]
    assert "no longer billed" in forms["vm:deallocate"]["confirm"]["words"] and "billed by the hour again" in forms["vm:start"]["confirm"]["words"]
    assert forms["record-remove:dns-rg/example.com"]["confirm"]["danger"] is True
    assert [c["value"] for c in next(x for x in forms["record-set:dns-rg/example.com"]["fields"] if x["name"] == "rtype")["choices"]] == \
        ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR"]
    assert fake.writes() == []  # drawn: nothing sent


def test_the_power_forms_send_the_vm_actions_as_the_reference_gives_them(read):
    p, fake = read
    forms = forms_of(p)
    for button, action, path in (("Restart web1", "restart", "restart"), ("Deallocate web1", "deallocate", "deallocate"),
                                 ("Start win1", "start", "start")):
        b = row_button(p, "Virtual machines", button)
        f = forms[b["form"]]
        args = page_args(f, b["values"])
        assert args[:3] == ["web-rg", button.split()[1], action] and args[3] is False
        rep = p.ask(f["hook"], *args)
        assert rep["ok"] and rep["accepted"] is True
        r = last(fake, "POST")
        assert r["path"] == f"{ARM}/resourceGroups/web-rg/providers/Microsoft.Compute/virtualMachines/{button.split()[1]}/{path}"
        assert r["query"] == {"api-version": "2026-04-01"} and r["body"] is None


def test_power_off_still_bills_so_it_is_sent_only_once_that_is_accepted(read):
    p, fake = read
    b = row_button(p, "Virtual machines", "Power off web1")
    f = forms_of(p)[b["form"]]
    with pytest.raises(Refusal, match="still billed for its compute") as refused:  # the first confirmation is not enough
        p.ask(f["hook"], *page_args(f, b["values"]))
    assert refused.value.accept == ACCEPT_BILLED and fake.writes() == [] and fake.vms["web1"]["power"] == "running"
    accept = next(x for x in f["fields"] if x["name"] == ACCEPT_BILLED)
    assert accept["type"] == "accept" and "billed" in accept["words"] and accept["yes"] == "Power off anyway"
    rep = p.ask(f["hook"], *page_args(f, b["values"], accepted={ACCEPT_BILLED}))
    assert rep["ok"] and "still billed" in " ".join(rep["lines"]) and fake.vms["web1"]["power"] == "stopped"
    r = last(fake, "POST")
    assert r["path"].endswith("/virtualMachines/web1/powerOff") and r["query"] == {"api-version": "2026-04-01"}
    assert "skipShutdown" not in r["query"]  # graceful: no hard power-off is offered


def test_a_record_is_set_with_every_other_record_kept_and_its_etag(read):
    p, fake = read
    f = forms_of(p)["record-set:dns-rg/example.com"]
    before = {k: v for k, v in fake.zones[("dns-rg", "example.com")].items()}
    # a TXT record added beside the others: the record set written whole, If-Match its etag, its TTL and metadata kept
    etag = fake.zones[("dns-rg", "example.com")][("@", "TXT")]["etag"]
    rep = p.ask(f["hook"], *page_args(f, {"name": "@", "rtype": "TXT", "value": "v=DMARC1; p=none", "ttl": ""}))
    assert rep["ok"] and rep["said"] == "added @ TXT v=DMARC1; p=none beside 2 others"
    r = last(fake, "PUT")
    assert r["path"] == f"{ARM}/resourceGroups/dns-rg/providers/Microsoft.Network/dnsZones/example.com/TXT/@"
    assert r["query"] == {"api-version": "2018-05-01"} and r["headers"]["If-Match"] == etag and "If-None-Match" not in r["headers"]
    assert r["body"] == {"properties": {"TTL": 3600, "TXTRecords": [
        {"value": ["v=spf1 include:spf.protection.outlook.com -all"]}, {"value": ["google-site-verification=abc123"]},
        {"value": ["v=DMARC1; p=none"]}]}}
    assert all(fake.zones[("dns-rg", "example.com")][k] == v for k, v in before.items() if k != ("@", "TXT"))  # the rest kept
    # an A record replaces the name's A records, its metadata kept
    rep = p.ask(f["hook"], *page_args(f, {"name": "@", "rtype": "A", "value": "20.1.2.99", "ttl": "300"}))
    assert rep["said"] == "set @ A 20.1.2.99 (it was 20.1.2.3)"
    assert last(fake, "PUT")["body"] == {"properties": {"TTL": 300, "metadata": {"owner": "me"}, "ARecords": [{"ipv4Address": "20.1.2.99"}]}}
    # a new record set: If-None-Match *, so none made meanwhile is written over
    rep = p.ask(f["hook"], *page_args(f, {"name": "_sip._tcp", "rtype": "SRV", "value": "10 5 5060 sip.example.com"}))
    r = last(fake, "PUT")
    assert r["headers"]["If-None-Match"] == "*" and "If-Match" not in r["headers"] and rep["said"].startswith("added _sip._tcp SRV")
    assert r["body"] == {"properties": {"TTL": 3600, "SRVRecords": [{"priority": 10, "weight": 5, "port": 5060, "target": "sip.example.com"}]}}
    rep = p.ask(f["hook"], *page_args(f, {"name": "@", "rtype": "A", "value": "20.1.2.99", "ttl": "300"}))
    assert rep["changed"] is False and "nothing written" in rep["said"]  # there already: nothing sent
    calls = len(fake.requests)
    for values, why in (({"name": "www", "rtype": "A", "value": "20.1.2.3"}, "is a CNAME"),
                        ({"name": "@", "rtype": "CNAME", "value": "other.example.org"}, "apex"),
                        ({"name": "@", "rtype": "NS", "value": "ns1.example.org"}, "the zone's own name servers"),
                        ({"name": "lb", "rtype": "A", "value": "20.1.2.3"}, "an alias record set"),
                        ({"name": "home", "rtype": "A", "value": "not-an-ip"}, "not an IPv4 address")):
        with pytest.raises(ValueError, match=why):
            p.ask(f["hook"], *page_args(f, values))
    assert all(r["method"] == "GET" for r in fake.requests[calls:])  # refused: nothing written


def test_a_record_is_removed_from_its_set_and_the_last_one_deletes_the_set(read):
    p, fake = read
    b = row_button(p, "example.com records", "Remove @ TXT google-site-verification")
    f = forms_of(p)[b["form"]]
    assert b["values"] == {"group": "dns-rg", "zone": "example.com", "name": "@", "rtype": "TXT", "value": "google-site-verification=abc123"}
    rep = p.ask(f["hook"], *page_args(f, b["values"]))
    assert rep["said"] == "removed @ TXT google-site-verification=abc123 (1 TXT record kept)"
    r = last(fake, "PUT")
    assert r["body"] == {"properties": {"TTL": 3600, "TXTRecords": [{"value": ["v=spf1 include:spf.protection.outlook.com -all"]}]}}
    b = row_button(p, "example.com records", "Remove www CNAME")
    etag = fake.zones[("dns-rg", "example.com")][("www", "CNAME")]["etag"]
    rep = p.ask(f["hook"], *page_args(f, b["values"]))
    assert rep["said"].endswith("(its record set deleted)") and fake.record("www", "CNAME") is None
    r = last(fake, "DELETE")
    assert r["path"] == f"{ARM}/resourceGroups/dns-rg/providers/Microsoft.Network/dnsZones/example.com/CNAME/www"
    assert r["headers"]["If-Match"] == etag and r["query"] == {"api-version": "2018-05-01"} and r["body"] is None
    # the page drew the zone as it is now: www has no Remove any more
    assert not any(isinstance(c, dict) and c.get("label", "").startswith("Remove www") for t in p.status()["tables"]
                   for row in t["rows"] for c in row)


def test_a_record_changed_meanwhile_is_not_written_over(read):
    p, fake = read
    f = forms_of(p)["record-set:dns-rg/example.com"]
    real = fake.answer

    def changed_between(method, host, path, query, headers, data):  # someone writes the set between the read and the write
        got = real(method, host, path, query, headers, data)
        if method == "GET" and path.endswith("/TXT/@"):
            zone = fake.zones[("dns-rg", "example.com")]
            zone[("@", "TXT")] = fake._recordset("@", "TXT", dict(zone[("@", "TXT")]["properties"]))
        return got
    fake.answer = changed_between
    with pytest.raises(Exception, match="it changed since it was read") as failed:
        p.ask(f["hook"], *page_args(f, {"name": "@", "rtype": "TXT", "value": "v=DMARC1; p=none"}))
    assert getattr(failed.value, "status", 0) == 412


def test_a_rule_is_added_and_removed_as_the_reference_gives_it(read):
    p, fake = read
    forms = forms_of(p)
    f = forms["rule-add:web-rg/web1-nsg"]
    args = page_args(f, {"name": "allow-web", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "ports": "80, 8080-8090",
                         "source": "203.0.113.7", "destination": "", "priority": "320", "description": "the web"})
    assert args == ["web-rg", "web1-nsg", "allow-web", "Inbound", "Allow", "Tcp", "80, 8080-8090", "203.0.113.7", None, 320,
                    "the web", False]
    rep = p.ask(f["hook"], *args)
    assert rep["ok"] and rep["said"] == "added allow-web: Allow inbound Tcp to ports 80, 8080-8090 from 203.0.113.7 to any, priority 320"
    r = last(fake, "PUT")
    assert r["path"] == f"{ARM}/resourceGroups/web-rg/providers/Microsoft.Network/networkSecurityGroups/web1-nsg/securityRules/allow-web"
    assert r["query"] == {"api-version": "2026-01-01"}
    assert r["body"] == {"properties": {"protocol": "Tcp", "access": "Allow", "direction": "Inbound", "priority": 320,
                                        "sourcePortRange": "*", "destinationPortRanges": ["80", "8080-8090"],
                                        "sourceAddressPrefix": "203.0.113.7", "destinationAddressPrefix": "*",
                                        "description": "the web"}}
    rows = next(t for t in p.status()["tables"] if t["title"] == "web1-nsg rules")["rows"]
    assert ["320", {"text": "allow-web", "sub": "the web"}] == rows[2][:2]  # drawn as it is now, by priority
    for values, why in (({"name": "allow-web", "priority": "330"}, "named allow-web already"),
                        ({"name": "x2", "priority": "300"}, "priority 300 is allow-ssh-home's"),
                        ({"name": "x3", "priority": "99"}, "100 to 4096"),
                        ({"name": "x4", "priority": "340", "ports": "70000"}, "not a port")):
        full = {"direction": "Inbound", "access": "Allow", "protocol": "Tcp", "ports": "81", "source": "10.0.0.0/8", **values}
        with pytest.raises(ValueError, match=why):
            p.ask(f["hook"], *page_args(f, full))
    b = row_button(p, "web1-nsg rules", "Remove allow-web")
    rf = forms[b["form"]]
    rep = p.ask(rf["hook"], *page_args(rf, b["values"]))
    assert rep["said"].startswith("removed allow-web") and not any(r["name"] == "allow-web" for r in fake.nsgs["web1-nsg"]["rules"])
    r = last(fake, "DELETE")
    assert r["path"].endswith("/networkSecurityGroups/web1-nsg/securityRules/allow-web") and r["query"] == {"api-version": "2026-01-01"}


def test_a_risky_rule_is_sent_only_once_that_is_accepted(read):
    p, fake = read
    forms = forms_of(p)
    f = forms["rule-add:web-rg/web1-nsg"]
    open_ssh = {"name": "ssh-anywhere", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "ports": "22",
                "source": "*", "priority": "200"}
    with pytest.raises(Refusal, match="opens SSH \\(port 22\\) to the whole internet") as refused:
        p.ask(f["hook"], *page_args(f, open_ssh))
    assert refused.value.accept == ACCEPT_RISKY and fake.writes() == []
    for values, why in (({**open_ssh, "ports": "*", "source": "Internet"}, "every port to the whole internet"),
                        ({**open_ssh, "ports": "3389", "source": "0.0.0.0/0"}, "RDP"),
                        ({**open_ssh, "access": "Deny", "source": "10.0.0.0/8"}, "cuts this PC off")):
        with pytest.raises(Refusal, match=why):
            p.ask(f["hook"], *page_args(f, values))
    rep = p.ask(f["hook"], *page_args(f, open_ssh, accepted={ACCEPT_RISKY}))
    assert rep["ok"] and rep["lines"][0].endswith("(accepted)") and fake.writes()[-1][0] == "PUT"
    # removing the rule that lets SSH in to web1: asked twice too
    b = row_button(p, "web1-nsg rules", "Remove allow-ssh-home")
    rf = forms[b["form"]]
    with pytest.raises(Refusal, match="letting SSH \\(port 22\\) in to web1") as refused:
        p.ask(rf["hook"], *page_args(rf, b["values"]))
    assert refused.value.accept == ACCEPT_RISKY and any(r["name"] == "allow-ssh-home" for r in fake.nsgs["web1-nsg"]["rules"])
    assert p.ask(rf["hook"], *page_args(rf, b["values"], accepted={ACCEPT_RISKY}))["ok"]
    assert not any(r["name"] == "allow-ssh-home" for r in fake.nsgs["web1-nsg"]["rules"])
    # a rule that is no risk is asked once; a default rule cannot be removed
    assert p.ask(rf["hook"], "web-rg", "web1-nsg", "allow-https", False)["ok"]
    with pytest.raises(Refusal, match="default rules"):
        p.ask(rf["hook"], "web-rg", "web1-nsg", "DenyAllInBound", True)


def test_an_ssh_key_is_added_and_removed(read):
    p, fake = read
    forms = forms_of(p)
    f = forms["key-add"]
    key = ssh_key("ssh-rsa", 4096, "me@desk")
    args = page_args(f, {"group": "web-rg", "name": "desk", "public_key": key, "location": ""})
    assert args == ["web-rg", "desk", key, None]
    rep = p.ask(f["hook"], *args)
    assert rep["ok"] and rep["lines"][0].startswith("ssh-rsa 4096 bits · SHA256:")
    r = last(fake, "PUT")
    assert r["path"] == f"{ARM}/resourceGroups/web-rg/providers/Microsoft.Compute/sshPublicKeys/desk"
    assert r["query"] == {"api-version": "2026-04-01"} and r["body"] == {"location": "eastus", "properties": {"publicKey": key}}
    for bad, why in ((ssh_key("ssh-rsa", 1024), "1024 bits"), ("ssh-dss AAAAB3NzaC1kc3MAAACBAP", "not taken by Azure|base64"),
                     ("not a key", "not an SSH public key")):
        with pytest.raises(ValueError, match=why):
            p.ask(f["hook"], "web-rg", "desk2", bad, None)
    with pytest.raises(Refusal, match="named desk already"):
        p.ask(f["hook"], "web-rg", "desk", key, None)
    b = row_button(p, "SSH public keys", "Remove the SSH key desk")
    rf = forms[b["form"]]
    rep = p.ask(rf["hook"], *page_args(rf, b["values"]))
    assert rep["ok"] and ("web-rg", "desk") not in fake.keys
    r = last(fake, "DELETE")
    assert r["path"].endswith("/sshPublicKeys/desk") and r["query"] == {"api-version": "2026-04-01"}
