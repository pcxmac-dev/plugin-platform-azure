"""Dynamic DNS through Azure DNS (the library's Keeper, liminal-libs 1.49.7): this network's public IPv4 address asked of
the name servers the plugin names, each host's A record set read, and written (with its etag, its TTL and metadata kept)
only when it is the keeper's own: a host with no record (made), one pointing here or at the address the keeper set last
(kept in the platform's folder: azure/ddns.json), or one the user took over on the page (asked twice). A host holding
another address, or several, is left as it is and offered Take over…; several addresses are never cut to one unasked. A
host taken out of the setting is let go (Keeper.settle, once the zones are read). Update DNS now is a confirmed form; a
pass ends once the plugin is detached, and reads no settings while it runs."""
from __future__ import annotations

import inspect
import json
import threading

import pytest

from conftest import HOME, SECRET, FakeAzure, settings_of
from liminal_libs.machines.ddns import ACCEPT as ACCEPT_TAKE_OVER
from liminal_libs.machines.ddns import TakeOverRefused
from plugin_platform_azure import PUBLIC_IPV4, AzurePlugin, ddns_state_file

OTHER = "93.184.216.99"  # this network's address after the router came back with another


def a_record(fake, name):
    held = fake.record(name, "A")
    return None if held is None else [x["ipv4Address"] for x in held["ARecords"]]


def puts(fake) -> list:
    return [r for r in fake.requests if r["method"] == "PUT"]


def test_its_name_servers_are_named_by_the_plugin():
    assert PUBLIC_IPV4 == (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
                           ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))


def test_a_host_holding_another_address_is_left_as_it_is_and_offered_take_over(made, env):
    """The audit's scenario: the apex holds the web VM's 20.1.2.3 and home holds 198.51.100.7; neither is Dynamic DNS's
    own, so neither is written; a host with no record is made."""
    env(settings_of(AZURE_DDNS_HOSTS="example.com, home.example.com, new.example.com"))
    p, fake = made()
    out = {h["host"]: h for h in p.ddns_update(force=False)}  # the zones read first (a refresh), then the pass
    assert out["example.com"]["result"] == "holds 20.1.2.3, not this network's address: left as it is (Take over… to point it here)"
    assert out["home.example.com"]["foreign"] is True and out["home.example.com"]["ok"] is False
    assert out["new.example.com"]["result"] == "made (was none)"
    assert a_record(fake, "@") == ["20.1.2.3"] and a_record(fake, "home") == ["198.51.100.7"] and a_record(fake, "new") == [HOME]
    assert [r["path"].rsplit("/", 2)[-2:] for r in puts(fake)] == [["A", "new"]]
    assert puts(fake)[0]["headers"]["If-None-Match"] == "*" and puts(fake)[0]["body"] == {
        "properties": {"TTL": 300, "ARecords": [{"ipv4Address": HOME}]}}
    st = p.status()
    table = next(t for t in st["tables"] if t["title"] == "Dynamic DNS")
    takes = {r[0]: r[-1] for r in table["rows"]}
    assert takes["example.com"] == {"form": "ddns-take", "title": "Take over…", "label": "Take over example.com",
                                    "values": {"host": "example.com", "holds": "20.1.2.3"}}
    assert takes["new.example.com"] == ""  # its own: nothing to take over
    forms = {f["id"]: f for f in st["forms"]}
    assert {"ddns-take", "ddns-now"} <= set(forms) and forms["ddns-take"]["hook"] == "ddns_take_over"
    assert {"form": "ddns-now", "title": "Update DNS now"} in st["actions"]  # confirmed now, no longer a plain hook
    assert not any(a.get("hook") == "ddns_update" for a in st["actions"])
    state = json.loads(ddns_state_file().read_text(encoding="utf-8"))  # kept in the platform's folder
    assert state == {"own": {"new.example.com": HOME}, "taken": []}
    assert ddns_state_file().as_posix().endswith("platform/azure/ddns.json")


def test_take_over_is_asked_twice_and_only_then_a_pass_sets_it(made, env):
    """Take over… sets the record at once and drops what it holds, so one yes is not enough (the re-verification):
    without accept_take_over exactly true it is refused naming it, and nothing is taken."""
    env(settings_of(AZURE_DDNS_HOSTS="home.example.com"))
    p, fake = made()
    p.ddns_update(force=False)
    assert a_record(fake, "home") == ["198.51.100.7"]
    take = {f["id"]: f for f in p.status()["forms"]}["ddns-take"]
    assert [x["name"] for x in take["fields"]] == list(inspect.signature(p.ddns_take_over).parameters) == [
        "host", "holds", ACCEPT_TAKE_OVER] and take["confirm"]["danger"] is True
    assert take["fields"][-1]["type"] == "accept" and ACCEPT_TAKE_OVER == "accept_take_over"
    with pytest.raises(TakeOverRefused) as refused:  # the first confirmation alone
        p.ask("ddns_take_over", "home.example.com", "198.51.100.7")
    assert refused.value.accept == "accept_take_over" and "home.example.com holds 198.51.100.7" in str(refused.value)
    assert not p.keeper().taken("home.example.com") and p.keeper().known() == [] and puts(fake) == []
    for almost in ("true", 1, "yes"):
        with pytest.raises(TakeOverRefused):
            p.ask("ddns_take_over", "home.example.com", "198.51.100.7", almost)
        assert not p.keeper().taken("home.example.com") and puts(fake) == []
    assert a_record(fake, "home") == ["198.51.100.7"]
    rep = p.ask("ddns_take_over", "home.example.com", "198.51.100.7", True)
    assert rep["ok"] is True and rep["said"] == "home.example.com taken over: set (was 198.51.100.7)"
    assert a_record(fake, "home") == [HOME] and p.keeper().taken("home.example.com")
    put = puts(fake)[-1]
    assert put["headers"]["If-Match"] and put["body"] == {"properties": {"TTL": 300, "ARecords": [{"ipv4Address": HOME}]}}
    with pytest.raises(ValueError, match="none of the Dynamic DNS hosts"):
        p.ask("ddns_take_over", "www.example.com", "", True)


def test_take_over_is_refused_when_the_record_changed_since_the_page_showed_it(made, env):
    env(settings_of(AZURE_DDNS_HOSTS="home.example.com"))
    p, fake = made()
    p.ddns_update(force=False)
    zone = fake.zones[("dns-rg", "example.com")]
    zone[("home", "A")] = fake._recordset("home", "A", {"TTL": 300, "ARecords": [{"ipv4Address": "198.51.100.8"}]})
    with pytest.raises(ValueError, match="holds 198.51.100.8 now, not 198.51.100.7 as shown: nothing taken over"):
        p.ask("ddns_take_over", "home.example.com", "198.51.100.7", True)
    assert not p.keeper().taken("home.example.com") and a_record(fake, "home") == ["198.51.100.8"] and puts(fake) == []


def test_a_host_with_several_addresses_is_never_cut_to_one(made, env):
    env(settings_of(AZURE_DDNS_HOSTS="multi.example.com"))
    p, fake = made()
    zone = fake.zones[("dns-rg", "example.com")]
    zone[("multi", "A")] = fake._recordset("multi", "A", {"TTL": 300, "ARecords": [{"ipv4Address": "198.51.100.1"},
                                                                                    {"ipv4Address": "198.51.100.2"}]})
    for force in (False, True):  # Update DNS now too
        out = p.ddns_update(force=force)
        assert out[0]["result"].startswith("holds 2 addresses (198.51.100.1, 198.51.100.2): left as it is")
    assert a_record(fake, "multi") == ["198.51.100.1", "198.51.100.2"] and puts(fake) == []


def test_its_own_old_address_is_updated_after_the_networks_address_changed(made, env):
    env(settings_of(AZURE_DDNS_HOSTS="new.example.com"))
    p, fake = made(public=[(HOME, "a stand-in"), (HOME, "a stand-in"), (OTHER, "a stand-in")])
    assert p.ddns_update(force=False)[0]["result"] == "made (was none)"
    out = p.ddns_update(force=True)  # the router came back with another address: the record the keeper set is its own
    assert out[0]["result"] == f"set (was {HOME})" and a_record(fake, "new") == [OTHER]


def test_a_host_set_by_hand_is_let_go_and_left_as_set(made, env):
    """A Dynamic DNS host's A record set by hand on the page is left as set: the keeper lets it go (Take over… again
    points it here), so its next pass never writes it back."""
    env(settings_of(AZURE_DDNS_HOSTS="new.example.com"))
    p, fake = made()
    p.ddns_update(force=False)
    assert p.keeper().own("new.example.com") == HOME
    rep = p.set_record("dns-rg", "example.com", "new", "A", "203.0.113.5")
    assert any("left as you set it" in x for x in rep["lines"]) and p.keeper().own("new.example.com") is None
    out = p.ddns_update(force=True)
    assert out[0]["foreign"] is True and a_record(fake, "new") == ["203.0.113.5"]


def test_a_host_taken_over_then_taken_out_of_the_setting_is_let_go_and_put_back_left_as_it_is(env, monkeypatch):
    """Keeper.settle with the whole setting: a host taken over, then taken out of the setting, is let go by the next pass
    (the address it was set to forgotten with it). Put back in the setting later (the router came back with another
    address meanwhile), it is left as it is, its row offering Take over… again."""
    env(settings_of(AZURE_DDNS_HOSTS="new.example.com, home.example.com"))
    fake, network = FakeAzure(), [HOME]
    p = AzurePlugin(transport=fake, public=lambda: (network[0], "a stand-in"), sleep=lambda s: None)
    p.ddns_update(force=False)
    p.ask("ddns_take_over", "home.example.com", "198.51.100.7", True)
    keeper = p.keeper()
    assert keeper.taken("home.example.com") and keeper.own("home.example.com") == HOME and a_record(fake, "home") == [HOME]
    monkeypatch.setenv("AZURE_DDNS_HOSTS", "new.example.com")
    p.settings_changed()
    out = p.ddns_update(force=False)
    assert [h["host"] for h in out] == ["new.example.com"] and keeper.known() == ["new.example.com"]
    assert not keeper.taken("home.example.com") and keeper.own("home.example.com") is None
    assert json.loads(ddns_state_file().read_text(encoding="utf-8")) == {"own": {"new.example.com": HOME}, "taken": []}
    network[0] = OTHER
    monkeypatch.setenv("AZURE_DDNS_HOSTS", "new.example.com, home.example.com")  # put back
    p.settings_changed()
    out = {h["host"]: h for h in p.ddns_update(force=True)}
    assert out["new.example.com"]["result"] == f"set (was {HOME})" and a_record(fake, "new") == [OTHER]  # its own: kept
    assert out["home.example.com"]["foreign"] is True and a_record(fake, "home") == [HOME]  # no longer its own: as it is
    assert out["home.example.com"]["result"] == f"holds {HOME}, not this network's address: left as it is (Take over… to point it here)"
    rows = next(t for t in p.status()["tables"] if t["title"] == "Dynamic DNS")["rows"]
    take = {r[0]: r[-1] for r in rows}["home.example.com"]
    assert take["form"] == "ddns-take" and take["values"] == {"host": "home.example.com", "holds": HOME}
    assert keeper.known() == ["new.example.com"]


def test_the_hosts_are_settled_only_once_the_zones_are_read(made, env, monkeypatch):
    """Never on zones not read: a refresh whose zone list failed lets no host go (nor does a pass, which has no host in
    the zones then); the next refresh that reads them does."""
    env(settings_of(AZURE_DDNS_HOSTS="new.example.com"))
    p, fake = made()
    p.ddns_update(force=False)
    assert p.keeper().own("new.example.com") == HOME
    monkeypatch.setenv("AZURE_DDNS_HOSTS", "home.example.com")  # new.example.com taken out of the setting
    p.settings_changed()
    fake.fail["zones"] = (500, "InternalServerError", "The server encountered an internal error.")
    p.refresh()
    assert p.snapshot().troubles.get("zones") and p.snapshot().zones == []
    assert p.keeper().own("new.example.com") == HOME  # nothing let go on zones not read
    with pytest.raises(ValueError, match="no Dynamic DNS host is in the subscription's Azure DNS zones"):
        p.ddns_update(force=False)
    assert p.keeper().known() == ["new.example.com"]
    fake.fail.clear()
    p.refresh()
    assert p.keeper().known() == [] and a_record(fake, "new") == [HOME]  # let go; its record left as it is
    assert puts(fake)[-1]["path"].endswith("/A/new") and len(puts(fake)) == 1


def test_a_host_taken_out_of_the_settings_while_it_was_not_running_is_let_go(made, env):
    """What the keeper held before a restart, for a host no longer set, is let go once the zones are read (the first
    refresh, before the first pass)."""
    ddns_state_file().parent.mkdir(parents=True, exist_ok=True)
    ddns_state_file().write_text(json.dumps({"own": {"gone.example.com": "198.51.100.9"}, "taken": ["old.example.com"]}),
                                 encoding="utf-8")
    env(settings_of(AZURE_DDNS_HOSTS="new.example.com"))
    p, fake = made()
    assert p.keeper().own("gone.example.com") == "198.51.100.9" and p.keeper().taken("old.example.com")
    p.ddns_update(force=False)
    assert p.keeper().own("gone.example.com") is None and not p.keeper().taken("old.example.com")
    assert json.loads(ddns_state_file().read_text(encoding="utf-8")) == {"own": {"new.example.com": HOME}, "taken": []}


def test_a_pass_stopped_by_a_detach_writes_nothing_and_reads_no_settings(made, env):
    """A pass ends once the plugin is detached (the worker's stop set): the Keeper checks it before each write, and the
    plugin's write refuses too; while a pass runs, no settings are read (the pass keeps the ones it began with)."""
    env(settings_of(AZURE_DDNS_HOSTS="new.example.com, other.example.com"))
    p, fake = made()
    p.refresh()
    cfg = p.config()
    stop = threading.Event()
    real = fake.answer

    def detached_meanwhile(method, host, path, query, headers, data):
        if method == "GET" and path.endswith("/A/new"):
            stop.set()  # the platform detaches the plugin while the pass reads the first host
        return real(method, host, path, query, headers, data)
    fake.answer = detached_meanwhile

    def no_settings(*a, **k):
        raise AssertionError("a pass read the settings")
    p.config = no_settings
    hosts, _ = p.ddns_hosts(cfg)
    p._ddns_pass(cfg, hosts, stop=stop)
    assert puts(fake) == [] and a_record(fake, "new") is None
    with pytest.raises(RuntimeError, match="no Dynamic DNS pass"):
        p._ddns_write(hosts[0], HOME)  # outside a pass, the write refuses


def test_a_host_that_cannot_be_kept_says_why(made, env):
    env(settings_of(AZURE_DDNS_HOSTS="lb.example.com, www.example.com"))
    p, fake = made()
    out = p.ddns_update()
    assert out[0]["ok"] is False and "alias record set" in out[0]["result"]
    assert out[1]["ok"] is False and "is a CNAME" in out[1]["result"]
    assert puts(fake) == []


def test_a_zone_two_resource_groups_hold_is_written_to_in_neither(made, env):
    env(settings_of(AZURE_DDNS_HOSTS="new.example.com"))
    p, fake = made()
    fake.zones[("a-rg", "example.com")] = {}  # a copy of the zone, not delegated
    out = p.ddns_update()
    assert out[0]["ok"] is False and "a zone in 2 resource groups (a-rg, dns-rg)" in out[0]["result"]
    assert puts(fake) == []


def test_no_address_found_writes_nothing(made, env):
    env(settings_of(ddns=True))
    p, fake = made(public=(None, "neither OpenDNS nor Google answered with a public IPv4 address"))
    out = p.ddns_update()
    assert out[0]["ok"] is False and out[0]["result"].startswith("this network's address was not found: neither OpenDNS nor Google")
    assert puts(fake) == []


def test_hosts_in_no_zone_are_refused_and_a_secret_typed_there_is_never_shown(made, env):
    env(settings_of(AZURE_DDNS_HOSTS="home.example.org"))
    p, fake = made()
    with pytest.raises(ValueError, match="no Dynamic DNS host is in the subscription's Azure DNS zones"):
        p.ddns_update()
    env(settings_of(AZURE_DDNS_HOSTS=f"new.example.com, {SECRET}"))  # the secret pasted twice, once into the hosts
    p.settings_changed()
    st = p.status()
    assert SECRET not in json.dumps(st) and SECRET.lower() not in json.dumps(st) and "•••" in st["problem"]
