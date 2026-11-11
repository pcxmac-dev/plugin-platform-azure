"""The plugin over the stand-ins: its settings read through the Login interface (an EnvironmentLogin not attached, the app's
login attached), its status from what was read (no request made to answer it; no value of a setting in it), valid while
set up and the last read worked or is untried, the background reading only while attached, its hooks asked by name, the
command line."""
from __future__ import annotations

import json
import time

import pytest

import plugin_platform_azure.__main__ as cli
from conftest import CLIENT, HOME, SECRET, SUB, TENANT, FakeAzure, Pairs, Platform, settings_of
from plugin_platform_azure import NOT_SET, RETRY_S
from plugin_platform_azure.page import BILLING
from plugin_platform_azure.settings import read


def wait_until(test, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if test():
            return True
        time.sleep(0.02)
    return False


def tables(st: dict) -> dict:
    return {t["title"]: t for t in st["tables"]}


def test_nothing_set_is_not_valid_and_names_the_settings_and_where_to_make_them(made):
    p, fake = made()
    st = p.status()
    assert st["present"] is False and st["valid"] is False and st["why"] == NOT_SET and not p.present()
    assert "AZURE_CLIENT_SECRET" in st["why"] and "App registrations" in st["why"] and "Access control (IAM)" in st["why"]
    assert st["tables"] == [] and st["actions"] == [] and st["forms"] == [] and st["billing"] == BILLING
    assert fake.requests == []
    with pytest.raises(ValueError, match="the API is not set up"):
        p.refresh()
    with pytest.raises(ValueError, match="Dynamic DNS is not set up"):
        p.ddns_update()


def test_the_settings_are_read_through_the_login_by_their_pairs():
    login = Pairs(settings_of(ddns=True, AZURE_DDNS_MINUTES="15"))
    c = read(login)
    assert (c.tenant, c.client_id, c.client_secret, c.subscription, c.minutes, c.hosts) == \
        (TENANT, CLIENT, SECRET, SUB, 15.0, ("new.example.com",))
    assert c.api_ready and c.ddns_ready and c.problems == ()
    assert "azure-client-secret" in login.asked and "AZURE_CLIENT_SECRET" not in login.asked  # asked by the pairs' names
    assert SECRET not in repr(c) and TENANT not in repr(c) and SUB not in repr(c)
    bad = read(Pairs(settings_of(AZURE_SUBSCRIPTION_ID="my-sub", AZURE_CLIENT_ID="not a guid", AZURE_DDNS_MINUTES="x")))
    assert not bad.api_ready and len(bad.problems) == 3 and "my-sub" not in " ".join(bad.problems)
    assert read(Pairs(settings_of(AZURE_TENANT_ID="contoso.onmicrosoft.com"))).tenant == "contoso.onmicrosoft.com"
    half = read(Pairs({"AZURE_TENANT_ID": TENANT, "AZURE_CLIENT_ID": CLIENT}))
    assert half.incomplete == ("AZURE_CLIENT_SECRET and AZURE_SUBSCRIPTION_ID are not set (the API needs all four)",)

    class Down(Pairs):
        def names(self):
            raise ConnectionError("the login app is not answering")
    assert read(Down({})).problems == ("the settings could not be read from the login: ConnectionError",)


def test_set_halfway_is_not_valid_and_says_what_is_missing(made, env):
    env({"AZURE_TENANT_ID": TENANT, "AZURE_CLIENT_ID": CLIENT})
    p, fake = made()
    st = p.status()
    assert st["present"] is True and st["valid"] is False and "AZURE_CLIENT_SECRET and AZURE_SUBSCRIPTION_ID" in st["why"]
    assert st["summary"] == "set up halfway" and st["actions"] == [] and fake.requests == []


def test_a_refresh_draws_the_tables_and_the_status_asks_nothing(made, env):
    env(settings_of(ddns=True))
    p, fake = made()
    st = p.status()
    assert st["valid"] is True and st["summary"].startswith("the subscription is read once attached")
    assert [t["title"] for t in st["tables"]] == ["Dynamic DNS"] and st["forms"] == []
    done = p.refresh()
    assert (done["vms"], done["zones"], done["nsgs"], done["troubles"]) == (2, 1, 2, {})
    calls = len(fake.requests)
    st = p.status()
    assert len(fake.requests) == calls  # the status asks nothing of Azure
    assert st["valid"] is True and "problem" not in st
    assert st["summary"] == "2 VMs (1 running) · 1 DNS zone · 12.35 USD this month · Dynamic DNS: checked once attached"
    assert (st["subscription"], st["offer"], st["spendingLimit"]) == ("Pay-As-You-Go (Enabled)", "PayAsYouGo_2014-09-01", "Off")
    assert st["costThisMonth"].startswith("12.35 USD so far") and st["billing"] == BILLING
    assert st["settingsSet"] == "AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID, AZURE_DDNS_HOSTS"
    t = tables(st)
    assert list(t) == ["Dynamic DNS", "Virtual machines", "Network security groups", "subnet-nsg rules", "web1-nsg rules",
                       "DNS zones", "example.com records", "SSH public keys", "Public IP addresses", "Disks",
                       "Resource groups", "Other resources"]
    vms = t["Virtual machines"]
    web1, win1 = vms["rows"]
    assert web1[:3] == [{"text": "web1", "sub": "web-rg · eastus"}, {"text": "running", "sub": "compute billed"},
                        {"text": "Standard_B1s", "sub": "Linux · ubuntu-24_04-lts server"}]
    assert web1[3] == {"text": "0.0104 USD an hour", "sub": "about 7.59 USD a month"} and web1[4] == "20.1.2.3"
    assert win1[1] == {"text": "deallocated", "sub": "compute not billed"} and win1[3]["text"] == "0.1880 USD an hour"  # Windows'
    assert "still billed" in vms["note"] and "deallocated is not" in vms["note"]
    assert [c["title"] for c in web1[7:] if c] == ["Restart", "Deallocate", "Power off"] and [c["title"] for c in win1[7:] if c] == ["Start"]
    nsg = t["web1-nsg rules"]
    assert nsg["rows"][0][:8] == ["300", "allow-ssh-home", "Inbound", "Allow", "Tcp", "22", "203.0.113.0/24", "any"]
    assert nsg["rows"][-1][1] == {"text": "DenyAllInBound", "sub": "default"} and nsg["rows"][-1][-1] == ""  # no Remove
    assert "attached to web1" in nsg["note"] and nsg["actions"] == [{"form": "rule-add:web-rg/web1-nsg", "title": "Add a rule…"}]
    assert t["Network security groups"]["rows"][0][:3] == [{"text": "subnet-nsg", "sub": "web-rg · eastus"}, "0", "web1, win1"]
    records = t["example.com records"]
    shown = [(r[0], r[1], r[2] if isinstance(r[2], str) else r[2]["text"]) for r in records["rows"]]
    assert ("@", "TXT", "v=spf1 include:spf.protection.outlook.com -all") in shown and ("lb", "A", "alias of spare-ip") in shown
    removable = {(r[0], r[1]) for r in records["rows"] if r[-1]}
    assert ("@", "NS") not in removable and ("@", "SOA") not in removable and ("lb", "A") not in removable
    assert ("@", "A") in removable and ("www", "CNAME") in removable
    assert t["DNS zones"]["rows"][0][1] == "8 of 10000"
    assert t["SSH public keys"]["rows"][0][2].startswith("ssh-ed25519 256 bits · SHA256:")
    ips = {r[0]["text"]: r for r in t["Public IP addresses"]["rows"]}
    assert ips["web1-ip"][5] == "VM web1" and ips["spare-ip"][5] == "not attached" and ips["win1-ip"][1] == "–"
    assert t["Disks"]["rows"][0][:5] == [{"text": "old-data", "sub": "web-rg"}, "64", "Standard_LRS", "Unattached", "–"]
    assert t["Resource groups"]["rows"] == [["dns-rg", "westus2", "Succeeded", "1"], ["web-rg", "eastus", "Succeeded", "6"]]
    assert t["Other resources"]["rows"] == [["network interfaces", "2"], ["virtual networks", "1"], ["storage accounts", "1"]]
    assert st["actions"] == [{"hook": "refresh", "args": [], "title": "Refresh",
                              "note": "the subscription read again now (a dozen requests or so)"},
                             {"form": "ddns-now", "title": "Update DNS now"}]  # confirmed: a form, no longer one click
    text = json.dumps(st)
    for value in (SECRET, TENANT, CLIENT, SUB):
        assert value not in text  # the settings by name, never a value


def test_a_part_that_fails_is_said_under_its_table_and_the_rest_is_read(made, env):
    env(settings_of())
    fake = FakeAzure()
    fake.fail["disks"] = (403, "AuthorizationFailed", f"The client '{CLIENT}' with object id 'x' does not have authorization to "
                          f"perform action 'Microsoft.Compute/disks/read' over scope '/subscriptions/{SUB}'.")
    fake.fail["states"] = (500, "InternalServerError", "An unexpected error occurred.")
    p, fake = made(fake)
    done = p.refresh()
    assert set(done["troubles"]) == {"disks", "states"}
    st = p.status()
    t = tables(st)
    assert st["valid"] is True and t["Disks"]["note"].startswith("not read: GET /subscriptions/•••/providers/Microsoft.Compute/disks: "
                                                                 "HTTP 403: the service principal has no role allowing this")
    assert CLIENT not in t["Disks"]["note"] and SUB not in t["Disks"]["note"]
    assert "power states not read" in t["Virtual machines"]["note"] and len(t["Virtual machines"]["rows"]) == 2
    # a VM whose power state the list did not give is asked one by one
    assert sum(1 for r in fake.requests if r["path"].endswith("/instanceView")) == 2  # the list failing: asked one by one
    fake.fail.clear()
    fake.status_only = False
    calls = len(fake.requests)
    p.refresh()
    t = tables(p.status())
    assert t["Virtual machines"]["rows"][0][1]["text"] == "running" and "2 power states asked one by one" in t["Virtual machines"]["note"]
    assert sum(1 for r in fake.requests[calls:] if r["path"].endswith("/instanceView")) == 2


def test_the_api_failing_is_not_valid_and_is_tried_again_later_when_detached(made, env):
    env(settings_of())
    t = [1_000_000.0]
    p, fake = made()
    p._clock = lambda: t[0]
    fake.fail["token"] = (401, "invalid_client", "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent "
                          "in the request is the client secret value, not the client secret ID.")
    with pytest.raises(Exception, match="AZURE_CLIENT_SECRET is not a secret of this app"):
        p.refresh()
    st = p.status()
    assert st["valid"] is False and st["why"].startswith("the API: POST /•••/oauth2/v2.0/token: HTTP 401: AZURE_CLIENT_SECRET")
    assert "Trace ID" not in st["why"] and TENANT not in st["why"] and SECRET not in json.dumps(st)
    t[0] += RETRY_S
    st = p.status()
    assert st["valid"] is True and st["summary"] == "the subscription is read once attached"  # the platform attaches it: tried again


def test_a_subscription_not_found_is_said_in_words(made, env):
    env(settings_of())
    fake = FakeAzure()
    fake.fail["subscription"] = (404, "SubscriptionNotFound", f"The subscription '{SUB}' could not be found.")
    p, fake = made(fake)
    with pytest.raises(Exception):
        p.refresh()
    st = p.status()
    assert st["valid"] is False and "AZURE_SUBSCRIPTION_ID names no subscription this service principal can see" in st["why"]
    assert SUB not in st["why"]


def test_a_change_of_the_settings_makes_a_failed_read_untried_and_drops_what_was_read(made, env, monkeypatch):
    env(settings_of())
    p, fake = made()
    p.refresh()
    assert p.snapshot() is not None
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "99999999-90ab-cdef-1234-567890abcdef")
    p.settings_changed()
    st = p.status()
    assert p.snapshot() is None and st["valid"] is True and st["summary"] == "the subscription is read once attached"
    assert "subscription" not in st and st["forms"] == []  # nothing of the other subscription shown


def test_attached_it_reads_in_the_background_through_the_apps_login_and_detached_nothing_runs(made):
    p, fake = made()
    login = Pairs(settings_of(ddns=True))
    p.attach(Platform(), login)
    try:
        assert p.working
        assert wait_until(lambda: p.status()["summary"] == f"2 VMs (1 running) · 1 DNS zone · 12.35 USD this month · "
                                                          f"new.example.com at {HOME}")
        assert "azure-client-secret" in login.asked
        assert fake.record("new", "A")["ARecords"] == [{"ipv4Address": HOME}]  # Dynamic DNS through Azure DNS
    finally:
        p.detach()
    assert not p.working and p.login is None
    calls = len(fake.requests)
    time.sleep(0.1)
    assert len(fake.requests) == calls


def test_a_power_change_reads_the_states_again_soon(made, monkeypatch):
    import plugin_platform_azure as module

    monkeypatch.setattr(module, "SOON_S", 0.0)
    p, fake = made()
    p.attach(Platform(), Pairs(settings_of()))
    try:
        assert wait_until(lambda: p.snapshot() is not None)
        p.power("web-rg", "win1", "start", accept_costs=True)
        assert wait_until(lambda: p.snapshot().vm("web-rg", "win1")["power"] == "running")
    finally:
        p.detach()


def test_a_read_failing_for_a_passing_reason_leaves_it_valid_and_says_so(made, env):
    """The audit: one failed read (a 503, a dropped connection) made the plugin not valid, the platform detached it, and
    Dynamic DNS stopped until a page asked again. A passing failure leaves it valid, with the last read's tables, the
    failure said as a problem, and is tried again soon; a refusal (a role missing) is still not valid."""
    env(settings_of(ddns=True))
    p, fake = made()
    p.refresh()
    for status, code in ((503, "ServiceUnavailable"), (500, "InternalServerError"), (429, "TooManyRequests")):
        fake.fail["subscription"] = (status, code, "Azure is busy.")
        with pytest.raises(Exception):
            p.refresh()
        st = p.status()
        assert st["valid"] is True and "the last read failed" in st["problem"] and "tried again within minutes" in st["problem"]
        assert "Virtual machines" in tables(st) and st["summary"].endswith("the last read failed: tried again soon")
    fake.fail["subscription"] = (403, "AuthorizationFailed", "The client does not have authorization.")
    with pytest.raises(Exception):
        p.refresh()
    st = p.status()
    assert st["valid"] is False and "the service principal has no role" in st["why"]
    fake.fail.clear()
    p.refresh()
    assert p.status()["valid"] is True and "problem" not in p.status()


def test_a_connection_lost_on_the_first_read_is_tried_again_soon_in_the_background(made, monkeypatch):
    import plugin_platform_azure as module

    monkeypatch.setattr(module, "RETRY_SOON_S", 0.05)
    p, fake = made()
    real = fake.answer
    lost = {"n": 4}  # more than the client's own two tries again: the first refresh fails, the worker's next one works

    def drops(method, host, path, query, headers, data):
        if host == "management.azure.com" and lost["n"] > 0 and path.endswith(SUB):
            lost["n"] -= 1
            raise ConnectionError("the connection was reset")
        return real(method, host, path, query, headers, data)
    fake.answer = drops
    p.attach(Platform(), Pairs(settings_of()))
    try:
        assert wait_until(lambda: p.snapshot() is not None, 10.0)  # tried again by itself, still attached
        assert p.status()["valid"] is True and lost["n"] == 0 and p.working
        asked = [r for r in fake.requests if r["host"] == "management.azure.com" and r["path"].endswith(SUB)]
        assert len(asked) == 5  # three tries of the first refresh dropped, then the worker's next refresh: one dropped, one answered
    finally:
        p.detach()


def test_the_reading_starts_only_when_the_platform_attaches_it(made):
    """The charts app run alone attaches every plugin it finds: by it, nothing of the plugin runs on its own."""
    p, fake = made()

    class Charts:
        NAME = "charts"
    for app in (object(), Charts()):
        p.attach(app, Pairs(settings_of(ddns=True)))
        try:
            assert not p.working
            time.sleep(0.1)
            assert fake.requests == []
        finally:
            p.detach()
    p.attach(Platform(), Pairs(settings_of()))
    try:
        assert p.working and wait_until(lambda: p.snapshot() is not None)
    finally:
        p.detach()
    assert not p.working


def test_the_hooks_are_asked_by_name_as_the_platform_asks_them(made, env):
    env(settings_of())
    p, fake = made()
    assert [v["name"] for v in p.ask("vms")] == ["web1", "win1"]
    assert [z["name"] for z in p.ask("zones")] == ["example.com"]
    sets = p.ask("records", "example.com")
    assert {"zone": "example.com", "group": "dns-rg", "name": "@", "type": "MX", "ttl": 3600, "values": ["10 mail.example.com"],
            "alias": "", "fqdn": "example.com."} in sets
    assert [g["name"] for g in p.ask("nsgs")] == ["subnet-nsg", "web1-nsg"]
    assert p.ask("ssh_keys")[0]["name"] == "laptop"
    with pytest.raises(ValueError, match="has not been read yet"):
        p.ask("power", "web-rg", "web1", "restart")  # a change names what it changes as last read
    p.ask("refresh")
    assert p.ask("power", "web-rg", "web1", "restart")["said"] == "web1 is being restarted"
    with pytest.raises(LookupError):
        p.ask("setup")
    with pytest.raises(ValueError, match="none of the subscription's VMs"):
        p.ask("power", "web-rg", "nope", "start")


def test_the_command_line(made, env):
    env(settings_of(ddns=True))
    p, fake = made()
    lines, errors, answers = [], [], []

    def run(*argv, say=()):
        lines.clear()
        errors.clear()
        answers[:] = list(say)
        return cli.main(list(argv), plugin=p, out=lines.append, err=errors.append, ask=lambda prompt: answers.pop(0) if answers else "")
    assert run("servers") == 0 and lines[0].startswith("web1") and "running" in lines[0] and lines[-1] == BILLING
    assert run("domains") == 0 and lines[0].startswith("example.com")
    assert run("records", "example.com") == 0 and any("v=spf1" in x for x in lines)
    assert run("firewalls") == 0 and lines[0].startswith("subnet-nsg") and any("allow-ssh-home: Allow inbound Tcp" in x for x in lines)
    assert run("keys") == 0 and lines[0].startswith("laptop")
    assert run("groups") == 0 and run("disks") == 0 and run("ips") == 0
    assert run("cost") == 0 and lines == [lines[0]] and lines[0].startswith("12.35 USD this month so far")
    assert run("ddns") == 0 and lines[0].startswith("new.example.com") and HOME in lines[0]
    assert run("--json", "ddns", "--now") == 0 and json.loads("\n".join(lines))[0]["ok"] is True
    assert run("power", "win1", "on") == 1 and errors == ["nothing done"] and fake.vms["win1"]["power"] == "deallocated"
    assert run("power", "win1", "on", say=["yes"]) == 1 and fake.vms["win1"]["power"] == "deallocated"  # its charge: asked again
    assert any("STARTS ITS COMPUTE CHARGE AGAIN" in x for x in lines)
    assert run("power", "win1", "on", say=["yes", "yes"]) == 0 and fake.vms["win1"]["power"] == "running"
    assert run("power", "web1", "poweroff", say=["yes"]) == 1 and fake.vms["web1"]["power"] == "running"  # asked twice
    assert run("power", "web1", "poweroff", say=["yes", "yes"]) == 0 and fake.vms["web1"]["power"] == "stopped"
    assert any("STILL BILLED" in x for x in lines)
    assert run("set", "example.com", "blog", "A", "203.0.113.5", say=["yes"]) == 0 and "added blog A 203.0.113.5" in lines
    assert fake.record("blog", "A")["ARecords"] == [{"ipv4Address": "203.0.113.5"}]
    assert run("remove", "example.com", "blog", "A", "203.0.113.5", say=["yes"]) == 0 and fake.record("blog", "A") is None
    assert run("status") == 0 and json.loads("\n".join(lines))["valid"] is True
    fake.fail["vms"] = (403, "AuthorizationFailed", "no")
    fake.fail["subscription"] = (403, "AuthorizationFailed", "The client does not have authorization.")
    assert run("servers") == 1 and errors[0].startswith("azure: GET /subscriptions/•••: HTTP 403: the service principal has no role")
    with pytest.raises(SystemExit):
        run("nonsense")


def test_the_platform_reads_it_in_its_own_shape(made, env):
    """What the platform's page draws: facts as words, tables of columns and rows, actions it asks by name."""
    env(settings_of(ddns=True))
    p, fake = made()
    p.refresh()
    st = p.status()
    for t in st["tables"]:
        assert set(t) >= {"title", "columns", "rows"} and all(len(r) == len(t["columns"]) for r in t["rows"]), t["title"]
    hooks = p.interface()["hooks"]
    forms = {f["id"] for f in st["forms"]}
    assert all(a["hook"] in hooks if "hook" in a else a["form"] in forms for a in st["actions"])
    assert all(f["hook"] in hooks for f in st["forms"])
    flat = {k: v for k, v in st.items() if not isinstance(v, (list, dict))}
    assert all(isinstance(v, (str, bool)) for v in flat.values())


def test_settings_entered_on_the_platforms_page_are_read_at_once(made):
    from liminal_libs.apps import EnvironmentLogin

    p, fake = made()
    kept: dict[str, str] = {}
    p.login = EnvironmentLogin(env=kept)  # as the platform lends its login to a plugin not yet attached
    assert p.status()["valid"] is False
    for variable, value in settings_of().items():
        p.login.save(variable, value)  # what the platform's settings route does
    assert p.status()["valid"] is False  # still the settings read a moment ago
    p.settings_changed()
    st = p.status()
    assert st["valid"] is True and "AZURE_CLIENT_SECRET" in st["settingsSet"] and SECRET not in str(st)
