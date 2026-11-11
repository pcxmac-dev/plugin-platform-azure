"""The plugin's API card (plugin API 2.2): each API it attaches to, with Microsoft's pages, every part (covered or not), the
calls the client makes and the notable others; the calls it names as used are exactly the client's; its facts come from
what the client already learned (no request made to answer them); its addresses answer (asked only with
LIMINAL_VENDOR_PAGES=1)."""
from __future__ import annotations

import json
import os

import pytest

import plugin_platform_azure.api as api_mod
from conftest import SECRET, SUB, TENANT, settings_of, ssh_key
from liminal_libs.sources.apis import dead_links, facts_of, problems
from plugin_platform_azure import MACHINE
from plugin_platform_azure.card import APIS, ARM_NAME, DNS_NAME, IDENTITY_NAME, PRICES_NAME

BY_API = {"arm": ARM_NAME, "dns": DNS_NAME, "prices": PRICES_NAME, "identity": IDENTITY_NAME}


def test_the_card_is_sound_and_names_each_api_it_attaches_to():
    assert problems(MACHINE.apis) == [] and MACHINE.apis is APIS
    assert [a.name for a in APIS] == [ARM_NAME, DNS_NAME, PRICES_NAME, IDENTITY_NAME]
    for a in APIS:
        assert a.maker == "Microsoft" and a.verified == "2026-11-11" and a.docs.startswith("https://learn.microsoft.com/")
        assert a.about and a.limits and a.auth and a.version and a.links[0].kind in ("docs", "reference", "guide")
        assert all(c.docs.startswith("https://") for c in a.calls if c.docs)
    arm = APIS[0]
    kinds = {x.kind for x in arm.links}
    assert {"docs", "reference", "guide", "limits", "pricing", "status", "changelog", "spec", "console", "tool", "sdk", "auth"} <= kinds
    assert "still" in arm.costs and "deallocated" in arm.costs  # a powered-off VM still bills: said
    assert len(arm.areas) > 3 * len(arm.covered)  # the rest of the API shown as such
    billable = {c.name for a in APIS for c in a.calls if c.costs}
    assert len(billable) >= 7
    # the one costing call it makes: a VM's start (a deallocated VM's compute charge starts again; its form says so)
    assert {c.name for a in APIS for c in a.used if c.costs} == {f"POST {api_mod.VM_START}"}
    start = next(c for c in arm.calls if c.name == f"POST {api_mod.VM_START}")
    assert "starts the compute charge again for a deallocated VM" in start.about


def test_the_calls_it_names_as_used_are_the_ones_the_client_makes():
    named = {(c.name, a.name) for a in APIS for c in a.used}
    made = {(f"{method} {path}", BY_API[api]) for method, path, api in api_mod.USED}
    assert named == made
    # and the client's changes are among them, each marked as one
    writes = {f"{m} {t}" for m, t in api_mod.WRITES}
    assert writes <= {c.name for a in APIS for c in a.used if c.writes}
    assert not any(c.writes for a in APIS for c in a.used if c.name.startswith("GET "))


def test_a_full_refresh_makes_only_the_calls_the_card_names(made, env):
    """Every request a refresh, a change and a Dynamic DNS pass send is one of the card's used calls."""
    import re

    env(settings_of(ddns=True))
    p, fake = made()
    p.refresh()
    p.ddns_update()
    p.power("web-rg", "web1", "restart")
    p.set_record("dns-rg", "example.com", "blog", "A", "203.0.113.5")
    p.remove_record("dns-rg", "example.com", "blog", "A", "203.0.113.5")
    p.add_rule("web-rg", "web1-nsg", "allow-dns", "Inbound", "Allow", "Udp", "53", "10.0.0.0/8", "*", 400)
    p.remove_rule("web-rg", "web1-nsg", "allow-dns")
    p.add_ssh_key("web-rg", "desk", ssh_key("ssh-rsa", 3072))
    p.remove_ssh_key("web-rg", "desk")

    def pattern(template: str) -> re.Pattern:
        return re.compile("^" + re.sub(r"\\\{[A-Za-z]+\\\}", "[^/]+", re.escape(template)) + "$")
    used = [(c.name.split(" ", 1)[0], pattern(c.name.split(" ", 1)[1])) for a in APIS for c in a.used]
    for r in fake.requests:
        assert any(m == r["method"] and pat.match(r["path"]) for m, pat in used), (r["method"], r["path"])
    hosts = {r["host"] for r in fake.requests}
    assert hosts == {"login.microsoftonline.com", "management.azure.com", "prices.azure.com"}


def test_its_facts_are_what_the_client_learned_without_asking(made, env):
    env(settings_of())
    p, fake = made()
    assert p.api_facts() == {} and facts_of(p) == {}
    p.refresh()
    calls = len(fake.requests)
    facts = facts_of(p)
    assert len(fake.requests) == calls  # nothing asked to answer them
    assert set(facts) == {ARM_NAME, DNS_NAME, PRICES_NAME, IDENTITY_NAME}
    arm = facts[ARM_NAME]
    assert arm["Reads left (subscription)"] == "249" and arm["Requests"].endswith("made") and arm["Last read"]
    assert arm["Cost this month"].startswith("12.35 USD")
    assert facts[IDENTITY_NAME]["Token"].endswith("lasting 60 min") and facts[DNS_NAME]["Zones read"] == "1 (8 record sets)"
    assert facts[PRICES_NAME]["Prices kept"] == "2 VM sizes, a day each"
    text = json.dumps(facts)
    assert SECRET not in text and TENANT not in text and SUB not in text


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="asks Microsoft's pages: LIMINAL_VENDOR_PAGES=1")
def test_every_address_on_the_card_answers():
    assert dead_links(MACHINE.apis) == []
