"""The client over the stand-ins: the token asked by the client credentials grant and kept, every Resource Manager request
bearing it and naming its api-version, a list followed across its pages on Resource Manager's own host alone, errors in
words with every setting's value taken out, the Retail Prices API's price chosen, the cost read."""
from __future__ import annotations

import pytest

from conftest import CLIENT, SECRET, SUB, TENANT, FakeAzure, cloud_error
from liminal_libs.machines.rest import RestError
from plugin_platform_azure.api import AzureApi, arm_words, pick_price, token_words
from plugin_platform_azure.settings import parse


def client(fake=None, clock=None):
    fake = fake or FakeAzure()
    cfg = parse({"AZURE_TENANT_ID": TENANT, "AZURE_CLIENT_ID": CLIENT, "AZURE_CLIENT_SECRET": SECRET, "AZURE_SUBSCRIPTION_ID": SUB})
    kw = {"clock": clock} if clock else {}
    return AzureApi(cfg, transport=fake, sleep=lambda s: None, **kw), fake


def test_the_token_is_asked_by_the_client_credentials_grant_and_kept_until_it_ends():
    now = [1_000_000.0]
    api, fake = client(clock=lambda: now[0])
    api.subscription_info()
    api.groups()
    token = fake.requests[0]
    assert (token["method"], token["host"], token["path"]) == ("POST", "login.microsoftonline.com", f"/{TENANT}/oauth2/v2.0/token")
    assert token["body"] == {"client_id": CLIENT, "scope": "https://management.azure.com/.default", "client_secret": SECRET,
                             "grant_type": "client_credentials"}
    assert fake.tokens == 1 and all(r["headers"]["Authorization"] == "Bearer eyJ0eXAi.stand-in-token-1" for r in fake.requests[1:])
    assert [r["query"]["api-version"] for r in fake.requests[1:]] == ["2022-12-01", "2021-04-01"]
    now[0] += 3599 - 59  # a minute before it ends: a new one
    api.groups()
    assert fake.tokens == 2 and fake.requests[-1]["headers"]["Authorization"].endswith("token-2")


def test_a_refused_token_is_asked_anew_and_errors_are_worded_without_a_value():
    fake = FakeAzure()
    api, _ = client(fake)
    api.groups()
    fake.fail["groups"] = (401, "InvalidAuthenticationToken", "The access token is invalid.")
    with pytest.raises(RestError) as e:
        api.groups()
    assert e.value.refused and fake.tokens == 1
    fake.fail.clear()
    api.groups()
    assert fake.tokens == 2  # forgotten on the refusal: a new one asked
    fake.fail["vms"] = (403, "AuthorizationFailed", f"The client '{CLIENT}' with object id '{CLIENT}' does not have authorization "
                        f"to perform action 'Microsoft.Compute/virtualMachines/read' over scope '/subscriptions/{SUB}' or the scope is invalid.")
    with pytest.raises(RestError) as e:
        api.vms()
    words = str(e.value)
    assert words.startswith("GET /subscriptions/•••/providers/Microsoft.Compute/virtualMachines: HTTP 403: the service principal "
                            "has no role allowing this")
    assert CLIENT not in words and SUB not in words and e.value.code == "AuthorizationFailed" and e.value.request_id == "req-0001"
    fake.fail["disks"] = (400, "BadRequest", f"echoed: client_secret={SECRET}")  # a secret an answer echoes is taken out too
    with pytest.raises(RestError) as e:
        api.disks()
    assert SECRET not in str(e.value) and "client_secret=•••" in str(e.value)


def test_a_provider_the_subscription_is_not_registered_for_reads_as_none():
    fake = FakeAzure()
    fake.fail["nsgs"] = (409, "MissingSubscriptionRegistration", "The subscription is not registered to use namespace 'Microsoft.Network'.")
    api, _ = client(fake)
    assert api.nsgs() == []


def test_a_list_is_followed_across_its_pages_on_resource_managers_host_alone():
    fake = FakeAzure()
    api, _ = client(fake)
    real = fake.route
    pages = {"n": 0}

    def paged(method, rest, query, headers, data):
        if rest == "/resourcegroups":
            pages["n"] += 1
            if "$skiptoken" not in query:
                return fake.ok({"value": fake.groups[:1], "nextLink": f"https://management.azure.com/subscriptions/{SUB}/resourcegroups"
                                                                      "?api-version=2021-04-01&$skiptoken=abc"})
            return fake.ok({"value": fake.groups[1:], "nextLink": "https://elsewhere.example.org/next?token=steal"})
        return real(method, rest, query, headers, data)
    fake.route = paged
    assert [g["name"] for g in api.groups()] == ["web-rg", "dns-rg"]
    assert pages["n"] == 2 and not any(r["host"] == "elsewhere.example.org" for r in fake.requests)  # the token goes nowhere else


def test_the_word_readers():
    from liminal_libs.machines.rest import Answer

    a = Answer(409, {}, b"", data={"error": {"code": "Conflict", "message": "Operation 'start' is not allowed."}})
    assert arm_words(a) == ("Azure refused it in the resource's current state (Conflict: Operation 'start' is not allowed.)", "Conflict")
    assert arm_words(Answer(412, {}, b"", data={"code": "PreconditionFailed"}))[0].startswith("it changed since it was read")
    t = Answer(400, {}, b"", data={"error": "invalid_request", "error_description": "AADSTS90002: Tenant 'x' not found.\r\nTrace ID: 1"})
    assert token_words(t) == ("AZURE_TENANT_ID names no tenant (AADSTS90002: Tenant 'x' not found.)", "invalid_request")


def test_a_vm_sizes_price_is_its_linux_or_windows_pay_as_you_go_one():
    api, fake = client()
    items = api.prices_of("eastus", "Standard_B1s")
    q = fake.requests[-1]
    assert q["host"] == "prices.azure.com" and "Authorization" not in q["headers"]
    assert q["query"]["$filter"] == ("serviceName eq 'Virtual Machines' and armRegionName eq 'eastus' and armSkuName eq "
                                     "'Standard_B1s' and priceType eq 'Consumption'")
    assert pick_price(items)["hour"] == 0.0104 and pick_price(items, windows=True)["hour"] == 0.0156
    assert pick_price(items, spot=True)["hour"] == 0.0021 and pick_price([], windows=True) is None
    reserved = [{**items[0], "type": "Reservation", "retailPrice": 50.0}, {**items[0], "type": "DevTestConsumption", "retailPrice": 0.001}]
    assert pick_price(reserved) is None  # pay as you go alone
    assert api.prices_of("eastus", "Standard_X'1")  == [] and "Standard_X''1" in fake.requests[-1]["query"]["$filter"]


def test_the_cost_this_month_is_read_from_cost_managements_query():
    api, fake = client()
    assert api.cost() == {"amount": 12.3456, "currency": "USD", "rows": 1}
    q = fake.requests[-1]
    assert (q["method"], q["path"], q["query"]) == ("POST", f"/subscriptions/{SUB}/providers/Microsoft.CostManagement/query",
                                                    {"api-version": "2026-06-01"})
    fake.fail["cost"] = (429, "429", "Too many requests. Please retry.")
    with pytest.raises(RestError) as e:
        api.cost()
    assert e.value.status == 429 and sum(1 for r in fake.requests if "CostManagement" in r["path"]) == 2  # never asked twice


def test_an_answer_azure_gives_without_a_body_is_said(monkeypatch):
    fake = FakeAzure()
    api, _ = client(fake)
    fake.fail["subscription"] = (503, "ServiceUnavailable", "busy")
    with pytest.raises(RestError) as e:
        api.subscription_info()
    assert e.value.status == 503 and "busy" in str(e.value)
    assert cloud_error(1, "a", "b")[2] == {"error": {"code": "a", "message": "b"}}
