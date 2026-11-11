"""Microsoft Azure's APIs as their references give them (read 2026-11-11), through the library's RestClient:

- the Microsoft identity platform's token endpoint (https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token): the
  client credentials grant, form-encoded (client_id, scope https://management.azure.com/.default, client_secret,
  grant_type client_credentials), answered with a bearer token and its expires_in; kept by the library's TokenSource
  until a minute before it ends;
- Azure Resource Manager (https://management.azure.com): every request bearing that token and naming its api-version (each
  resource provider has its own); a list answers {"value": [...], "nextLink": ...}; a change of a VM's power is accepted
  (202) and done by Azure after; an error is a CloudError {"error": {"code", "message", "details"}}; what is left of the
  rate limits comes back in the x-ms-ratelimit-remaining-* headers (kept by the client: the API's facts);
- Azure DNS (the Microsoft.Network/dnszones provider of Resource Manager, API 2018-05-01): zones, record sets read, set and
  deleted whole with their etag;
- the Azure Retail Prices API (https://prices.azure.com/api/retail/prices): public, unauthenticated; a VM size's price an
  hour in a region.

Only what the plugin uses is here. Every change goes through `_write`, which sends nothing but the free changes in WRITES:
a VM started, restarted, deallocated or powered off, a DNS record set written or deleted, a security rule added or
removed, an SSH public key resource added or removed. Nothing that creates, resizes, restores or destroys a billable
thing: those calls are named on the API card (card.py) alone."""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from urllib.parse import quote, urlsplit

from liminal_libs.machines.rest import Answer, RestClient, RestError, TokenSource, bearer

from . import records as recs
from . import rules as nsg_rules

MANAGEMENT = "https://management.azure.com"
LOGIN = "https://login.microsoftonline.com"  # the global Azure cloud's (Microsoft Entra ID's) sign-in host
PRICES = "https://prices.azure.com"
SCOPE = "https://management.azure.com/.default"  # Resource Manager's application ID URI with /.default
# the api-version of each resource provider the plugin asks (each reference's version, read 2026-11-11)
V_SUBSCRIPTIONS = "2022-12-01"  # Microsoft.Resources: Subscriptions - Get
V_RESOURCES = "2021-04-01"  # Microsoft.Resources: Resource Groups - List, Resources - List
V_COMPUTE = "2026-04-01"  # Microsoft.Compute: Virtual Machines, SSH Public Keys
V_DISKS = "2026-03-02"  # Microsoft.Compute: Disks
V_NETWORK = "2026-01-01"  # Microsoft.Network: Network Interfaces, Public IP Addresses, Network Security Groups, Security Rules
V_DNS = "2018-05-01"  # Microsoft.Network: Azure DNS (zones, record sets)
V_COST = "2026-06-01"  # Microsoft.CostManagement: Query - Usage
V_PRICES = "2023-01-01-preview"  # the Retail Prices API (filters case sensitive)
TIMEOUT_S = 30.0
PAGES_MOST = 20  # a list's pages asked at most (Resource Manager gives up to 1,000 items a page)
HOURS_A_MONTH = 730.0  # a month's hours on average (365 × 24 / 12): an hourly price as a month's

# -- the paths (templates: the API card names its calls by them, and a test compares the two) ---------------------------------
SUBSCRIPTION = "/subscriptions/{subscriptionId}"
GROUPS = SUBSCRIPTION + "/resourcegroups"
RESOURCES = SUBSCRIPTION + "/resources"
VMS = SUBSCRIPTION + "/providers/Microsoft.Compute/virtualMachines"
VM = SUBSCRIPTION + "/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}"
VM_VIEW = VM + "/instanceView"
VM_START, VM_RESTART, VM_DEALLOCATE, VM_POWER_OFF = VM + "/start", VM + "/restart", VM + "/deallocate", VM + "/powerOff"
DISKS = SUBSCRIPTION + "/providers/Microsoft.Compute/disks"
SSH_KEYS = SUBSCRIPTION + "/providers/Microsoft.Compute/sshPublicKeys"
SSH_KEY = SUBSCRIPTION + "/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/sshPublicKeys/{sshPublicKeyName}"
NICS = SUBSCRIPTION + "/providers/Microsoft.Network/networkInterfaces"
PUBLIC_IPS = SUBSCRIPTION + "/providers/Microsoft.Network/publicIPAddresses"
NSGS = SUBSCRIPTION + "/providers/Microsoft.Network/networkSecurityGroups"
NSG = SUBSCRIPTION + "/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkSecurityGroups/{networkSecurityGroupName}"
RULE = (SUBSCRIPTION + "/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkSecurityGroups/"
        "{networkSecurityGroupName}/securityRules/{securityRuleName}")
COST = SUBSCRIPTION + "/providers/Microsoft.CostManagement/query"
ZONES = SUBSCRIPTION + "/providers/Microsoft.Network/dnszones"
ZONE_ALL = SUBSCRIPTION + "/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnsZones/{zoneName}/all"
RECORD_SET = (SUBSCRIPTION + "/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnsZones/{zoneName}/"
              "{recordType}/{relativeRecordSetName}")
TOKEN = "/{tenant}/oauth2/v2.0/token"
RETAIL = "/api/retail/prices"

VM_ACTIONS = {"start": VM_START, "restart": VM_RESTART, "deallocate": VM_DEALLOCATE, "powerOff": VM_POWER_OFF}
# the only changes the plugin sends (method, path): each costs nothing (a VM's start bills its compute again from then on)
WRITES = frozenset({("POST", VM_START), ("POST", VM_RESTART), ("POST", VM_DEALLOCATE), ("POST", VM_POWER_OFF),
                    ("PUT", RECORD_SET), ("DELETE", RECORD_SET), ("PUT", RULE), ("DELETE", RULE),
                    ("PUT", SSH_KEY), ("DELETE", SSH_KEY)})
READS_BY_POST = frozenset({COST})  # a read asked by POST: Cost Management's query
USED = (  # every call the client makes, as the API card names them (method, path template, the Api it belongs to)
    ("POST", TOKEN, "identity"), ("GET", SUBSCRIPTION, "arm"), ("GET", GROUPS, "arm"), ("GET", RESOURCES, "arm"),
    ("GET", VMS, "arm"), ("GET", VM_VIEW, "arm"), ("POST", VM_START, "arm"), ("POST", VM_RESTART, "arm"),
    ("POST", VM_DEALLOCATE, "arm"), ("POST", VM_POWER_OFF, "arm"), ("GET", DISKS, "arm"), ("GET", SSH_KEYS, "arm"),
    ("GET", SSH_KEY, "arm"), ("PUT", SSH_KEY, "arm"), ("DELETE", SSH_KEY, "arm"), ("GET", NICS, "arm"),
    ("GET", PUBLIC_IPS, "arm"), ("GET", NSGS, "arm"), ("GET", NSG, "arm"), ("PUT", RULE, "arm"), ("DELETE", RULE, "arm"),
    ("POST", COST, "arm"), ("GET", ZONES, "dns"),
    ("GET", ZONE_ALL, "dns"), ("GET", RECORD_SET, "dns"), ("PUT", RECORD_SET, "dns"), ("DELETE", RECORD_SET, "dns"),
    ("GET", RETAIL, "prices"),
)
# the subscription not registered for a provider: nothing of it was ever made there, so a list of it is empty. Not
# NoRegisteredProviderFound: Resource Manager also answers it for an API version it does not serve, which is a fault to
# show, never "nothing there" (the audit, 2026-11-11)
NOT_REGISTERED = frozenset({"MissingSubscriptionRegistration"})

# Resource Manager's error codes (its troubleshooting page) in words of what to do; Azure's own words follow them
ADVICE = {
    "AuthorizationFailed": "the service principal has no role allowing this: assign it the plugin's role on the subscription "
                           "(the README's), Access control (IAM) > Add role assignment",
    "SubscriptionNotFound": "AZURE_SUBSCRIPTION_ID names no subscription this service principal can see",
    "ResourceGroupNotFound": "the resource group is not in the subscription (any more): Refresh",
    "ResourceNotFound": "it is not in the subscription (any more): Refresh",
    "MissingSubscriptionRegistration": "the subscription is not registered for this resource provider",
    "NoRegisteredProviderFound": "the subscription is not registered for this resource provider (or the API version)",
    "Conflict": "Azure refused it in the resource's current state",
}
# the Microsoft identity platform's error codes (its reference) in words of what to do
TOKEN_ADVICE = {
    "AADSTS7000215": "AZURE_CLIENT_SECRET is not a secret of this app: its Value (not its ID), from Certificates & secrets",
    "AADSTS7000222": "the client secret has expired: make a new one under Certificates & secrets",
    "AADSTS700016": "AZURE_CLIENT_ID names no app in this tenant",
    "AADSTS90002": "AZURE_TENANT_ID names no tenant",
    "AADSTS7000112": "the app is disabled in Microsoft Entra ID",
}


def arm_words(answer: Answer) -> tuple[str, str]:
    """A CloudError in words ({"error": {"code", "message", "details"}}), with what to do for the codes known."""
    data = answer.data
    err = data.get("error") if isinstance(data, Mapping) else None
    if not isinstance(err, Mapping):
        if answer.status == 412:
            return "it changed since it was read (its etag): Refresh and try again", "PreconditionFailed"
        return "", ""
    code = str(err.get("code") or "")
    message = " ".join(str(err.get("message") or "").split())
    if not message:
        details = [str(d.get("message")) for d in (err.get("details") or []) if isinstance(d, Mapping) and d.get("message")]
        message = "; ".join(details[:3])
    if answer.status == 412 and code in ("", "PreconditionFailed"):
        return "it changed since it was read (its etag): Refresh and try again", code or "PreconditionFailed"
    advice = ADVICE.get(code, "")
    words = f"{advice} ({code}: {message})" if advice and message else advice or (f"{code}: {message}" if code else message)
    return words, code


def token_words(answer: Answer) -> tuple[str, str]:
    """The token endpoint's error in words ({"error", "error_description", "error_codes"}), its first line only (the
    trace and correlation IDs left out), with what to do for the codes known."""
    data = answer.data if isinstance(answer.data, Mapping) else {}
    first = str(data.get("error_description") or "").replace("\r", "\n").split("\n")[0].strip()
    code = first.split(":", 1)[0] if first.startswith("AADSTS") else ""
    advice = TOKEN_ADVICE.get(code, "")
    words = f"{advice} ({first})" if advice and first else advice or first or str(data.get("error") or "")
    return words, str(data.get("error") or code)


def quoted(value: str) -> str:
    """A name in a path: its characters Azure's names hold kept, every other one escaped (nothing can leave its segment)."""
    return quote(str(value), safe="@*()._-~")


def path_of(template: str, **values: str) -> str:
    return template.format(**{k: quoted(v) for k, v in values.items()})


def group_of(resource_id: str) -> str:
    """The resource group named in a resource ID ("" when none is)."""
    parts = str(resource_id or "").split("/")
    for i, p in enumerate(parts[:-1]):
        if p.lower() == "resourcegroups":
            return parts[i + 1]
    return ""


def name_of(resource_id: str) -> str:
    return str(resource_id or "").rstrip("/").rsplit("/", 1)[-1]


def key_of(resource_id: str) -> str:
    """A resource ID as compared (Azure's IDs are case-insensitive)."""
    return str(resource_id or "").rstrip("/").lower()


def parent_of(resource_id: str, child: str) -> str:
    """The ID a child's ID is under (a NIC's of its IP configuration: parent_of(id, "ipConfigurations"))."""
    lower = str(resource_id or "").lower()
    at = lower.find(f"/{child.lower()}/")
    return key_of(resource_id[:at]) if at >= 0 else key_of(resource_id)


class AzureApi:
    """Azure's APIs with a service principal's credentials (`cfg`, settings.Config): a RestClient for each API (its facts
    its own), one token for Resource Manager and Azure DNS. `transport` is a test's stand-in (RestClient's)."""

    def __init__(self, cfg, transport: Callable | None = None, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep):
        self.cfg = cfg
        self.subscription = cfg.subscription
        secrets = cfg.secrets
        self.token_at: float | None = None  # when the token held was given, and how long it lasts
        self.token_lasts: float = 0.0
        self._clock = clock
        common = {"transport": transport, "secrets": secrets, "timeout": TIMEOUT_S, "clock": clock, "sleep": sleep}
        self.login = RestClient(LOGIN, error=token_words, **common)
        self.token = TokenSource(self._fetch_token, clock=clock)
        borne = {"auth": bearer(self.token), "on_refused": self.token.forget, "error": arm_words, **common}
        self.arm = RestClient(MANAGEMENT, **borne)
        self.dns = RestClient(MANAGEMENT, **borne)
        self.costs = RestClient(MANAGEMENT, retries=0, **borne)  # Cost Management throttles hard: never asked twice
        self.prices = RestClient(PRICES, **common)

    # -- the token ----------------------------------------------------------------------------------------------------------
    def _fetch_token(self) -> tuple[str, float]:
        """A token for Resource Manager by the client credentials grant (the shared secret's case)."""
        data = self.login.post(path_of(TOKEN, tenant=self.cfg.tenant),
                               form={"client_id": self.cfg.client_id, "scope": SCOPE, "client_secret": self.cfg.client_secret,
                                     "grant_type": "client_credentials"})
        token = data.get("access_token") if isinstance(data, Mapping) else None
        if not token or str(data.get("token_type") or "Bearer").lower() != "bearer":
            raise RestError("the token endpoint answered without a bearer token")
        try:
            lasts = float(data.get("expires_in") or 3599)
        except (TypeError, ValueError):
            lasts = 3599.0
        self.token_at, self.token_lasts = self._clock(), lasts
        return str(token), lasts

    # -- reading ------------------------------------------------------------------------------------------------------------
    def path(self, template: str, **values: str) -> str:
        return path_of(template, subscriptionId=self.subscription, **values)

    def _list(self, client: RestClient, path: str, version: str, params: Mapping | None = None, most: int = PAGES_MOST) -> list:
        """Every item of a Resource Manager list across its pages (nextLink: followed on Resource Manager's own host
        alone, so the token goes nowhere else)."""
        def next_of(data, _params):
            link = data.get("nextLink") if isinstance(data, Mapping) else None
            if isinstance(link, str) and link.startswith(MANAGEMENT + "/"):
                return link, {}
            return None
        return list(client.pages(path, {"api-version": version, **(params or {})}, items="value", next_of=next_of, most=most))

    def _maybe_none(self, client: RestClient, path: str, version: str, params: Mapping | None = None) -> list:
        """A list that is empty when the subscription is not registered for its provider (nothing of it was ever made)."""
        try:
            return self._list(client, path, version, params)
        except RestError as e:
            if e.code in NOT_REGISTERED:
                return []
            raise

    def subscription_info(self) -> dict:
        return self.arm.get(self.path(SUBSCRIPTION), {"api-version": V_SUBSCRIPTIONS}) or {}

    def groups(self) -> list:
        return self._list(self.arm, self.path(GROUPS), V_RESOURCES)

    def resources(self) -> list:
        return self._list(self.arm, self.path(RESOURCES), V_RESOURCES, most=10)

    def vms(self) -> list:
        return self._maybe_none(self.arm, self.path(VMS), V_COMPUTE)

    def vm_statuses(self) -> list:
        """Every VM's run-time state at once (List All with statusOnly=true: "retrieves the power states of all VMs in a
        subscription")."""
        return self._maybe_none(self.arm, self.path(VMS), V_COMPUTE, {"statusOnly": "true"})

    def instance_view(self, group: str, name: str) -> dict:
        return self.arm.get(self.path(VM_VIEW, resourceGroupName=group, vmName=name), {"api-version": V_COMPUTE}) or {}

    def disks(self) -> list:
        return self._maybe_none(self.arm, self.path(DISKS), V_DISKS)

    def ssh_keys(self) -> list:
        return self._maybe_none(self.arm, self.path(SSH_KEYS), V_COMPUTE)

    def nics(self) -> list:
        return self._maybe_none(self.arm, self.path(NICS), V_NETWORK)

    def public_ips(self) -> list:
        return self._maybe_none(self.arm, self.path(PUBLIC_IPS), V_NETWORK)

    def nsgs(self) -> list:
        return self._maybe_none(self.arm, self.path(NSGS), V_NETWORK)

    def zones(self) -> list:
        return self._maybe_none(self.dns, self.path(ZONES), V_DNS)

    def record_sets(self, group: str, zone: str) -> list[recs.RecordSet]:
        items = self._list(self.dns, self.path(ZONE_ALL, resourceGroupName=group, zoneName=zone), V_DNS, most=10)
        return [recs.parse(zone, group, x) for x in items if isinstance(x, Mapping)]

    def record_set(self, group: str, zone: str, rtype: str, name: str) -> recs.RecordSet | None:
        """A record set as it is now (None: there is none)."""
        try:
            data = self.dns.get(self.path(RECORD_SET, resourceGroupName=group, zoneName=zone, recordType=rtype,
                                          relativeRecordSetName=name), {"api-version": V_DNS})
        except RestError as e:
            if e.status == 404:
                return None
            raise
        return recs.parse(zone, group, data) if isinstance(data, Mapping) else None

    def cost(self) -> dict:
        """The subscription's cost this month so far (Cost Management's query: Usage, month to date, its PreTaxCost
        summed): {amount, currency}."""
        body = {"type": "Usage", "timeframe": "MonthToDate",
                "dataset": {"granularity": "None", "aggregation": {"totalCost": {"name": "PreTaxCost", "function": "Sum"}}}}
        answer = self._read_post(COST, {"api-version": V_COST}, body)
        props = (answer.data or {}).get("properties") if isinstance(answer.data, Mapping) else None
        columns = [str(c.get("name") or "") for c in (props or {}).get("columns") or [] if isinstance(c, Mapping)]
        rows = (props or {}).get("rows") or []
        cost_at = next((i for i, c in enumerate(columns) if c.lower() in ("pretaxcost", "cost", "costusd")), None)
        currency_at = next((i for i, c in enumerate(columns) if c.lower() in ("currency", "billingcurrency")), None)
        amount, currency = 0.0, ""
        for row in rows:
            if isinstance(row, list) and cost_at is not None and cost_at < len(row):
                try:
                    amount += float(row[cost_at] or 0)
                except (TypeError, ValueError):
                    continue
                if currency_at is not None and currency_at < len(row):
                    currency = str(row[currency_at] or currency)
        return {"amount": amount, "currency": currency, "rows": len(rows)}

    def prices_of(self, region: str, size: str) -> list:
        """The Retail Prices API's pay-as-you-go prices of a VM size in a region (its primary meters): every item, Linux and
        Windows, spot and low priority among them (pick_price chooses)."""
        filt = (f"serviceName eq 'Virtual Machines' and armRegionName eq '{_odata(region)}' and "
                f"armSkuName eq '{_odata(size)}' and priceType eq 'Consumption'")
        url = (f"{PRICES}{RETAIL}?api-version={V_PRICES}&meterRegion={quote(chr(39) + 'primary' + chr(39), safe='')}"
               f"&$filter={quote(filt, safe='')}")

        def next_of(data, _params):
            link = data.get("NextPageLink") if isinstance(data, Mapping) else None
            if isinstance(link, str):
                parts = urlsplit(link)
                if parts.scheme == "https" and parts.hostname == "prices.azure.com" and parts.port in (None, 443):
                    # its own host, written as the reference's example writes it (prices.azure.com:443): asked as the base
                    return parts._replace(netloc="prices.azure.com").geturl(), {}
            return None
        return list(self.prices.pages(url, None, items="Items", next_of=next_of, most=5))

    def _read_post(self, template: str, params: Mapping, json) -> Answer:
        """A read asked by POST (READS_BY_POST alone: Cost Management's query; RuntimeError otherwise, nothing sent)."""
        if template not in READS_BY_POST:
            raise RuntimeError(f"POST {template} is not one of the plugin's reads: refused, nothing sent")
        return self.costs.request("POST", self.path(template), params=params, json=json)

    # -- the free changes ---------------------------------------------------------------------------------------------------
    def _write(self, method: str, template: str, values: Mapping[str, str], params: Mapping, json=None,
               headers: Mapping[str, str] | None = None, client: RestClient | None = None) -> Answer:
        """A change, sent only when it is one of WRITES (RuntimeError otherwise: nothing sent)."""
        if (method, template) not in WRITES:
            raise RuntimeError(f"{method} {template} is not one of the plugin's free changes: refused, nothing sent")
        return (client or self.arm).request(method, self.path(template, **values), params=params, json=json, headers=headers)

    def vm_action(self, group: str, name: str, action: str) -> Answer:
        """A VM started, restarted, deallocated or powered off (accepted: Azure does it after)."""
        if action not in VM_ACTIONS:
            raise ValueError(f"{action!r} is none of {', '.join(VM_ACTIONS)}")
        return self._write("POST", VM_ACTIONS[action], {"resourceGroupName": group, "vmName": name}, {"api-version": V_COMPUTE})

    def put_record_set(self, plan: recs.Plan) -> recs.RecordSet:
        """A record set written whole, if it is as it was read (If-Match its etag; a new one If-None-Match: *)."""
        headers = {"If-None-Match": "*"} if plan.new or not plan.etag else {"If-Match": plan.etag}
        answer = self._write("PUT", RECORD_SET, {"resourceGroupName": plan.group, "zoneName": plan.zone, "recordType": plan.type,
                                                 "relativeRecordSetName": plan.name}, {"api-version": V_DNS},
                             json=plan.body(), headers=headers, client=self.dns)
        data = answer.data if isinstance(answer.data, Mapping) else {"name": plan.name, "type": f"Microsoft.Network/dnszones/{plan.type}",
                                                                      "properties": plan.body()["properties"]}
        return recs.parse(plan.zone, plan.group, data)

    def delete_record_set(self, plan: recs.Plan) -> None:
        """A record set deleted, if it is as it was read (If-Match its etag)."""
        self._write("DELETE", RECORD_SET, {"resourceGroupName": plan.group, "zoneName": plan.zone, "recordType": plan.type,
                                           "relativeRecordSetName": plan.name}, {"api-version": V_DNS},
                    headers={"If-Match": plan.etag} if plan.etag else None, client=self.dns)

    def nsg(self, group: str, name: str) -> dict | None:
        """A network security group as it is now, its rules and what it is attached to (None: there is none)."""
        try:
            data = self.arm.get(self.path(NSG, resourceGroupName=group, networkSecurityGroupName=name), {"api-version": V_NETWORK})
        except RestError as e:
            if e.status == 404:
                return None
            raise
        return data if isinstance(data, Mapping) else None

    def put_rule(self, group: str, nsg: str, rule: nsg_rules.Rule) -> dict:
        """A new rule made, never one of its name replaced: If-None-Match: * (the caller has read the group just before
        and found no rule of that name)."""
        answer = self._write("PUT", RULE, {"resourceGroupName": group, "networkSecurityGroupName": nsg, "securityRuleName": rule.name},
                             {"api-version": V_NETWORK}, json=nsg_rules.body(rule), headers={"If-None-Match": "*"})
        return answer.data if isinstance(answer.data, Mapping) else {}

    def delete_rule(self, group: str, nsg: str, name: str) -> int:
        answer = self._write("DELETE", RULE, {"resourceGroupName": group, "networkSecurityGroupName": nsg, "securityRuleName": name},
                             {"api-version": V_NETWORK})
        return answer.status

    def ssh_key(self, group: str, name: str) -> dict | None:
        """An SSH public key resource as it is now (None: there is none)."""
        try:
            data = self.arm.get(self.path(SSH_KEY, resourceGroupName=group, sshPublicKeyName=name), {"api-version": V_COMPUTE})
        except RestError as e:
            if e.status == 404:
                return None
            raise
        return data if isinstance(data, Mapping) else None

    def put_ssh_key(self, group: str, name: str, location: str, public_key: str) -> dict:
        """A new key resource made, never one of its name replaced: If-None-Match: * (the caller has looked for one of that
        name just before and found none)."""
        answer = self._write("PUT", SSH_KEY, {"resourceGroupName": group, "sshPublicKeyName": name}, {"api-version": V_COMPUTE},
                             json={"location": location, "properties": {"publicKey": public_key}}, headers={"If-None-Match": "*"})
        return answer.data if isinstance(answer.data, Mapping) else {}

    def delete_ssh_key(self, group: str, name: str) -> int:
        return self._write("DELETE", SSH_KEY, {"resourceGroupName": group, "sshPublicKeyName": name}, {"api-version": V_COMPUTE}).status

    # -- what it learned ----------------------------------------------------------------------------------------------------
    def requests_made(self) -> int:
        return sum(c.seen.requests for c in (self.login, self.arm, self.dns, self.costs, self.prices))


def _odata(value: str) -> str:
    """A value inside an OData string literal (its quote doubled)."""
    return str(value).replace("'", "''")


def power_of(statuses: Iterable) -> tuple[str, str]:
    """A VM's power state (its PowerState/<state> status: running, stopped, deallocated ...) and Azure's words for it."""
    for s in statuses or []:
        code = str((s or {}).get("code") or "") if isinstance(s, Mapping) else ""
        if code.lower().startswith("powerstate/"):
            return code.split("/", 1)[1].lower(), str(s.get("displayStatus") or "")
    return "", ""


def statuses_of(item: Mapping) -> list:
    """The statuses of a VM in a List All statusOnly answer, or of an instanceView answer."""
    if not isinstance(item, Mapping):
        return []
    view = (item.get("properties") or {}).get("instanceView") if isinstance(item.get("properties"), Mapping) else None
    if not isinstance(view, Mapping):
        view = item.get("instanceView") if isinstance(item.get("instanceView"), Mapping) else item
    return list(view.get("statuses") or []) if isinstance(view, Mapping) else []


def pick_price(items: Iterable, windows: bool = False, spot: bool = False) -> dict | None:
    """The pay-as-you-go price an hour of a VM size (the Retail Prices API's items of it): Linux or Windows (a Windows
    product's name says Windows), regular or spot (a spot meter's name says Spot), never low priority."""
    def says(i, word):
        return word in f"{i.get('meterName') or ''} {i.get('skuName') or ''}".lower()
    found = []
    for i in items or []:
        if not isinstance(i, Mapping) or str(i.get("type") or "") != "Consumption":
            continue
        if str(i.get("unitOfMeasure") or "").lower() != "1 hour" or i.get("isPrimaryMeterRegion") is False:
            continue
        if says(i, "low priority") or says(i, "spot") != spot:
            continue
        if ("windows" in str(i.get("productName") or "").lower()) != windows:
            continue
        try:
            if float(i.get("tierMinimumUnits") or 0) != 0:
                continue
            float(i.get("retailPrice"))
        except (TypeError, ValueError):
            continue
        found.append(i)
    if not found:
        return None
    best = min(found, key=lambda i: float(i["retailPrice"]))
    return {"hour": float(best["retailPrice"]), "currency": str(best.get("currencyCode") or "USD"),
            "product": str(best.get("productName") or ""), "meter": str(best.get("meterName") or "")}
