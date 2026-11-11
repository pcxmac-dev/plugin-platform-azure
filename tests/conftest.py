"""Stand-ins for Azure: the tests never reach Microsoft, a resolver or the network. `FakeAzure` is a RestClient transport
answering the Microsoft identity platform's token endpoint, Resource Manager (Compute, Network, Azure DNS, Cost Management)
and the Retail Prices API from a subscription in memory, its answers laid out as the references' samples show them (a list's
{"value": [...]}, a CloudError {"error": {"code", "message"}}, a VM's power change accepted with 202 and a Location, a record
set written with its etag); every request kept (`requests`). `Pairs` is a Login holding pairs by name."""
from __future__ import annotations

import base64
import json
import re
import struct
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

import liminal_libs.dns as dns_mod
import liminal_libs.machines.rest as rest_mod
from liminal_libs.apps import Login, Unauthorized, pair_name
from plugin_platform_azure import AzurePlugin
from plugin_platform_azure.settings import NAMES

TENANT = "00000000-1111-2222-3333-444444444444"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SECRET = "Az8Q~stand-in-secret.0123456789abcdefghij"  # a stand-in client secret (no app's)
SUB = "12345678-90ab-cdef-1234-567890abcdef"
HOME = "93.184.216.34"  # this network's public address in the tests
VERSIONS = {"subscriptions": "2022-12-01", "resources": "2021-04-01", "compute": "2026-04-01", "disks": "2026-03-02",
            "network": "2026-01-01", "dns": "2018-05-01", "cost": "2026-06-01", "prices": "2023-01-01-preview"}


def ssh_key(kind: str = "ssh-ed25519", bits: int = 2048, comment: str = "me@laptop") -> str:
    """A well-formed public key's line (made up: no one's key)."""
    def s(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b
    if kind == "ssh-rsa":
        n = (1 << (bits - 1)) | 0x10001
        blob = s(b"ssh-rsa") + s((65537).to_bytes(3, "big")) + s(b"\x00" + n.to_bytes(bits // 8, "big"))
    else:
        blob = s(b"ssh-ed25519") + s(bytes(range(32)))
    return f"{kind} {base64.b64encode(blob).decode()} {comment}"


def rid(group: str, provider: str, kind: str, name: str) -> str:
    return f"/subscriptions/{SUB}/resourceGroups/{group}/providers/{provider}/{kind}/{name}"


def cloud_error(status: int, code: str, message: str, headers=None):
    return status, {"Content-Type": "application/json; charset=utf-8", "x-ms-request-id": "req-0001", **(headers or {})}, \
        {"error": {"code": code, "message": message}}


def rule(name, priority, port, source, access="Allow", direction="Inbound", protocol="Tcp"):
    return {"name": name, "properties": {"protocol": protocol, "sourcePortRange": "*", "destinationPortRange": port,
                                         "sourceAddressPrefix": source, "destinationAddressPrefix": "*", "access": access,
                                         "priority": priority, "direction": direction, "provisioningState": "Succeeded"}}


DEFAULT_RULES = [
    {"name": "AllowVnetInBound", "properties": {"description": "Allow inbound traffic from all VMs in VNET", "access": "Allow",
                                                "destinationAddressPrefix": "VirtualNetwork", "destinationPortRange": "*",
                                                "direction": "Inbound", "priority": 65000, "sourceAddressPrefix": "VirtualNetwork",
                                                "sourcePortRange": "*", "protocol": "*"}},
    {"name": "DenyAllInBound", "properties": {"description": "Deny all inbound traffic", "access": "Deny",
                                              "destinationAddressPrefix": "*", "destinationPortRange": "*", "direction": "Inbound",
                                              "priority": 65500, "sourceAddressPrefix": "*", "sourcePortRange": "*", "protocol": "*"}},
]


class FakeAzure:
    """Azure in memory (module docstring)."""

    def __init__(self):
        self.requests: list[dict] = []
        self.tokens = 0
        self.secret = SECRET
        self.fail: dict[str, tuple] = {}  # a route's name -> (status, code, message[, headers]): its answer instead
        self.status_only = True  # List All with statusOnly gives the power states (False: they must be asked one by one)
        self.limits = {"x-ms-ratelimit-remaining-subscription-reads": "249"}
        self.subscription = {"id": f"/subscriptions/{SUB}", "subscriptionId": SUB, "tenantId": TENANT,
                             "displayName": "Pay-As-You-Go", "state": "Enabled", "authorizationSource": "RoleBased",
                             "subscriptionPolicies": {"locationPlacementId": "Public_2014-09-01",
                                                      "quotaId": "PayAsYouGo_2014-09-01", "spendingLimit": "Off"}}
        self.groups = [{"id": f"/subscriptions/{SUB}/resourceGroups/web-rg", "name": "web-rg", "location": "eastus",
                        "properties": {"provisioningState": "Succeeded"}},
                       {"id": f"/subscriptions/{SUB}/resourceGroups/dns-rg", "name": "dns-rg", "location": "westus2",
                        "properties": {"provisioningState": "Succeeded"}}]
        subnet = f"/subscriptions/{SUB}/resourceGroups/web-rg/providers/Microsoft.Network/virtualNetworks/web-vnet/subnets/default"
        self.vms = {
            "web1": {"group": "web-rg", "size": "Standard_B1s", "os": "Linux", "power": "running", "nic": "web1-nic",
                     "image": {"publisher": "Canonical", "offer": "ubuntu-24_04-lts", "sku": "server"}},
            "win1": {"group": "web-rg", "size": "Standard_D2s_v3", "os": "Windows", "power": "deallocated", "nic": "win1-nic",
                     "image": {"publisher": "MicrosoftWindowsServer", "offer": "WindowsServer", "sku": "2022-datacenter"}},
        }
        self.nics = {
            "web1-nic": {"vm": "web1", "nsg": "web1-nsg", "ip": "web1-ip", "private": "10.0.0.4", "subnet": subnet},
            "win1-nic": {"vm": "win1", "nsg": None, "ip": "win1-ip", "private": "10.0.0.5", "subnet": subnet},
        }
        self.ips = {
            "web1-ip": {"address": "20.1.2.3", "allocation": "Static", "nic": "web1-nic"},
            "win1-ip": {"address": "", "allocation": "Dynamic", "nic": "win1-nic"},
            "spare-ip": {"address": "20.1.2.9", "allocation": "Static", "nic": None},
        }
        self.nsgs = {
            "web1-nsg": {"group": "web-rg", "rules": [rule("allow-ssh-home", 300, "22", "203.0.113.0/24"),
                                                      rule("allow-https", 310, "443", "Internet")],
                         "nics": ["web1-nic"], "subnets": []},
            "subnet-nsg": {"group": "web-rg", "rules": [], "nics": [], "subnets": [subnet]},
        }
        self.disks = [
            {"name": "web1-os", "group": "web-rg", "size": 30, "sku": "Premium_LRS", "state": "Attached", "vm": "web1"},
            {"name": "old-data", "group": "web-rg", "size": 64, "sku": "Standard_LRS", "state": "Unattached", "vm": None},
        ]
        self.keys = {("web-rg", "laptop"): {"location": "eastus", "key": ssh_key()}}
        self.zones = {("dns-rg", "example.com"): {}}
        self.etag = 0
        zone = self.zones[("dns-rg", "example.com")]
        for name, rtype, props in (
                ("@", "NS", {"NSRecords": [{"nsdname": f"ns{i}-01.azure-dns.{t}."} for i, t in
                                           ((1, "com"), (2, "net"), (3, "org"), (4, "info"))]}),
                ("@", "SOA", {"SOARecord": {"host": "ns1-01.azure-dns.com.", "email": "azuredns-hostmaster.microsoft.com",
                                            "serialNumber": 1, "refreshTime": 3600, "retryTime": 300, "expireTime": 2419200,
                                            "minimumTTL": 300}}),
                ("@", "A", {"ARecords": [{"ipv4Address": "20.1.2.3"}]}),
                ("@", "MX", {"MXRecords": [{"preference": 10, "exchange": "mail.example.com"}]}),
                ("@", "TXT", {"TXTRecords": [{"value": ["v=spf1 include:spf.protection.outlook.com -all"]},
                                             {"value": ["google-site-verification=abc123"]}]}),
                ("www", "CNAME", {"CNAMERecord": {"cname": "web1.eastus.cloudapp.azure.com"}}),
                ("home", "A", {"ARecords": [{"ipv4Address": "198.51.100.7"}], "TTL": 300}),
                ("lb", "A", {"ARecords": [], "targetResource": {"id": rid("web-rg", "Microsoft.Network", "publicIPAddresses", "spare-ip")}}),
        ):
            zone[(name, rtype)] = self._recordset(name, rtype, {"TTL": 3600, "metadata": {"owner": "me"} if name == "@" and rtype == "A" else {}, **props})
        self.cost = 12.3456
        self.prices = {
            ("eastus", "Standard_B1s"): [("Virtual Machines BS Series", "B1s", 0.0104), ("Virtual Machines BS Series Windows", "B1s", 0.0156),
                                         ("Virtual Machines BS Series", "B1s Spot", 0.0021),
                                         ("Virtual Machines BS Series", "B1s Low Priority", 0.0021)],
            ("eastus", "Standard_D2s_v3"): [("Virtual Machines DSv3 Series", "D2s v3", 0.096),
                                            ("Virtual Machines DSv3 Series Windows", "D2s v3", 0.188)],
        }

    # -- the subscription's resources as Azure answers them ----------------------------------------------------------------------
    def _recordset(self, name, rtype, props):
        self.etag += 1
        return {"id": f"/subscriptions/{SUB}/resourceGroups/dns-rg/providers/Microsoft.Network/dnszones/example.com/{rtype}/{name}",
                "name": name, "type": f"Microsoft.Network/dnszones/{rtype}", "etag": f"etag-{self.etag}",
                "properties": {"fqdn": f"{'' if name == '@' else name + '.'}example.com.", "provisioningState": "Succeeded", **props}}

    def vm_json(self, name):
        v = self.vms[name]
        return {"id": rid(v["group"], "Microsoft.Compute", "virtualMachines", name), "name": name, "type": "Microsoft.Compute/virtualMachines",
                "location": "eastus", "properties": {
                    "vmId": f"vm-{name}", "hardwareProfile": {"vmSize": v["size"]}, "provisioningState": "Succeeded",
                    "timeCreated": "2026-10-01T10:00:00.0000000+00:00",
                    "storageProfile": {"imageReference": v["image"], "osDisk": {"osType": v["os"], "name": f"{name}-os"}},
                    "osProfile": {"computerName": name, "adminUsername": "azureuser"},
                    "networkProfile": {"networkInterfaces": [{"id": rid(v["group"], "Microsoft.Network", "networkInterfaces", v["nic"]),
                                                              "properties": {"primary": True}}]}}}

    def view(self, name):
        state = self.vms[name]["power"]
        words = {"running": "VM running", "deallocated": "VM deallocated", "stopped": "VM stopped"}.get(state, state)
        return {"statuses": [{"code": "ProvisioningState/succeeded", "level": "Info", "displayStatus": "Provisioning succeeded"},
                             {"code": f"PowerState/{state}", "level": "Info", "displayStatus": words}]}

    def nic_json(self, name):
        n = self.nics[name]
        config = {"name": "ipconfig1", "id": rid("web-rg", "Microsoft.Network", "networkInterfaces", name) + "/ipConfigurations/ipconfig1",
                  "properties": {"privateIPAddress": n["private"], "subnet": {"id": n["subnet"]},
                                 "publicIPAddress": {"id": rid("web-rg", "Microsoft.Network", "publicIPAddresses", n["ip"])}}}
        props = {"ipConfigurations": [config], "virtualMachine": {"id": rid("web-rg", "Microsoft.Compute", "virtualMachines", n["vm"])},
                 "primary": True, "macAddress": "00-0D-3A-00-00-01"}
        if n["nsg"]:
            props["networkSecurityGroup"] = {"id": rid("web-rg", "Microsoft.Network", "networkSecurityGroups", n["nsg"])}
        return {"id": rid("web-rg", "Microsoft.Network", "networkInterfaces", name), "name": name, "location": "eastus",
                "properties": props}

    def ip_json(self, name):
        x = self.ips[name]
        props = {"publicIPAddressVersion": "IPv4", "publicIPAllocationMethod": x["allocation"], "idleTimeoutInMinutes": 4,
                 "provisioningState": "Succeeded"}
        if x["address"]:
            props["ipAddress"] = x["address"]
        if x["nic"]:
            props["ipConfiguration"] = {"id": rid("web-rg", "Microsoft.Network", "networkInterfaces", x["nic"]) + "/ipConfigurations/ipconfig1"}
        return {"id": rid("web-rg", "Microsoft.Network", "publicIPAddresses", name), "name": name, "location": "eastus",
                "sku": {"name": "Standard", "tier": "Regional"}, "properties": props}

    def nsg_json(self, name):
        g = self.nsgs[name]
        return {"id": rid(g["group"], "Microsoft.Network", "networkSecurityGroups", name), "name": name, "location": "eastus",
                "type": "Microsoft.Network/networkSecurityGroups",
                "properties": {"securityRules": [dict(r) for r in g["rules"]], "defaultSecurityRules": DEFAULT_RULES,
                               "networkInterfaces": [{"id": rid("web-rg", "Microsoft.Network", "networkInterfaces", n)} for n in g["nics"]],
                               "subnets": [{"id": s} for s in g["subnets"]], "provisioningState": "Succeeded"}}

    def resources(self):
        out = [{"id": rid(v["group"], "Microsoft.Compute", "virtualMachines", n), "name": n, "type": "Microsoft.Compute/virtualMachines"}
               for n, v in self.vms.items()]
        out += [{"id": rid("web-rg", "Microsoft.Network", "networkInterfaces", n), "name": n, "type": "Microsoft.Network/networkInterfaces"}
                for n in self.nics]
        out += [{"id": rid("web-rg", "Microsoft.Network", "virtualNetworks", "web-vnet"), "name": "web-vnet",
                 "type": "Microsoft.Network/virtualNetworks"},
                {"id": rid("web-rg", "Microsoft.Storage", "storageAccounts", "webdiag"), "name": "webdiag",
                 "type": "Microsoft.Storage/storageAccounts"},
                {"id": rid("dns-rg", "Microsoft.Network", "dnszones", "example.com"), "name": "example.com",
                 "type": "Microsoft.Network/dnszones"}]
        return out

    # -- the transport --------------------------------------------------------------------------------------------------------
    def __call__(self, method, url, headers, body, timeout):
        parts = urlsplit(url)
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        data = None
        if body:
            text = body.decode()
            data = json.loads(text) if headers.get("Content-Type") == "application/json" else \
                {k: v[0] for k, v in parse_qs(text).items()}
        self.requests.append({"method": method, "url": url, "host": parts.hostname, "path": unquote(parts.path), "query": query,
                              "headers": dict(headers), "body": data})
        status, got, answer = self.answer(method, parts.hostname, unquote(parts.path), query, headers, data)
        raw = answer if isinstance(answer, bytes) else json.dumps(answer).encode() if answer is not None else b""
        return status, got, raw

    def ok(self, data, status=200, headers=None):
        return status, {"Content-Type": "application/json; charset=utf-8", "x-ms-request-id": "req-0001", **self.limits,
                        **(headers or {})}, data

    def failing(self, route):
        f = self.fail.get(route)
        if f is None:
            return None
        return cloud_error(f[0], f[1], f[2], f[3] if len(f) > 3 else None)

    def answer(self, method, host, path, query, headers, data):
        if host == "login.microsoftonline.com":
            assert method == "POST" and path == f"/{TENANT}/oauth2/v2.0/token", path
            assert headers["Content-Type"] == "application/x-www-form-urlencoded" and "Authorization" not in headers
            if self.failing("token"):
                f = self.fail["token"]
                return 401, {"Content-Type": "application/json"}, {
                    "error": f[1], "error_description": f"{f[2]}\r\nTrace ID: 0000aaaa\r\nCorrelation ID: bbbb\r\nTimestamp: 2026-11-11 10:00:00Z",
                    "error_codes": [7000215], "trace_id": "0000aaaa", "correlation_id": "bbbb"}
            assert data == {"client_id": CLIENT, "scope": "https://management.azure.com/.default", "client_secret": self.secret,
                            "grant_type": "client_credentials"}, data
            self.tokens += 1
            return 200, {"Content-Type": "application/json"}, {"token_type": "Bearer", "expires_in": 3599,
                                                               "access_token": f"eyJ0eXAi.stand-in-token-{self.tokens}"}
        if host == "prices.azure.com":
            assert method == "GET" and path == "/api/retail/prices" and "Authorization" not in headers
            assert query["api-version"] == VERSIONS["prices"] and query["meterRegion"] == "'primary'"
            filt = query["$filter"]
            region = re.search(r"armRegionName eq '([^']+)'", filt).group(1)
            size = re.search(r"armSkuName eq '([^']+)'", filt).group(1)
            assert "serviceName eq 'Virtual Machines'" in filt and "priceType eq 'Consumption'" in filt
            items = [{"currencyCode": "USD", "tierMinimumUnits": 0.0, "retailPrice": price, "unitPrice": price,
                      "armRegionName": region, "location": "US East", "meterName": meter, "productName": product,
                      "skuName": meter, "serviceName": "Virtual Machines", "serviceFamily": "Compute",
                      "unitOfMeasure": "1 Hour", "type": "Consumption", "isPrimaryMeterRegion": True, "armSkuName": size}
                     for product, meter, price in self.prices.get((region, size), [])]
            return 200, {"Content-Type": "application/json"}, {"BillingCurrency": "USD", "CustomerEntityId": "Default",
                                                               "CustomerEntityType": "Retail", "Items": items, "NextPageLink": None,
                                                               "Count": len(items)}
        assert host == "management.azure.com", host
        assert headers.get("Authorization", "").startswith("Bearer eyJ0eXAi.stand-in-token-"), "a Resource Manager request bears the token"
        base = f"/subscriptions/{SUB}"
        assert path.startswith(base), path
        rest = path[len(base):]
        return self.route(method, rest, query, headers, data)

    def version(self, query, kind):
        assert query.get("api-version") == VERSIONS[kind], (kind, query)

    def route(self, method, rest, query, headers, data):
        m = re.fullmatch
        if rest == "" and method == "GET":
            self.version(query, "subscriptions")
            return self.failing("subscription") or self.ok(self.subscription)
        if rest == "/resourcegroups":
            self.version(query, "resources")
            return self.failing("groups") or self.ok({"value": self.groups})
        if rest == "/resources":
            self.version(query, "resources")
            return self.failing("resources") or self.ok({"value": self.resources()})
        if rest == "/providers/Microsoft.Compute/virtualMachines":
            self.version(query, "compute")
            if query.get("statusOnly") == "true":
                if self.failing("states"):
                    return self.failing("states")
                if not self.status_only:
                    return self.ok({"value": [{"id": self.vm_json(n)["id"], "name": n, "properties": {}} for n in self.vms]})
                return self.ok({"value": [{"id": self.vm_json(n)["id"], "name": n, "type": "Microsoft.Compute/virtualMachines",
                                           "location": "eastus", "properties": {"instanceView": self.view(n)}} for n in self.vms]})
            return self.failing("vms") or self.ok({"value": [self.vm_json(n) for n in self.vms]})
        if rest == "/providers/Microsoft.Compute/disks":
            self.version(query, "disks")
            return self.failing("disks") or self.ok({"value": [
                {"id": rid(d["group"], "Microsoft.Compute", "disks", d["name"]), "name": d["name"], "location": "eastus",
                 "sku": {"name": d["sku"]}, "managedBy": rid("web-rg", "Microsoft.Compute", "virtualMachines", d["vm"]) if d["vm"] else None,
                 "properties": {"diskSizeGB": d["size"], "diskState": d["state"], "osType": "Linux",
                                "timeCreated": "2026-10-01T10:00:00+00:00"}} for d in self.disks]})
        if rest == "/providers/Microsoft.Compute/sshPublicKeys":
            self.version(query, "compute")
            return self.failing("keys") or self.ok({"value": [self.key_json(g, n) for g, n in self.keys]})
        if rest == "/providers/Microsoft.Network/networkInterfaces":
            self.version(query, "network")
            return self.failing("nics") or self.ok({"value": [self.nic_json(n) for n in self.nics]})
        if rest == "/providers/Microsoft.Network/publicIPAddresses":
            self.version(query, "network")
            return self.failing("ips") or self.ok({"value": [self.ip_json(n) for n in self.ips]})
        if rest == "/providers/Microsoft.Network/networkSecurityGroups":
            self.version(query, "network")
            return self.failing("nsgs") or self.ok({"value": [self.nsg_json(n) for n in self.nsgs]})
        if rest == "/providers/Microsoft.Network/dnszones":
            self.version(query, "dns")
            return self.failing("zones") or self.ok({"value": [
                {"id": rid(g, "Microsoft.Network", "dnszones", z), "name": z, "type": "Microsoft.Network/dnszones", "location": "global",
                 "etag": "zone-etag", "properties": {"maxNumberOfRecordSets": 10000, "numberOfRecordSets": len(sets),
                                                     "nameServers": ["ns1-01.azure-dns.com", "ns2-01.azure-dns.net",
                                                                     "ns3-01.azure-dns.org", "ns4-01.azure-dns.info"]}}
                for (g, z), sets in self.zones.items()]})
        if rest == "/providers/Microsoft.CostManagement/query" and method == "POST":
            self.version(query, "cost")
            assert data == {"type": "Usage", "timeframe": "MonthToDate", "dataset": {"granularity": "None", "aggregation": {
                "totalCost": {"name": "PreTaxCost", "function": "Sum"}}}}, data
            return self.failing("cost") or self.ok({"id": "q", "properties": {
                "columns": [{"name": "PreTaxCost", "type": "Number"}, {"name": "Currency", "type": "String"}],
                "nextLink": None, "rows": [[self.cost, "USD"]]}})
        g = m(r"/resourceGroups/([^/]+)/providers/Microsoft\.Compute/virtualMachines/([^/]+)/(instanceView|start|restart|deallocate|powerOff)", rest)
        if g:
            group, name, what = g.groups()
            self.version(query, "compute")
            if name not in self.vms or self.vms[name]["group"] != group:
                return cloud_error(404, "ResourceNotFound", f"The Resource 'Microsoft.Compute/virtualMachines/{name}' was not found.")
            if what == "instanceView":
                assert method == "GET"
                return self.failing("view") or self.ok(self.view(name))
            assert method == "POST" and data is None, (method, data)
            if self.failing(what):
                return self.failing(what)
            self.vms[name]["power"] = {"start": "running", "restart": "running", "deallocate": "deallocated", "powerOff": "stopped"}[what]
            return self.ok(None, 202, {"Location": "https://management.azure.com/subscriptions/x/operationresults/1", "Retry-After": "10"})
        g = m(r"/resourceGroups/([^/]+)/providers/Microsoft\.Compute/sshPublicKeys/([^/]+)", rest)
        if g:
            group, name = g.groups()
            self.version(query, "compute")
            if method == "GET":
                return self.ok(self.key_json(group, name)) if (group, name) in self.keys else \
                    cloud_error(404, "ResourceNotFound", f"The Resource 'Microsoft.Compute/sshPublicKeys/{name}' was not found.")
            if method == "PUT":
                assert set(data) == {"location", "properties"} and set(data["properties"]) == {"publicKey"}, data
                if headers.get("If-None-Match") == "*" and (group, name) in self.keys:
                    return cloud_error(412, "PreconditionFailed", "The resource exists.")
                self.keys[(group, name)] = {"location": data["location"], "key": data["properties"]["publicKey"]}
                return self.ok(self.key_json(group, name), 201)
            assert method == "DELETE"
            return self.ok(None, 200 if self.keys.pop((group, name), None) else 204)
        g = m(r"/resourceGroups/([^/]+)/providers/Microsoft\.Network/networkSecurityGroups/([^/]+)", rest)
        if g:
            group, nsg = g.groups()
            self.version(query, "network")
            assert method == "GET"
            if self.failing("nsg"):
                return self.failing("nsg")
            return self.ok(self.nsg_json(nsg)) if nsg in self.nsgs and self.nsgs[nsg]["group"] == group else \
                cloud_error(404, "ResourceNotFound", f"The Resource 'Microsoft.Network/networkSecurityGroups/{nsg}' was not found.")
        g = m(r"/resourceGroups/([^/]+)/providers/Microsoft\.Network/networkSecurityGroups/([^/]+)/securityRules/([^/]+)", rest)
        if g:
            group, nsg, name = g.groups()
            self.version(query, "network")
            rules = self.nsgs[nsg]["rules"]
            if method == "PUT":
                assert set(data) == {"properties"}, data
                if headers.get("If-None-Match") == "*" and any(r["name"] == name for r in rules):
                    return cloud_error(412, "PreconditionFailed", "The resource exists.")
                rules[:] = [r for r in rules if r["name"] != name] + [{"name": name, "properties": {**data["properties"],
                                                                                                    "provisioningState": "Succeeded"}}]
                return self.ok({"name": name, "id": rid(group, "Microsoft.Network", "networkSecurityGroups", nsg) + f"/securityRules/{name}",
                                "properties": {**data["properties"], "provisioningState": "Updating"}}, 201,
                               {"Azure-AsyncOperation": "https://management.azure.com/subscriptions/x/operations/2"})
            assert method == "DELETE"
            before = len(rules)
            rules[:] = [r for r in rules if r["name"] != name]
            return self.ok(None, 202 if len(rules) < before else 204, {"Location": "https://management.azure.com/x"})
        g = m(r"/resourceGroups/([^/]+)/providers/Microsoft\.Network/dnsZones/([^/]+)/all", rest)
        if g:
            group, zone = g.groups()
            self.version(query, "dns")
            assert method == "GET"
            return self.failing("records") or self.ok({"value": list(self.zones[(group, zone)].values())})
        g = m(r"/resourceGroups/([^/]+)/providers/Microsoft\.Network/dnsZones/([^/]+)/([A-Z]+)/([^/]+)", rest)
        if g:
            group, zone, rtype, name = g.groups()
            self.version(query, "dns")
            sets = self.zones[(group, zone)]
            held = sets.get((name, rtype))
            if method == "GET":
                return self.ok(held) if held else cloud_error(404, "NotFound", f"The resource record '{name}' does not exist in resource group '{group}' of subscription '{SUB}'.")
            if method == "PUT":
                if headers.get("If-None-Match") == "*" and held:
                    return 412, {"Content-Type": "application/json"}, {"code": "PreconditionFailed", "message": "The Resource exists."}
                if "If-Match" in headers and (not held or headers["If-Match"] != held["etag"]):
                    return 412, {"Content-Type": "application/json"}, {"code": "PreconditionFailed", "message": "The etag does not match."}
                assert set(data) == {"properties"} and "TTL" in data["properties"], data
                made = self._recordset(name, rtype, data["properties"])
                sets[(name, rtype)] = made
                return self.ok(made, 200 if held else 201)
            assert method == "DELETE"
            if "If-Match" in headers and held and headers["If-Match"] != held["etag"]:
                return 412, {"Content-Type": "application/json"}, {"code": "PreconditionFailed", "message": "The etag does not match."}
            sets.pop((name, rtype), None)
            return self.ok(None, 200 if held else 204)
        return cloud_error(404, "NotFound", f"no route {method} {rest}")

    def key_json(self, group, name):
        k = self.keys[(group, name)]
        return {"id": rid(group, "Microsoft.Compute", "sshPublicKeys", name), "name": name, "location": k["location"],
                "type": "Microsoft.Compute/sshPublicKeys", "properties": {"publicKey": k["key"]}}

    # -- what the tests ask of it -------------------------------------------------------------------------------------------------
    def writes(self) -> list[tuple[str, str]]:
        """The changes sent: (method, path under the subscription)."""
        return [(r["method"], r["path"].split(SUB, 1)[-1]) for r in self.requests
                if r["host"] == "management.azure.com" and r["method"] != "GET" and "CostManagement" not in r["path"]]

    def record(self, name, rtype, zone=("dns-rg", "example.com")):
        held = self.zones[zone].get((name, rtype))
        return None if held is None else held["properties"]


class Platform:
    """The platform app as a plugin sees it attach it (its NAME): the one app whose attaching starts the reading."""

    NAME = "platform"


class Pairs(Login):
    """A login holding pairs by name (the login app's store, as the Login interface asks it)."""

    NAMESPACE = "test"

    def __init__(self, values: dict[str, str]):
        self.pairs = {pair_name(k): v for k, v in values.items()}
        self.asked: list[str] = []

    def user(self) -> dict:
        return {"name": "tester"}

    def vector(self, name: str) -> str:
        self.asked.append(name)
        if name not in self.pairs:
            raise Unauthorized(f"no {name}", 404)
        return self.pairs[name]

    def names(self) -> set[str]:
        return set(self.pairs)


def settings_of(api: bool = True, ddns: bool = False, **more) -> dict[str, str]:
    out = {}
    if api:
        out.update({"AZURE_TENANT_ID": TENANT, "AZURE_CLIENT_ID": CLIENT, "AZURE_CLIENT_SECRET": SECRET, "AZURE_SUBSCRIPTION_ID": SUB})
    if ddns:
        out.update({"AZURE_DDNS_HOSTS": "new.example.com"})  # a host with no record yet: Dynamic DNS's own to make
    out.update(more)
    return out


@pytest.fixture(autouse=True)
def _no_azure_no_network(monkeypatch, tmp_path):
    """No test reaches Azure, a resolver or this machine's settings: HTTPS and nslookup refused, every AZURE_ variable
    cleared, the platform's folder (the Dynamic DNS state's) the test's own."""
    def refused(*a, **k):
        raise AssertionError("a test reached for the network")
    monkeypatch.setattr(rest_mod, "_requests_transport", refused)
    monkeypatch.setattr(dns_mod, "query", refused)
    for n in NAMES:
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("LIMINAL_PLATFORM_DIR", str(tmp_path / "platform"))


@pytest.fixture
def env(monkeypatch):
    """Sets the plugin's variables (the EnvironmentLogin's: what the platform reads today)."""
    def put(values: dict[str, str]):
        for k, v in values.items():
            monkeypatch.setenv(k, v)
    return put


@pytest.fixture
def made():
    """A plugin over the stand-ins: (plugin, fake Azure). `public`: this network's address as asked (a list: one answer
    after another, the last kept)."""
    def make(fake: FakeAzure | None = None, public=(HOME, "a stand-in")):
        fake = fake or FakeAzure()
        answers = list(public) if isinstance(public, list) else [public]

        def ask():
            return answers.pop(0) if len(answers) > 1 else answers[0]
        p = AzurePlugin(transport=fake, public=ask, sleep=lambda s: None)
        return p, fake
    return make
