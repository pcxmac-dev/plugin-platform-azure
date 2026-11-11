"""What the plugin read, in its own shape: Resource Manager's answers (their fields as the references give them, read
2026-11-11) joined into what the page shows. A VM's network interfaces give its private and public addresses and the
subnets it is on; a network security group's networkInterfaces and subnets give the VMs it is attached to; a public IP's
ipConfiguration the resource it is on; a disk's managedBy its VM. Nothing here asks anything."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from . import records as recs
from . import rules as nsg_rules
from .api import group_of, key_of, name_of, parent_of, power_of, statuses_of

# a VM's power state -> its words on the page and whether its compute is billed (Azure's "States and billing status")
POWER = {
    "running": ("running", True), "starting": ("starting", True), "stopping": ("stopping", True),
    "stopped": ("stopped, still billed", True), "deallocating": ("deallocating", False),
    "deallocated": ("deallocated", False), "hibernated": ("hibernated (deallocated)", False),
}
KINDS = {  # resource types the counts name in words (the rest by their type)
    "microsoft.containerservice/managedclusters": "Kubernetes clusters (AKS)",
    "microsoft.network/loadbalancers": "load balancers",
    "microsoft.network/applicationgateways": "application gateways",
    "microsoft.network/virtualnetworks": "virtual networks",
    "microsoft.network/networkinterfaces": "network interfaces",
    "microsoft.network/natgateways": "NAT gateways",
    "microsoft.network/bastionhosts": "Bastion hosts",
    "microsoft.network/privatednszones": "private DNS zones",
    "microsoft.network/trafficmanagerprofiles": "Traffic Manager profiles",
    "microsoft.network/networkwatchers": "network watchers",
    "microsoft.compute/snapshots": "snapshots",
    "microsoft.compute/images": "images",
    "microsoft.compute/galleries": "compute galleries",
    "microsoft.compute/availabilitysets": "availability sets",
    "microsoft.compute/virtualmachinescalesets": "VM scale sets",
    "microsoft.compute/virtualmachines/extensions": "VM extensions",
    "microsoft.compute/restorepointcollections": "restore point collections",
    "microsoft.sql/servers": "SQL servers",
    "microsoft.sql/servers/databases": "SQL databases",
    "microsoft.dbforpostgresql/flexibleservers": "PostgreSQL servers",
    "microsoft.dbformysql/flexibleservers": "MySQL servers",
    "microsoft.documentdb/databaseaccounts": "Cosmos DB accounts",
    "microsoft.web/sites": "App Service apps",
    "microsoft.web/serverfarms": "App Service plans",
    "microsoft.storage/storageaccounts": "storage accounts",
    "microsoft.keyvault/vaults": "key vaults",
    "microsoft.containerregistry/registries": "container registries",
    "microsoft.containerinstance/containergroups": "container groups",
    "microsoft.app/containerapps": "container apps",
    "microsoft.recoveryservices/vaults": "Recovery Services vaults (backups)",
    "microsoft.operationalinsights/workspaces": "Log Analytics workspaces",
    "microsoft.insights/components": "Application Insights",
    "microsoft.cdn/profiles": "CDN and Front Door profiles",
}
SHOWN = frozenset({"microsoft.compute/virtualmachines", "microsoft.compute/disks", "microsoft.network/publicipaddresses",
                   "microsoft.network/networksecuritygroups", "microsoft.network/dnszones", "microsoft.compute/sshpublickeys"})
KEY_TYPES = ("ssh-rsa", "ssh-ed25519")  # what Azure takes: RSA of 2048 bits or more, ED25519 (its SSH key docs)
RSA_LEAST = 2048
KEY_NAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,78}[A-Za-z0-9_])?$")


def _props(item) -> Mapping:
    p = item.get("properties") if isinstance(item, Mapping) else None
    return p if isinstance(p, Mapping) else {}


def _id(ref) -> str:
    return str(ref.get("id") or "") if isinstance(ref, Mapping) else ""


@dataclass
class Snapshot:
    """The subscription as read by a refresh (each part's trouble in `troubles` when it could not be read)."""

    at: float
    subscription: dict = field(default_factory=dict)
    groups: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)  # resource type (lowercase) -> how many
    by_group: dict = field(default_factory=dict)  # resource group (lowercase) -> how many resources
    vms: list = field(default_factory=list)
    disks: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    nsgs: list = field(default_factory=list)
    zones: list = field(default_factory=list)
    records: dict = field(default_factory=dict)  # zone key (group/zone, lowercase) -> [RecordSet] or why not read
    keys: list = field(default_factory=list)
    troubles: dict = field(default_factory=dict)  # part -> why it was not read
    views: int = 0  # VMs whose power state was asked one by one (the list did not give it)

    def zone(self, group: str, zone: str) -> dict | None:
        k = zone_key(group, zone)
        return next((z for z in self.zones if z["key"] == k), None)

    def zone_named(self, zone: str) -> dict | None:
        return next((z for z in self.zones if z["name"].lower() == str(zone).lower().rstrip(".")), None)

    def vm(self, group: str, name: str) -> dict | None:
        g, n = str(group).lower(), str(name).lower()
        return next((v for v in self.vms if v["group"].lower() == g and v["name"].lower() == n), None)

    def vm_named(self, name: str) -> list:
        return [v for v in self.vms if v["name"].lower() == str(name).lower()]

    def nsg(self, group: str, name: str) -> dict | None:
        g, n = str(group).lower(), str(name).lower()
        return next((x for x in self.nsgs if x["group"].lower() == g and x["name"].lower() == n), None)

    def key(self, group: str, name: str) -> dict | None:
        g, n = str(group).lower(), str(name).lower()
        return next((k for k in self.keys if k["group"].lower() == g and k["name"].lower() == n), None)

    def group(self, name: str) -> dict | None:
        return next((g for g in self.groups if g["name"].lower() == str(name).lower()), None)


def zone_key(group: str, zone: str) -> str:
    return f"{group}/{zone}".lower()


def subscription_of(data: Mapping) -> dict:
    policies = data.get("subscriptionPolicies") if isinstance(data.get("subscriptionPolicies"), Mapping) else {}
    return {"name": str(data.get("displayName") or ""), "state": str(data.get("state") or ""),
            "offer": str(policies.get("quotaId") or ""), "spendingLimit": str(policies.get("spendingLimit") or "")}


def groups_of(items: Iterable) -> list:
    out = [{"name": str(g.get("name") or ""), "location": str(g.get("location") or ""),
            "state": str(_props(g).get("provisioningState") or "")} for g in items or [] if isinstance(g, Mapping)]
    return sorted(out, key=lambda g: g["name"].lower())


def counts_of(items: Iterable) -> tuple[dict, dict]:
    """How many resources of each type, and in each resource group."""
    by_type: dict[str, int] = {}
    by_group: dict[str, int] = {}
    for r in items or []:
        if not isinstance(r, Mapping):
            continue
        t = str(r.get("type") or "").lower()
        by_type[t] = by_type.get(t, 0) + 1
        g = group_of(_id(r) or str(r.get("id") or "")).lower()
        if g:
            by_group[g] = by_group.get(g, 0) + 1
    return by_type, by_group


def kind_of(rtype: str) -> str:
    return KINDS.get(rtype.lower(), rtype)


# -- network interfaces: what joins a VM to its addresses and its security groups --------------------------------------------
def nics_of(items: Iterable) -> dict:
    """The network interfaces by ID: their VM, their security group, their IP configurations' private addresses,
    public IP IDs and subnets."""
    out = {}
    for n in items or []:
        if not isinstance(n, Mapping):
            continue
        p = _props(n)
        configs = [c for c in p.get("ipConfigurations") or [] if isinstance(c, Mapping)]
        out[key_of(_id(n))] = {
            "name": str(n.get("name") or ""), "vm": key_of(_id(p.get("virtualMachine"))) if p.get("virtualMachine") else "",
            "nsg": key_of(_id(p.get("networkSecurityGroup"))) if p.get("networkSecurityGroup") else "",
            "private": [str(_props(c).get("privateIPAddress")) for c in configs if _props(c).get("privateIPAddress")],
            "public": [key_of(_id(_props(c).get("publicIPAddress"))) for c in configs if _props(c).get("publicIPAddress")],
            "subnets": [key_of(_id(_props(c).get("subnet"))) for c in configs if _props(c).get("subnet")],
        }
    return out


def public_ips_of(items: Iterable) -> dict:
    out = {}
    for x in items or []:
        if not isinstance(x, Mapping):
            continue
        p = _props(x)
        sku = x.get("sku") if isinstance(x.get("sku"), Mapping) else {}
        dns = p.get("dnsSettings") if isinstance(p.get("dnsSettings"), Mapping) else {}
        out[key_of(_id(x))] = {
            "name": str(x.get("name") or ""), "group": group_of(_id(x)), "location": str(x.get("location") or ""),
            "address": str(p.get("ipAddress") or ""), "version": str(p.get("publicIPAddressVersion") or "IPv4"),
            "allocation": str(p.get("publicIPAllocationMethod") or ""), "sku": str(sku.get("name") or ""),
            "tier": str(sku.get("tier") or ""), "on": _id(p.get("ipConfiguration")), "fqdn": str(dns.get("fqdn") or ""),
        }
    return out


def vms_of(items: Iterable, statuses: Iterable, nics: Mapping, ips: Mapping) -> list:
    """The VMs with their power state (statusOnly's answer, by ID), size, OS and addresses."""
    power = {}
    for s in statuses or []:
        if isinstance(s, Mapping) and _id(s):
            state, words = power_of(statuses_of(s))
            if state:
                power[key_of(_id(s))] = (state, words)
    out = []
    for v in items or []:
        if not isinstance(v, Mapping):
            continue
        p = _props(v)
        storage = p.get("storageProfile") if isinstance(p.get("storageProfile"), Mapping) else {}
        os_disk = storage.get("osDisk") if isinstance(storage.get("osDisk"), Mapping) else {}
        image = storage.get("imageReference") if isinstance(storage.get("imageReference"), Mapping) else {}
        hardware = p.get("hardwareProfile") if isinstance(p.get("hardwareProfile"), Mapping) else {}
        network = p.get("networkProfile") if isinstance(p.get("networkProfile"), Mapping) else {}
        nic_ids = [key_of(_id(n)) for n in network.get("networkInterfaces") or [] if _id(n)]
        v4, v6, private, subnets = [], [], [], []
        for nid in nic_ids:
            nic = nics.get(nid) or {}
            private += nic.get("private") or []
            subnets += nic.get("subnets") or []
            for pid in nic.get("public") or []:
                ip = ips.get(pid) or {}
                if ip.get("address"):
                    (v6 if ip.get("version") == "IPv6" else v4).append(ip["address"])
        state, words = power.get(key_of(_id(v)), ("", ""))
        out.append({
            "id": _id(v), "key": key_of(_id(v)), "name": str(v.get("name") or ""), "group": group_of(_id(v)),
            "location": str(v.get("location") or ""), "size": str(hardware.get("vmSize") or ""),
            "os": str(os_disk.get("osType") or ""), "created": str(p.get("timeCreated") or ""),
            "provisioning": str(p.get("provisioningState") or ""), "priority": str(p.get("priority") or "Regular"),
            "license": str(p.get("licenseType") or ""), "image": " ".join(str(image.get(k) or "") for k in ("offer", "sku")).strip(),
            "nics": nic_ids, "subnets": subnets, "private": private, "ipv4": v4, "ipv6": v6, "power": state,
            "powerWords": words, "zones": [str(z) for z in v.get("zones") or []],
        })
    return sorted(out, key=lambda v: (v["group"].lower(), v["name"].lower()))


def disks_of(items: Iterable, vm_names: Mapping) -> list:
    out = []
    for d in items or []:
        if not isinstance(d, Mapping):
            continue
        p = _props(d)
        sku = d.get("sku") if isinstance(d.get("sku"), Mapping) else {}
        out.append({"name": str(d.get("name") or ""), "group": group_of(_id(d)), "location": str(d.get("location") or ""),
                    "sizeGb": p.get("diskSizeGB"), "sku": str(sku.get("name") or ""), "state": str(p.get("diskState") or ""),
                    "vm": vm_names.get(key_of(str(d.get("managedBy") or "")), name_of(str(d.get("managedBy") or "")))
                    if d.get("managedBy") else "", "os": str(p.get("osType") or ""), "created": str(p.get("timeCreated") or "")})
    return sorted(out, key=lambda d: (d["group"].lower(), d["name"].lower()))


ON_WORDS = {"loadbalancers": "load balancer", "applicationgateways": "application gateway", "natgateways": "NAT gateway",
            "bastionhosts": "Bastion host", "virtualnetworkgateways": "virtual network gateway", "azurefirewalls": "firewall"}


def resource_named(resource_id: str) -> tuple[str, str]:
    """A resource ID's type and name (the pair after its provider: loadBalancers, lb1)."""
    parts = str(resource_id or "").split("/")
    for i, x in enumerate(parts):
        if x.lower() == "providers" and i + 3 < len(parts):
            return parts[i + 2], parts[i + 3]
    return "", ""


def ips_listed(ips: Mapping, nics: Mapping, vm_names: Mapping) -> list:
    """The public IP addresses with what each is on (a VM by its network interface, else the resource's kind)."""
    out = []
    for ip in ips.values():
        on = ip.get("on") or ""
        rtype, rname = resource_named(on)
        if rtype.lower() == "networkinterfaces":
            nic = nics.get(parent_of(on, "ipConfigurations")) or {}
            vm = vm_names.get(nic.get("vm") or "", "")
            where = f"VM {vm}" if vm else f"network interface {rname}"
        elif rtype:
            where = f"{ON_WORDS.get(rtype.lower(), rtype)} {rname}"
        else:
            where = ""
        out.append({**ip, "where": where})
    return sorted(out, key=lambda x: (x["group"].lower(), x["name"].lower()))


def nsgs_of(items: Iterable, nics: Mapping, vms: list) -> list:
    """The network security groups with their rules (the group's own and its defaults) and the VMs they are attached to
    (through a VM's network interface or a subnet it is on)."""
    by_nic = {nid: v["name"] for v in vms for nid in v["nics"]}
    out = []
    for g in items or []:
        if not isinstance(g, Mapping):
            continue
        p = _props(g)
        nic_ids = [key_of(_id(n)) for n in p.get("networkInterfaces") or [] if _id(n)]
        subnet_ids = {key_of(_id(s)) for s in p.get("subnets") or [] if _id(s)}
        servers = [by_nic[n] for n in nic_ids if n in by_nic]
        servers += [v["name"] for v in vms if subnet_ids & set(v["subnets"]) and v["name"] not in servers]
        own = sorted((nsg_rules.parse(r) for r in p.get("securityRules") or [] if isinstance(r, Mapping)),
                     key=lambda r: (r.direction != "Inbound", r.priority, r.name.lower()))
        defaults = sorted((nsg_rules.parse(r, default=True) for r in p.get("defaultSecurityRules") or [] if isinstance(r, Mapping)),
                          key=lambda r: (r.direction != "Inbound", r.priority, r.name.lower()))
        out.append({"id": _id(g), "key": key_of(_id(g)), "name": str(g.get("name") or ""), "group": group_of(_id(g)),
                    "location": str(g.get("location") or ""), "rules": own, "defaults": defaults,
                    "servers": sorted(set(servers), key=str.lower), "nics": len(nic_ids), "subnets": len(subnet_ids)})
    return sorted(out, key=lambda x: (x["group"].lower(), x["name"].lower()))


def zones_of(items: Iterable) -> list:
    out = []
    for z in items or []:
        if not isinstance(z, Mapping):
            continue
        p = _props(z)
        name, group = str(z.get("name") or ""), group_of(_id(z))
        out.append({"key": zone_key(group, name), "name": name, "group": group, "sets": p.get("numberOfRecordSets"),
                    "most": p.get("maxNumberOfRecordSets"), "servers": [str(s) for s in p.get("nameServers") or []],
                    "type": str(p.get("zoneType") or "Public")})
    return sorted(out, key=lambda z: (z["name"].lower(), z["group"].lower()))


def keys_of(items: Iterable) -> list:
    out = []
    for k in items or []:
        if not isinstance(k, Mapping):
            continue
        text = str(_props(k).get("publicKey") or "")
        out.append({"name": str(k.get("name") or ""), "group": group_of(_id(k)), "location": str(k.get("location") or ""),
                    "key": describe_key(text)})
    return sorted(out, key=lambda k: (k["group"].lower(), k["name"].lower()))


# -- SSH public keys ----------------------------------------------------------------------------------------------------------
def key_blob(text: str) -> tuple[str, bytes, str]:
    """An OpenSSH public key's line as (its type, its blob, its comment); ValueError when it is none."""
    parts = str(text or "").strip().split(None, 2)
    if len(parts) < 2:
        raise ValueError("not an SSH public key: the one line of a .pub file (ssh-rsa AAAA… or ssh-ed25519 AAAA…)")
    kind, data = parts[0], parts[1]
    try:
        blob = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("not an SSH public key: its second part is not base64") from None
    return kind, blob, parts[2] if len(parts) > 2 else ""


def _strings(blob: bytes) -> list[bytes]:
    out, at = [], 0
    while at + 4 <= len(blob):
        (n,) = struct.unpack(">I", blob[at:at + 4])
        at += 4
        if at + n > len(blob):
            raise ValueError("not an SSH public key: its blob is cut short")
        out.append(blob[at:at + n])
        at += n
    if at != len(blob):
        raise ValueError("not an SSH public key: its blob does not end where it should")
    return out


def check_key(text: str) -> tuple[str, str]:
    """An SSH public key Azure takes (RSA of 2048 bits or more, or ED25519), as the one line sent, and its description;
    ValueError in words otherwise."""
    raw = str(text or "")
    if "PRIVATE KEY" in raw.upper():  # a private key pasted: refused without a word of it said back
        raise ValueError("that is a private key: paste the one line of the .pub file beside it (ssh-ed25519 AAAA… or "
                         "ssh-rsa AAAA…); a private key never leaves this PC")
    line = " ".join(raw.split())
    if any(ord(c) < 32 for c in raw.strip()):
        raise ValueError("an SSH public key is one line")
    kind, blob, _ = key_blob(line)
    if kind not in KEY_TYPES:
        named = kind if re.fullmatch(r"(?:ssh|ecdsa|sk)-[a-z0-9@.-]{1,40}", kind) else "that"  # a key type, never what was pasted
        raise ValueError(f"{named} keys are not taken by Azure: RSA (ssh-rsa, 2048 bits or more) or ED25519 (ssh-ed25519)")
    parts = _strings(blob)
    if not parts or parts[0].decode("ascii", "replace") != kind:
        raise ValueError(f"not an SSH public key: its blob is not an {kind} key's")
    if kind == "ssh-rsa":
        if len(parts) != 3:
            raise ValueError("not an RSA public key: its blob holds no exponent and modulus")
        bits = int.from_bytes(parts[2], "big").bit_length()
        if bits < RSA_LEAST:
            raise ValueError(f"an RSA key of {bits} bits: Azure takes RSA keys of {RSA_LEAST} bits or more")
    elif len(parts) != 2 or len(parts[1]) != 32:
        raise ValueError("not an ED25519 public key: its key is not 32 bytes")
    return line, describe_key(line)


def describe_key(text: str) -> str:
    """A key in words: its type, size and SHA256 fingerprint (as ssh-keygen -l shows it), its comment."""
    try:
        kind, blob, comment = key_blob(text)
        parts = _strings(blob)
    except ValueError:
        return "not readable as an SSH public key" if text else "no public key"
    size = ""
    if kind == "ssh-rsa" and len(parts) == 3:
        size = f" {int.from_bytes(parts[2], 'big').bit_length()} bits"
    elif kind == "ssh-ed25519":
        size = " 256 bits"
    print_ = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"{kind}{size} · SHA256:{print_}" + (f" · {comment}" if comment else "")


def key_name(value: str) -> str:
    n = str(value or "").strip()
    if not KEY_NAME.match(n):
        raise ValueError(f"{n!r} is not an SSH key's name here: 1 to 80 letters, digits, _ . -, beginning with a letter, "
                         "a digit or _")
    return n


# -- the record sets of a zone, as the page shows them -------------------------------------------------------------------------
def names_holding(sets: list, name: str) -> dict:
    """The types of the record sets at `name` in a zone as read (the CNAME rule's check)."""
    n = name.lower()
    return {s.type: s for s in sets if isinstance(s, recs.RecordSet) and s.name.lower() == n}
