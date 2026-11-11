"""Network security groups' security rules as Azure's Virtual Network reference gives them
(https://learn.microsoft.com/en-us/rest/api/virtualnetwork/security-rules, API 2026-01-01, read 2026-11-11): a rule has a
name, a priority (100 to 4096, the lower first, unique among the group's rules), a direction (Inbound, Outbound), an access
(Allow, Deny), a protocol (Tcp, Udp, Icmp, Esp, Ah or * for any), the source and destination address prefixes (a CIDR, an
IP range, * for any, or a service tag such as Internet, VirtualNetwork, AzureLoadBalancer) and port ranges (a port, a
range, or *). A rule is added with a PUT of its own and removed with a DELETE of its own: the group's other rules are never
touched. The default rules (AllowVnetInBound ... DenyAllInBound) are the group's own and cannot be removed.

A change that may lock this PC out of a server, or open one to the whole internet, is risky: asked a second time
(`risk_of_adding`, `risk_of_removing`): an Allow inbound rule opening SSH (22), RDP (3389) or every port to any source; an
inbound Deny covering SSH or RDP on a group attached to a server; the removal of an inbound Allow rule letting SSH or RDP
in to a server the group is attached to."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

DIRECTIONS = ("Inbound", "Outbound")
ACCESSES = ("Allow", "Deny")
PROTOCOLS = ("Tcp", "Udp", "Icmp", "Esp", "Ah", "*")  # SecurityRuleProtocol
PRIORITY = (100, 4096)
SSH, RDP = 22, 3389
WIDE = frozenset({"*", "internet", "0.0.0.0/0", "::/0"})  # a source that is the whole internet
NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,78}[A-Za-z0-9_])?$")
TAG = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)*$")  # a service tag: Internet, VirtualNetwork, Storage.WestUS
DESCRIPTION_MAX = 140
ACCEPT = "accept_risky"  # the hooks' argument accepting a risky change (the page's second confirmation)


@dataclass
class Rule:
    """A security rule as read: its name, priority, direction, access, protocol, the destination ports, the sources and
    destinations (prefixes, tags, application security groups by name), its description, whether it is a default rule."""

    name: str
    priority: int
    direction: str
    access: str
    protocol: str
    ports: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    destinations: list = field(default_factory=list)
    description: str = ""
    default: bool = False
    source_ports: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"name": self.name, "priority": self.priority, "direction": self.direction, "access": self.access,
                "protocol": self.protocol, "ports": list(self.ports), "sources": list(self.sources),
                "destinations": list(self.destinations), "description": self.description, "default": self.default}


def _names(props: dict, one: str, many: str, groups: str) -> list[str]:
    out = [str(x) for x in (props.get(many) or []) if str(x).strip()]
    if props.get(one):
        out.insert(0, str(props[one]))
    out += [str(g.get("id") or "").rstrip("/").rsplit("/", 1)[-1] for g in (props.get(groups) or []) if isinstance(g, dict)]
    return [x for x in out if x]


def parse(data: dict, default: bool = False) -> Rule:
    """A rule from Azure's answer (an NSG's securityRules or defaultSecurityRules item)."""
    p = data.get("properties") or {}
    try:
        priority = int(p.get("priority") or 0)
    except (TypeError, ValueError):
        priority = 0
    return Rule(name=str(data.get("name") or ""), priority=priority, direction=str(p.get("direction") or ""),
                access=str(p.get("access") or ""), protocol=str(p.get("protocol") or "*"),
                ports=_names(p, "destinationPortRange", "destinationPortRanges", "_"),
                sources=_names(p, "sourceAddressPrefix", "sourceAddressPrefixes", "sourceApplicationSecurityGroups"),
                destinations=_names(p, "destinationAddressPrefix", "destinationAddressPrefixes", "destinationApplicationSecurityGroups"),
                description=str(p.get("description") or ""), default=default,
                source_ports=_names(p, "sourcePortRange", "sourcePortRanges", "_"))


def shown(items) -> str:
    """Ports or addresses in words: * as any."""
    vals = [str(x) for x in items or []]
    return ", ".join("any" if v == "*" else v for v in vals) or "any"


# -- what a rule covers -------------------------------------------------------------------------------------------------------
def port_ranges(ports) -> list[tuple[int, int]]:
    out = []
    for p in ports or []:
        s = str(p).strip()
        if s == "*":
            out.append((0, 65535))
        elif "-" in s:
            a, _, b = s.partition("-")
            try:
                out.append((int(a), int(b)))
            except ValueError:
                continue
        else:
            try:
                out.append((int(s), int(s)))
            except ValueError:
                continue
    return out


def covers_port(rule: Rule, port: int) -> bool:
    return rule.protocol in ("Tcp", "*") and any(a <= port <= b for a, b in port_ranges(rule.ports))


def every_port(rule: Rule) -> bool:
    return any(a <= 1 and b >= 65535 for a, b in port_ranges(rule.ports))


def from_everywhere(rule: Rule) -> bool:
    """Whether the rule's source is the whole internet (*, Internet, 0.0.0.0/0, ::/0)."""
    return any(str(s).strip().lower() in WIDE for s in rule.sources)


def lets_in(rule: Rule) -> list[str]:
    """What of SSH and RDP an inbound Allow rule lets in ([] when it is no such rule)."""
    if rule.direction != "Inbound" or rule.access != "Allow":
        return []
    return [w for w, p in (("SSH (port 22)", SSH), ("RDP (port 3389)", RDP)) if covers_port(rule, p)]


def risk_of_adding(rule: Rule, servers: list[str]) -> str:
    """Why adding `rule` is risky, in words ("" when it is not): an Allow inbound rule opening SSH, RDP or every port to
    the whole internet; an inbound Deny covering SSH or RDP on a group attached to `servers` (it may cut this PC off)."""
    if rule.direction != "Inbound":
        return ""
    if rule.access == "Allow" and from_everywhere(rule):
        opened = [w for w, p in (("SSH (port 22)", SSH), ("RDP (port 3389)", RDP)) if covers_port(rule, p)]
        if every_port(rule) and rule.protocol in ("Tcp", "Udp", "*"):
            return "it opens every port to the whole internet"
        if opened:
            return f"it opens {' and '.join(opened)} to the whole internet"
        return ""
    if rule.access == "Deny" and servers:
        cut = [w for w, p in (("SSH (port 22)", SSH), ("RDP (port 3389)", RDP)) if covers_port(rule, p)]
        if cut:
            return (f"it denies {' and '.join(cut)} on a group attached to {', '.join(servers)}: placed before the rule that "
                    "lets it in, it cuts this PC off")
    return ""


def risk_of_removing(rule: Rule, servers: list[str]) -> str:
    """Why removing `rule` is risky ("" when it is not): it is the inbound Allow letting SSH or RDP in to `servers`."""
    let = lets_in(rule)
    if let and servers:
        return f"it is the rule letting {' and '.join(let)} in to {', '.join(servers)}: without it, they may be cut off"
    return ""


# -- a rule as typed ---------------------------------------------------------------------------------------------------------
def choice(value, options, what: str) -> str:
    v = str(value or "").strip()
    for o in options:
        if v.lower() == o.lower():
            return o
    raise ValueError(f"{what} is one of {', '.join(options)}, not {value!r}")


def ports_of(value) -> list[str]:
    """Ports as typed (22; 80, 443; 8000-8100; * for every port)."""
    parts = [p.strip() for p in re.split(r"[,\s]+", str(value or "")) if p.strip()]
    if not parts:
        raise ValueError("no ports given: 22, 80, 443, 8000-8100, or * for every port")
    if "*" in parts:
        if len(parts) > 1:
            raise ValueError("* is every port: it stands alone")
        return ["*"]
    out = []
    for p in parts:
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", p)
        if not m:
            raise ValueError(f"{p!r} is not a port or a range of ports (0 to 65535)")
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (0 <= a <= 65535 and 0 <= b <= 65535 and a <= b):
            raise ValueError(f"{p!r} is not a port or a range of ports (0 to 65535)")
        out.append(p)
    return out


def addresses_of(value, what: str) -> list[str]:
    """Sources or destinations as typed: * (any), a service tag (Internet, VirtualNetwork, AzureLoadBalancer ...), or IP
    addresses and CIDRs, comma separated (a tag stands alone)."""
    parts = [p.strip() for p in re.split(r"[,\s]+", str(value or "")) if p.strip()]
    if not parts:
        return ["*"]
    if len(parts) == 1 and (parts[0] == "*" or (TAG.match(parts[0]) and not _ip(parts[0]))):
        return parts
    out = []
    for p in parts:
        if not _ip(p):
            raise ValueError(f"{p!r} is not an IP address or a CIDR ({what}; a service tag or * stands alone)")
        out.append(p)
    return out


def _ip(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


def rule_of(name, direction, access, protocol, ports, source, destination, priority, description=None) -> Rule:
    """A rule from what the page's form gives, each part checked; ValueError in words otherwise."""
    n = str(name or "").strip()
    if not NAME.match(n):
        raise ValueError(f"{n!r} is not a rule name: 1 to 80 letters, digits, _ . -, beginning with a letter or a digit")
    try:
        p = int(str(priority).strip())
    except (TypeError, ValueError):
        raise ValueError(f"the priority is a number, {PRIORITY[0]} to {PRIORITY[1]}") from None
    if not PRIORITY[0] <= p <= PRIORITY[1]:
        raise ValueError(f"the priority is {PRIORITY[0]} to {PRIORITY[1]} (the lower, the sooner it applies)")
    d = str(description or "").strip()
    if len(d) > DESCRIPTION_MAX or any(ord(c) < 32 for c in d):
        raise ValueError(f"a description is one line of at most {DESCRIPTION_MAX} characters")
    return Rule(name=n, priority=p, direction=choice(direction, DIRECTIONS, "the direction"),
                access=choice(access, ACCESSES, "the access"), protocol=choice(protocol, PROTOCOLS, "the protocol"),
                ports=ports_of(ports), sources=addresses_of(source, "the source"),
                destinations=addresses_of(destination, "the destination"), description=d, source_ports=["*"])


def body(rule: Rule) -> dict:
    """The rule's body for its PUT (Security Rules - Create Or Update): one port or address as the singular property,
    several as the plural."""
    props: dict = {"protocol": rule.protocol, "access": rule.access, "direction": rule.direction, "priority": rule.priority,
                   "sourcePortRange": "*"}
    for one, many, values in (("destinationPortRange", "destinationPortRanges", rule.ports),
                              ("sourceAddressPrefix", "sourceAddressPrefixes", rule.sources),
                              ("destinationAddressPrefix", "destinationAddressPrefixes", rule.destinations)):
        if len(values) == 1:
            props[one] = values[0]
        else:
            props[many] = list(values)
    if rule.description:
        props["description"] = rule.description
    return {"properties": props}


def said(rule: Rule) -> str:
    """A rule in words: Allow Inbound Tcp 22 from Internet to any, priority 300."""
    return (f"{rule.name}: {rule.access} {rule.direction.lower()} {'any protocol' if rule.protocol == '*' else rule.protocol} "
            f"to ports {shown(rule.ports)} from {shown(rule.sources)} to {shown(rule.destinations)}, priority {rule.priority}")
