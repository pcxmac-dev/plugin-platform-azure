"""Azure DNS's record sets as its reference gives them (https://learn.microsoft.com/en-us/rest/api/dns/record-sets, API
2018-05-01, read 2026-11-11): a record set is every record of one name and type in a zone (its records in the property of
its type: ARecords, AAAARecords, CNAMERecord, MXRecords, NSRecords, PTRRecords, SRVRecords, TXTRecords, caaRecords,
SOARecord), with one TTL for them all, its metadata and its etag. A record set is written whole (PUT) or deleted whole
(DELETE), so a change is a plan made over the record set read just before it, sent with that read's etag (If-Match; a new
one with If-None-Match: *): what someone changed meanwhile is never written over.

What is kept and refused, from Azure's own pages (Azure DNS zones and records, the FAQ): every other record set is left as
it is; a record set's metadata and TTL are kept; a CNAME stands alone at its name and never at the zone's apex; the SOA and
the apex NS record set are the zone's own (created and deleted with it): never written here; an alias record set (its
targetResource) is changed in the portal, as is a record set of a type this API version cannot show whole (an A, AAAA or
CNAME read back holding nothing: a Traffic Manager link, which 2018-05-01 does not show). A TXT value is sent as strings of
at most 255 characters ("you need to specify each TXT string separately"); the TTL is 1 to 2,147,483,647 seconds; a record
set holds at most 20 records (400 TXT records) and a zone 10,000 record sets (Azure DNS limits)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

TYPES = ("A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT")  # RecordType
FIELDS = {"A": "ARecords", "AAAA": "AAAARecords", "CAA": "caaRecords", "CNAME": "CNAMERecord", "MX": "MXRecords",
          "NS": "NSRecords", "PTR": "PTRRecords", "SOA": "SOARecord", "SRV": "SRVRecords", "TXT": "TXTRecords"}
SINGLE_VALUED = frozenset({"CNAME", "SOA"})  # "these record sets can only contain a single record"
WRITABLE = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR")  # what a record set here may be, in the order offered
REPLACES = frozenset({"A", "AAAA", "CNAME", "PTR"})  # set: the name's records of the type replaced; the rest added beside
NOTES = {  # what each type holds, its value's form, and what setting one does (the page's choices)
    "A": "an IPv4 address; replaces the name's A records",
    "AAAA": "an IPv6 address; replaces the name's AAAA records",
    "CNAME": "a host name the name stands for; it stands alone, never at @",
    "MX": "preference and mail server: 10 mail.example.com; added beside the others",
    "TXT": "text (SPF, DKIM, DMARC, a verification); added beside the others",
    "NS": "a subdomain's name server; added beside the others (not at @: the zone's own)",
    "SRV": "priority weight port target: 10 5 5060 sip.example.com; added beside the others",
    "CAA": 'flags tag value: 0 issue letsencrypt.org; added beside the others',
    "PTR": "a host name (a reverse zone's); replaces the name's PTR record",
}
TTL_MIN, TTL_MAX, TTL_DEFAULT = 1, 2_147_483_647, 3600
TTL_DDNS = 300  # a Dynamic DNS host's A record made here: kept short, so a new address is seen soon
MOST_RECORDS, MOST_TXT = 20, 400  # records per record set (TXT records per record set)
TXT_CHUNK = 255
LABEL = re.compile(r"^(?:\*|[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)$")
HOST_LABEL = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
CAA_TAG = re.compile(r"^[A-Za-z0-9]{1,15}$")


class Refusal(ValueError):
    """A change not made, and why: nothing was sent to Azure. `accept`: the hook's argument that, set, makes it anyway
    (the platform's page asks it as a second, explicit confirmation); None when nothing could make it."""

    def __init__(self, message: str, accept: str | None = None):
        super().__init__(message)
        self.accept = accept


@dataclass
class RecordSet:
    """A record set as read: its zone and resource group, its name in the zone (@ for the apex), its type, its TTL, its
    records as Azure gives them (`records`: dicts of its type's fields), its metadata, etag and alias target."""

    zone: str
    group: str
    name: str
    type: str
    ttl: int = TTL_DEFAULT
    records: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    etag: str = ""
    target: str = ""  # an alias record set's targetResource id ("" when it is none)
    fqdn: str = ""

    @property
    def values(self) -> list[str]:
        return [value_of(self.type, r) for r in self.records]

    @property
    def own(self) -> str:
        """Why the zone holds it as its own (never written here), or ""."""
        if self.type == "SOA":
            return "the zone's own SOA record (made and deleted with the zone)"
        if self.type == "NS" and self.name == "@":
            return "the zone's own name servers (made and deleted with the zone)"
        return ""

    @property
    def unwritable(self) -> str:
        """Why no change is written over it here, or "" (it is the zone's own, an alias, or read back empty)."""
        if self.own:
            return self.own
        if self.target:
            return f"an alias record set (of {self.target.rstrip('/').rsplit('/', 1)[-1]}): changed in the Azure portal"
        if not self.records and self.type in ("A", "AAAA", "CNAME"):
            return ("read back with no records: it may be a Traffic Manager link this API version does not show, so it "
                    "is changed in the Azure portal")
        return ""

    def as_dict(self) -> dict:
        return {"zone": self.zone, "group": self.group, "name": self.name, "type": self.type, "ttl": self.ttl,
                "values": self.values, "alias": self.target.rstrip("/").rsplit("/", 1)[-1] if self.target else "",
                "fqdn": self.fqdn}


def type_of(data: dict) -> str:
    """A record set's type from its resource type ("Microsoft.Network/dnszones/A") or its id."""
    t = str(data.get("type") or "")
    if "/" in t:
        return t.rsplit("/", 1)[-1].upper()
    parts = str(data.get("id") or "").rstrip("/").split("/")
    return parts[-2].upper() if len(parts) >= 2 else ""


def parse(zone: str, group: str, data: dict) -> RecordSet:
    """A record set from Azure's answer (a list's item, a get's or a put's answer)."""
    props = data.get("properties") or {}
    t = type_of(data)
    raw = props.get(FIELDS.get(t, ""), None)
    records = ([raw] if raw else []) if t in SINGLE_VALUED else [r for r in (raw or []) if isinstance(r, dict)]
    target = props.get("targetResource") or {}
    try:
        ttl = int(props.get("TTL") if props.get("TTL") is not None else TTL_DEFAULT)
    except (TypeError, ValueError):
        ttl = TTL_DEFAULT
    return RecordSet(zone=zone, group=group, name=str(data.get("name") or "@"), type=t, ttl=ttl, records=records,
                     metadata=dict(props.get("metadata") or {}), etag=str(data.get("etag") or ""),
                     target=str(target.get("id") or "") if isinstance(target, dict) else "", fqdn=str(props.get("fqdn") or ""))


def value_of(rtype: str, r: dict) -> str:
    """A record's value in words, as a zone file writes it."""
    if rtype == "A":
        return str(r.get("ipv4Address") or "")
    if rtype == "AAAA":
        return str(r.get("ipv6Address") or "")
    if rtype == "CNAME":
        return str(r.get("cname") or "")
    if rtype == "MX":
        return f"{r.get('preference', '')} {r.get('exchange', '')}".strip()
    if rtype == "NS":
        return str(r.get("nsdname") or "")
    if rtype == "PTR":
        return str(r.get("ptrdname") or "")
    if rtype == "SRV":
        return f"{r.get('priority', '')} {r.get('weight', '')} {r.get('port', '')} {r.get('target', '')}".strip()
    if rtype == "TXT":
        return "".join(str(s) for s in (r.get("value") or []))
    if rtype == "CAA":
        return f"{r.get('flags', 0)} {r.get('tag', '')} {r.get('value', '')}".strip()
    if rtype == "SOA":
        return f"{r.get('host', '')} {r.get('email', '')} {r.get('serialNumber', '')}".strip()
    return ""


# -- what is written ------------------------------------------------------------------------------------------------------
def record_type(value: str) -> str:
    t = str(value or "").strip().upper()
    if t == "SOA":
        raise Refusal("the SOA record is the zone's own: it is not written here")
    if t not in WRITABLE:
        raise ValueError(f"{value!r} is no record type here: {', '.join(WRITABLE)}")
    return t


def relative_name(name: str, zone: str) -> str:
    """A name as Azure DNS names it in `zone`: @ (the zone itself), www, home, *, _dmarc, a.b; the zone's own name given in
    full is taken off (home.example.com is home)."""
    n = str(name or "").strip().rstrip(".")
    z = zone.lower().rstrip(".")
    if n.startswith("@.") and n[2:].lower() == z:  # @.example.com, as the Dynamic DNS hosts are typed
        n = "@"
    if n.lower() == z or n == "@" or not n:
        if not n:
            raise ValueError("no name given: @ for the zone itself, www, home ...")
        return "@"
    if n.lower().endswith("." + z):
        n = n[: -len(z) - 1]
    labels = n.split(".")
    if len(n) > 253 or not all(LABEL.match(x) and (x != "*" or i == 0) for i, x in enumerate(labels)):
        raise ValueError(f"{str(name).strip()!r} is not a name in {zone}: @, www, home, *, _dmarc")
    return n.lower()


def host_name(value: str, what: str) -> str:
    """A host name a record points at (a CNAME's, an MX's exchange, an NS, a PTR, an SRV's target)."""
    h = str(value or "").strip().rstrip(".").lower()
    labels = h.split(".")
    if len(h) > 253 or len(labels) < 2 or not all(HOST_LABEL.match(x) for x in labels):
        raise ValueError(f"{value!r} is not a host name ({what})")
    return h


def number(value: str, what: str, low: int, high: int) -> int:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{what} is a number, {low} to {high}") from None
    if not low <= n <= high:
        raise ValueError(f"{what} is {low} to {high}")
    return n


def record_of(rtype: str, value: str) -> dict:
    """A record of `rtype` from its value as typed (a zone file's form); ValueError when it is none."""
    v = str(value or "").strip()
    if not v:
        raise ValueError("no value given")
    if rtype == "A":
        try:
            return {"ipv4Address": str(ipaddress.IPv4Address(v))}
        except ValueError:
            raise ValueError(f"{v!r} is not an IPv4 address (an A record's)") from None
    if rtype == "AAAA":
        try:
            return {"ipv6Address": str(ipaddress.IPv6Address(v))}
        except ValueError:
            raise ValueError(f"{v!r} is not an IPv6 address (an AAAA record's)") from None
    if rtype == "CNAME":
        return {"cname": host_name(v, "a CNAME record's")}
    if rtype == "NS":
        return {"nsdname": host_name(v, "an NS record's")}
    if rtype == "PTR":
        return {"ptrdname": host_name(v, "a PTR record's")}
    if rtype == "MX":
        parts = v.split()
        if len(parts) != 2:
            raise ValueError("an MX record is its preference and its mail server: 10 mail.example.com")
        return {"preference": number(parts[0], "an MX preference", 0, 65535), "exchange": host_name(parts[1], "an MX record's mail server")}
    if rtype == "SRV":
        parts = v.split()
        if len(parts) != 4:
            raise ValueError("an SRV record is its priority, weight, port and target: 10 5 5060 sip.example.com")
        return {"priority": number(parts[0], "an SRV priority", 0, 65535), "weight": number(parts[1], "an SRV weight", 0, 65535),
                "port": number(parts[2], "an SRV port", 0, 65535), "target": host_name(parts[3], "an SRV record's target")}
    if rtype == "CAA":
        parts = v.split(None, 2)
        if len(parts) != 3:
            raise ValueError("a CAA record is its flags, tag and value: 0 issue letsencrypt.org")
        tag = parts[1]
        if not CAA_TAG.match(tag):
            raise ValueError(f"{tag!r} is not a CAA tag (issue, issuewild, iodef)")
        text = parts[2].strip()
        if len(text) >= 2 and text[0] == text[-1] == '"':
            text = text[1:-1]
        if not text or any(ord(c) < 32 or ord(c) == 127 for c in text):
            raise ValueError("a CAA record's value is one line of text")
        return {"flags": number(parts[0], "CAA flags", 0, 255), "tag": tag.lower(), "value": text}
    if rtype == "TXT":
        if len(v) >= 2 and v[0] == v[-1] == '"':  # typed quoted, as a zone file writes it
            v = v[1:-1]
        if not v or any(ord(c) < 32 or ord(c) == 127 for c in v) or len(v) > 4096:
            raise ValueError("a TXT record's text is one line of at most 4,096 characters")
        return {"value": [v[i:i + TXT_CHUNK] for i in range(0, len(v), TXT_CHUNK)]}
    raise ValueError(f"{rtype!r} is no record type here")


def same(rtype: str, a: dict, b: dict) -> bool:
    """Whether two records of `rtype` are the same record (names in any case, TXT by its whole text)."""
    va, vb = value_of(rtype, a), value_of(rtype, b)
    if rtype in ("CNAME", "NS", "PTR", "MX", "SRV"):
        return va.lower().rstrip(".") == vb.lower().rstrip(".")
    if rtype in ("A", "AAAA"):
        try:
            return ipaddress.ip_address(va) == ipaddress.ip_address(vb)
        except ValueError:
            return va == vb
    return va == vb


def ttl_of(value) -> int:
    return number(value, "the TTL (seconds)", TTL_MIN, TTL_MAX)


# -- the plans ----------------------------------------------------------------------------------------------------------------
@dataclass
class Plan:
    """A change planned over the record set read just before it: what is sent (`records` None: the record set deleted),
    its TTL, whether the record set is new, and the change in words."""

    zone: str
    group: str
    name: str
    type: str
    records: list | None
    ttl: int
    metadata: dict
    etag: str
    new: bool
    said: str
    changed: bool = True

    def body(self) -> dict:
        """The record set's body for its PUT (Record Sets - Create Or Update)."""
        props: dict = {"TTL": self.ttl}
        if self.metadata:
            props["metadata"] = self.metadata
        key = FIELDS[self.type]
        props[key] = (self.records[0] if self.records else {}) if self.type in SINGLE_VALUED else list(self.records or [])
        return {"properties": props}


def said(name: str, rtype: str, value: str) -> str:
    short = value if len(value) <= 60 else value[:59] + "…"
    return f"{name} {rtype} {short}"


def plan_set(zone: str, group: str, name: str, rtype: str, value: str, held: RecordSet | None, others: list[str],
             ttl=None) -> Plan:
    """A record set (`rtype` at `name`) with a record set: an A, AAAA, CNAME or PTR record replaces the name's records of
    its type; an MX, TXT, NS, SRV or CAA record is added beside the others (or its TTL changed when it is there already).
    `held`: the record set as just read (None: there is none); `others`: the types the name holds besides (a CNAME's
    rule)."""
    t = record_type(rtype)
    n = relative_name(name, zone)
    record = record_of(t, value)
    if held is not None and held.unwritable:
        raise Refusal(f"{n} {t} in {zone} is {held.unwritable}")
    if t == "CNAME" and n == "@":
        raise Refusal("a CNAME cannot stand at the zone's apex (@): the zone's NS and SOA records are there")
    if t == "NS" and n == "@":
        raise Refusal("the NS records at @ are the zone's own name servers: they are not written here")
    if t == "CNAME" and others:
        raise Refusal(f"{n} holds other records ({', '.join(sorted(others))}): a CNAME stands alone at its name")
    if t != "CNAME" and "CNAME" in others:
        raise Refusal(f"{n} is a CNAME: it holds no {t} record beside it")
    shown = value_of(t, record)
    ttl_given = ttl_of(ttl) if ttl not in (None, "") else None
    base_ttl = held.ttl if held is not None else (TTL_DEFAULT if ttl_given is None else ttl_given)
    new_ttl = ttl_given if ttl_given is not None else base_ttl
    current = list(held.records) if held is not None else []
    meta = dict(held.metadata) if held is not None else {}
    etag = held.etag if held is not None else ""
    if t in REPLACES:
        if len(current) == 1 and same(t, current[0], record) and new_ttl == base_ttl:
            return Plan(zone, group, n, t, current, new_ttl, meta, etag, False, f"{said(n, t, shown)} is there already: nothing written",
                        changed=False)
        gone = [value_of(t, r) for r in current if not same(t, r, record)]
        words = (f"set {said(n, t, shown)}" + (f" (it was {', '.join(gone)})" if gone else "") if current
                 else f"added {said(n, t, shown)}")
        if current and not gone and new_ttl != base_ttl:
            words = f"{said(n, t, shown)}: TTL {new_ttl}"
        return Plan(zone, group, n, t, [record], new_ttl, meta, etag, held is None, words)
    if any(same(t, r, record) for r in current):
        if new_ttl == base_ttl:
            return Plan(zone, group, n, t, current, new_ttl, meta, etag, False, f"{said(n, t, shown)} is there already: nothing written",
                        changed=False)
        return Plan(zone, group, n, t, current, new_ttl, meta, etag, False, f"{said(n, t, shown)}: TTL {new_ttl}")
    most = MOST_TXT if t == "TXT" else MOST_RECORDS
    if len(current) >= most:
        raise Refusal(f"{n} {t} holds {len(current)} records already: a record set holds at most {most}")
    words = f"added {said(n, t, shown)}" + (f" beside {len(current)} other{'s' if len(current) != 1 else ''}" if current else "")
    return Plan(zone, group, n, t, [*current, record], new_ttl, meta, etag, held is None, words)


def plan_remove(zone: str, group: str, name: str, rtype: str, value: str, held: RecordSet | None) -> Plan:
    """The record set without one record (`value` names it); the last one removed deletes the record set."""
    t = str(rtype or "").strip().upper()
    if t not in TYPES:
        raise ValueError(f"{rtype!r} is no record type: {', '.join(TYPES)}")
    n = relative_name(name, zone)
    if held is None:
        raise Refusal(f"{zone} has no {t} record set at {n}")
    if held.unwritable:
        raise Refusal(f"{n} {t} in {zone} is {held.unwritable}")
    want = str(value or "").strip()
    try:
        probe = record_of(t, want) if want else None
    except ValueError:
        probe = None
    matches = [r for r in held.records if (probe is not None and same(t, r, probe)) or value_of(t, r) == want]
    if not want and len(held.records) > 1:
        raise Refusal(f"{n} holds {len(held.records)} {t} records: name the one to remove by its value")
    if not want and len(held.records) == 1:
        matches = list(held.records)
    if not matches:
        raise Refusal(f"{zone} has no {t} record at {n}" + (f" holding {want}" if want else ""))
    rest = [r for r in held.records if not any(r is m for m in matches)]
    words = "removed " + ", ".join(said(n, t, value_of(t, m)) for m in matches)
    if not rest:
        return Plan(zone, group, n, t, None, held.ttl, dict(held.metadata), held.etag, False, words + " (its record set deleted)")
    return Plan(zone, group, n, t, rest, held.ttl, dict(held.metadata), held.etag, False,
                words + f" ({len(rest)} {t} record{'s' if len(rest) != 1 else ''} kept)")


def plan_address(zone: str, group: str, name: str, address: str, held: RecordSet | None) -> Plan:
    """A Dynamic DNS host's A record set holding this network's address alone (its TTL and metadata kept; a new one
    TTL_DDNS)."""
    n = relative_name(name, zone)
    if held is not None and held.unwritable:
        raise Refusal(f"{n} A in {zone} is {held.unwritable}")
    record = record_of("A", address)
    if held is None:
        return Plan(zone, group, n, "A", [record], TTL_DDNS, {}, "", True, "made")
    return Plan(zone, group, n, "A", [record], held.ttl, dict(held.metadata), held.etag, False, "set")
