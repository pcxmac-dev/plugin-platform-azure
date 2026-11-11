"""What the platform's page draws of the plugin (liminal-platform's status.tables, actions and forms): the tables of what was
read last, the buttons that ask a hook, and the forms whose changes the page confirms first (a risky one a second time,
when the hook refuses it naming its `accept` argument). Nothing here asks Azure anything."""
from __future__ import annotations

import time

from . import records as recs
from . import rules as nsg_rules
from .api import HOURS_A_MONTH
from .model import POWER, SHOWN, Snapshot, kind_of, zone_key

ACCEPT_BILLED = "accept_still_billed"  # power off: the VM still bills, accepted on a second confirmation
ACCEPT_RISKY = nsg_rules.ACCEPT
BILLING = ("A VM stopped with Power off, or shut down from inside its OS, is still billed for its compute (Azure: Stopped); "
           "one deallocated is not, though its disks and static public IPs still bill.")
ACTIONS = {  # a VM's power change: the hook's action, the button, the states it is offered in
    "start": ("Start", ("stopped", "deallocated", "hibernated")),
    "restart": ("Restart", ("running",)),
    "deallocate": ("Deallocate", ("running", "stopped")),
    "poweroff": ("Power off", ("running",)),
}


def when(t: float | None) -> str:
    return "–" if not t else time.strftime("%b %d %H:%M", time.localtime(t))


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n:,} {word if n == 1 else many or word + 's'}"


def cell(text, sub: str | None = None):
    return {"text": text, "sub": sub} if sub else text


def money(amount: float, currency: str = "USD") -> str:
    digits = 4 if 0 < abs(amount) < 1 else 2  # a VM's price an hour in four places, the rest in two
    return f"{amount:,.{digits}f} {currency}".strip()


def day(stamp: str) -> str:
    return str(stamp or "")[:10] or "–"


DEALLOCATED = ("deallocated", "hibernated")  # its compute not billed: a Start bills it again


def start_form(power: str) -> str:
    """The Start form for a VM in this power state (as read): a deallocated VM's Start starts its compute charge again; a
    stopped (powered-off, still allocated) VM was billing all along."""
    return "vm:start-deallocated" if power in DEALLOCATED else "vm:start-stopped"


def start_words(power: str) -> str:
    """What starting a VM in this power state does to the bill, in words."""
    if power in DEALLOCATED:
        return "it was deallocated: starting it starts its compute charge again, by the hour"
    return "it was stopped but still allocated: it has been billed for its compute all along, so the bill does not change"


def price_cells(price: dict | None, why: str = "") -> object:
    if not price:
        return cell("–", why or None)
    hour = price["hour"]
    return cell(f"{money(hour, price['currency'])} an hour", f"about {money(hour * HOURS_A_MONTH, price['currency'])} a month")


# -- the tables -----------------------------------------------------------------------------------------------------------
def vm_table(snap: Snapshot, prices: dict, writable: bool) -> dict:
    """The VMs (`prices`: each VM's price an hour by its key, with why there is none)."""
    rows = []
    for v in snap.vms:
        words, billed = POWER.get(v["power"], (v["powerWords"] or "not known", None))
        bill = "compute billed" if billed else "compute not billed" if billed is False else "billing not known"
        os_words = " · ".join(x for x in (v["os"], v["image"], "spot" if v["priority"].lower() == "spot" else "") if x)
        price, why = prices.get(v["key"]) or (None, "")
        row = [cell(v["name"], f"{v['group']} · {v['location']}"), cell(words, bill), cell(v["size"] or "–", os_words or None),
               price_cells(price, why), ", ".join(v["ipv4"]) or "–", ", ".join(v["ipv6"]) or "–", day(v["created"])]
        if writable:
            for action, (title, states) in ACTIONS.items():
                form = start_form(v["power"]) if action == "start" else f"vm:{action}"
                row.append({"form": form, "title": title, "label": f"{title} {v['name']}",
                            "values": {"group": v["group"], "name": v["name"], "action": action}}
                           if v["power"] in states else "")
        rows.append(row)
    trouble = snap.troubles.get("vms")
    partly = [f"{what} not read: {snap.troubles[part]}" for part, what in (("states", "power states"), ("nics", "addresses"),
                                                                           ("ips", "public addresses")) if snap.troubles.get(part)]
    said = [BILLING, f"Prices: Azure's retail prices (pay as you go, {int(HOURS_A_MONTH)} hours a month)."]
    if snap.views:
        said.append(f"{plural(snap.views, 'power state')} asked one by one.")
    if partly:
        said.append(f"{'; '.join(partly)}.")
    note = f"not read: {trouble}" if trouble else " ".join(said)
    columns = [{"title": "VM"}, {"title": "State"}, {"title": "Size"}, {"title": "Price"}, {"title": "Public IPv4"},
               {"title": "Public IPv6"}, {"title": "Created"}]
    if writable:
        columns += [{"title": ""}, {"title": ""}, {"title": ""}, {"title": ""}]
    return {"title": "Virtual machines", "note": note, "columns": columns, "rows": rows, "empty": "No VMs in the subscription."}


def disk_table(snap: Snapshot) -> dict:
    rows = [[cell(d["name"], d["group"]), str(d["sizeGb"]) if d["sizeGb"] is not None else "–", d["sku"] or "–",
             d["state"] or "–", d["vm"] or "–", d["location"], day(d["created"])] for d in snap.disks]
    trouble = snap.troubles.get("disks")
    return {"title": "Disks", "note": f"not read: {trouble}" if trouble else
            "managed disks bill whether their VM runs, is deallocated or has none",
            "columns": [{"title": "Disk"}, {"title": "GiB", "num": True}, {"title": "SKU"}, {"title": "State"},
                        {"title": "VM"}, {"title": "Location"}, {"title": "Created"}],
            "rows": rows, "empty": "No managed disks."}


def ip_table(snap: Snapshot) -> dict:
    rows = [[cell(x["name"], x["group"]), x["address"] or "–", x["version"], x["allocation"] or "–",
             " ".join(y for y in (x["sku"], x["tier"]) if y) or "–", x["where"] or "not attached", x["fqdn"] or "–"]
            for x in snap.ips]
    trouble = snap.troubles.get("ips")
    return {"title": "Public IP addresses",
            "note": f"not read: {trouble}" if trouble else "a dynamic address is released when its VM is deallocated",
            "columns": [{"title": "Name"}, {"title": "Address"}, {"title": "Version"}, {"title": "Allocation"},
                        {"title": "SKU"}, {"title": "On"}, {"title": "DNS name"}],
            "rows": rows, "empty": "No public IP addresses."}


def nsg_tables(snap: Snapshot, writable: bool) -> list:
    out = []
    trouble = snap.troubles.get("nsgs")
    overview = [[cell(g["name"], f"{g['group']} · {g['location']}"), str(len(g["rules"])),
                 ", ".join(g["servers"]) or "no VM", f"{plural(g['nics'], 'interface')}, {plural(g['subnets'], 'subnet')}"]
                for g in snap.nsgs]
    out.append({"title": "Network security groups", "note": f"not read: {trouble}" if trouble else
                "Azure's firewalls: each group's rules apply where it is attached (a VM's network interface or its subnet)",
                "columns": [{"title": "Group"}, {"title": "Rules", "num": True}, {"title": "VMs"}, {"title": "Attached to"}],
                "rows": overview, "empty": "No network security groups."})
    for g in snap.nsgs:
        rows = []
        for r in [*g["rules"], *g["defaults"]]:
            row = [str(r.priority), cell(r.name, "default" if r.default else (r.description or None)), r.direction, r.access,
                   "any" if r.protocol == "*" else r.protocol, nsg_rules.shown(r.ports), nsg_rules.shown(r.sources),
                   nsg_rules.shown(r.destinations)]
            if writable:
                row.append("" if r.default else {"form": f"rule-remove:{g['group']}/{g['name']}", "title": "Remove",
                                                  "label": f"Remove {r.name} from {g['name']}",
                                                  "values": {"group": g["group"], "nsg": g["name"], "name": r.name}})
            rows.append(row)
        table = {"title": f"{g['name']} rules", "note": (
            f"{g['group']} · attached to {', '.join(g['servers']) or 'no VM'} · the lower the priority, the sooner a rule "
            "applies; the default rules are the group's own"),
            "columns": [{"title": "Priority", "num": True}, {"title": "Rule"}, {"title": "Direction"}, {"title": "Access"},
                        {"title": "Protocol"}, {"title": "Ports"}, {"title": "Source"}, {"title": "Destination"},
                        *([{"title": ""}] if writable else [])],
            "rows": rows, "empty": "No rules."}
        if writable:
            table["actions"] = [{"form": f"rule-add:{g['group']}/{g['name']}", "title": "Add a rule…"}]
        out.append(table)
    return out


def zone_tables(snap: Snapshot, writable: bool) -> list:
    out = []
    trouble = snap.troubles.get("zones")
    rows = [[cell(z["name"], z["group"]), f"{z['sets']} of {z['most']}" if z["sets"] is not None else "–",
             ", ".join(z["servers"][:2]) + (" …" if len(z["servers"]) > 2 else "") or "–"] for z in snap.zones]
    out.append({"title": "DNS zones", "note": f"not read: {trouble}" if trouble else
                "Azure DNS: each zone billed by the month, its queries by the million; its records cost nothing more",
                "columns": [{"title": "Zone"}, {"title": "Record sets"}, {"title": "Name servers"}], "rows": rows,
                "empty": "No DNS zones in Azure DNS."})
    for z in snap.zones:
        held = snap.records.get(z["key"])
        if not isinstance(held, list):
            out.append({"title": f"{z['name']} records", "note": str(held or "not read"), "columns": [{"title": "Name"}],
                        "rows": [], "empty": "Not read."})
            continue
        rows = []
        for s in sorted(held, key=lambda s: (s.name != "@", s.name.lower(), s.type)):
            why = s.unwritable
            values = s.values or ([f"alias of {s.as_dict()['alias']}"] if s.target else ["–"])
            for value in values:
                short = value if len(value) <= 64 else value[:63] + "…"
                row = [s.name, s.type, cell(short, why if why and s.target else None), str(s.ttl)]
                if writable:
                    row.append("" if why or not s.records else
                               {"form": f"record-remove:{z['group']}/{z['name']}", "title": "Remove",
                                "label": f"Remove {s.name} {s.type} {short}",
                                "values": {"group": z["group"], "zone": z["name"], "name": s.name, "rtype": s.type,
                                           "value": value}})
                rows.append(row)
        table = {"title": f"{z['name']} records",
                 "note": (f"{z['group']} · set and removed here: each record set written whole, with every other record "
                          "kept and only if no one changed it since it was read" if writable else
                          f"{z['group']} · set and removed once the API works"),
                 "columns": [{"title": "Name"}, {"title": "Type"}, {"title": "Value"}, {"title": "TTL", "num": True},
                             *([{"title": ""}] if writable else [])],
                 "rows": rows, "empty": "No record sets."}
        if writable:
            table["actions"] = [{"form": f"record-set:{z['group']}/{z['name']}", "title": "Set a record…"}]
        out.append(table)
    return out


def key_table(snap: Snapshot, writable: bool) -> dict:
    rows = []
    for k in snap.keys:
        row = [cell(k["name"], k["group"]), k["location"], k["key"]]
        if writable:
            row.append({"form": "key-remove", "title": "Remove", "label": f"Remove the SSH key {k['name']}",
                        "values": {"group": k["group"], "name": k["name"]}})
        rows.append(row)
    trouble = snap.troubles.get("keys")
    table = {"title": "SSH public keys", "note": f"not read: {trouble}" if trouble else
             "keys kept as Azure resources, offered when a VM is made (a VM keeps the keys it was made with)",
             "columns": [{"title": "Key"}, {"title": "Location"}, {"title": "Public key"}, *([{"title": ""}] if writable else [])],
             "rows": rows, "empty": "No SSH public keys stored in Azure."}
    if writable:
        table["actions"] = [{"form": "key-add", "title": "Add an SSH key…"}]
    return table


def group_table(snap: Snapshot) -> dict:
    rows = [[g["name"], g["location"], g["state"] or "–", str(snap.by_group.get(g["name"].lower(), 0))] for g in snap.groups]
    trouble = snap.troubles.get("groups")
    return {"title": "Resource groups", "note": f"not read: {trouble}" if trouble else "",
            "columns": [{"title": "Group"}, {"title": "Location"}, {"title": "State"}, {"title": "Resources", "num": True}],
            "rows": rows, "empty": "No resource groups."}


def others_table(snap: Snapshot) -> dict:
    rows = [[kind_of(t), str(n)] for t, n in sorted(snap.counts.items(), key=lambda kv: (-kv[1], kv[0])) if t not in SHOWN]
    trouble = snap.troubles.get("resources")
    return {"title": "Other resources", "note": f"not read: {trouble}" if trouble else
            "everything else the subscription holds, by kind (one list of its resources)",
            "columns": [{"title": "Kind"}, {"title": "How many", "num": True}], "rows": rows, "empty": "Nothing else."}


# -- the forms --------------------------------------------------------------------------------------------------------------
def vm_forms() -> list:
    """The power changes, each a form over the hook `power` (group, name, action, accept_still_billed), its confirmation
    saying what it bills: two Start forms, the row's button naming the one for its VM's power state as read (a deallocated
    VM's compute charge starts again; a stopped one was billing all along), each asked once."""
    fixed = [{"name": "group", "label": "Resource group", "type": "fixed"}, {"name": "name", "label": "VM", "type": "fixed"}]
    accept = {"name": ACCEPT_BILLED, "type": "accept", "title": "Power it off anyway?", "yes": "Power off anyway",
              "words": ("Powered off, {name} keeps its place on its host and is billed for its compute by the hour, as when "
                        "it runs. Deallocate is what stops that charge.")}
    words = {
        "start-deallocated": ("Start this VM?", "{name} in {group} is deallocated, so its compute is not billed now. "
                              "Starting it STARTS ITS COMPUTE CHARGE AGAIN, by the hour (its price is in the table), and a "
                              "dynamic public IP may come back as another address.", "Start it", False),
        "start-stopped": ("Start this VM?", "{name} in {group} is stopped (powered off) but still allocated: it has been "
                          "billed for its compute all along, so starting it adds no charge.", "Start it", False),
        "restart": ("Restart this VM?", "{name} in {group} is restarted: its operating system restarts, and what is not "
                    "saved is lost. It stays allocated and billed.", "Restart it", True),
        "deallocate": ("Deallocate this VM?", "{name} in {group} is shut down and its compute released: its compute is no "
                       "longer billed (its disks and a static public IP still are). A dynamic public IP is released (it "
                       "gets another when it starts again), and data on its temporary disk may be lost.", "Deallocate it", True),
        "poweroff": ("Power off this VM?", "{name} in {group} is shut down but keeps its place on its host: it is STILL "
                     "BILLED for its compute, as if it were running. Deallocate it instead to stop the charge. You are "
                     "asked once more.", "Power it off", True),
    }
    out = []
    for form, (head, text, yes, danger) in words.items():
        action = form.split("-", 1)[0]
        fields = [*fixed, {"name": "action", "label": "Change", "type": "fixed", "value": action}, accept]
        out.append({"id": f"vm:{form}", "hook": "power", "title": f"{ACTIONS[action][0]} a VM", "fields": fields,
                    "confirm": {"title": head, "words": text, "yes": yes, "danger": danger}})
    return out


def record_forms(z: dict) -> list:
    g, name = z["group"], z["name"]
    fixed = [{"name": "group", "label": "Resource group", "type": "fixed", "value": g},
             {"name": "zone", "label": "Zone", "type": "fixed", "value": name}]
    kept = ("Every other record set is kept; the record set is written whole, and only if no one changed it since it was "
            "read just before (its etag).")
    return [
        {"id": f"record-set:{g}/{name}", "hook": "set_record", "title": f"Set a record in {name}",
         "note": ("An A, AAAA, CNAME or PTR record replaces the name's records of its type; an MX, TXT, NS, SRV or CAA record "
                  "is added beside the others."),
         "fields": [*fixed,
                    {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "@, www, home",
                     "note": f"@ is {name} itself; home is home.{name}"},
                    {"name": "rtype", "label": "Type", "type": "choice", "value": "A",
                     "choices": [{"value": t, "title": t, "note": recs.NOTES[t]} for t in recs.WRITABLE]},
                    {"name": "value", "label": "Value", "type": "text", "required": True,
                     "placeholder": "an address, a host name or text, as its type says"},
                    {"name": "ttl", "label": "TTL (seconds)", "type": "number", "min": recs.TTL_MIN, "max": recs.TTL_MAX,
                     "placeholder": str(recs.TTL_DEFAULT), "empty": f"the record set's own, else {recs.TTL_DEFAULT}"}],
         "submit": "Review the change",
         "confirm": {"title": f"Set this record in {name}?", "words": "{name} {rtype} {value} is set in {zone}. " + kept,
                     "yes": "Set the record"}},
        {"id": f"record-remove:{g}/{name}", "hook": "remove_record", "title": f"Remove a record from {name}",
         "fields": [*fixed, {"name": "name", "label": "Name", "type": "fixed"}, {"name": "rtype", "label": "Type", "type": "fixed"},
                    {"name": "value", "label": "Value", "type": "fixed"}],
         "confirm": {"title": f"Remove this record from {name}?",
                     "words": "{name} {rtype} {value} is removed from {zone}: the name's other {rtype} records stay, and "
                              "the last one removed deletes its record set. " + kept,
                     "yes": "Remove the record", "danger": True}},
    ]


def rule_forms(g: dict) -> list:
    rg, nsg = g["group"], g["name"]
    fixed = [{"name": "group", "label": "Resource group", "type": "fixed", "value": rg},
             {"name": "nsg", "label": "Security group", "type": "fixed", "value": nsg}]
    accept = {"name": ACCEPT_RISKY, "type": "accept", "title": "Go on anyway?", "yes": "Yes, I accept the risk",
              "words": ("This change may open a VM to the whole internet or cut this PC off from it (SSH, RDP). Azure "
                        "applies it within moments.")}
    servers = ", ".join(g["servers"]) or "no VM"
    return [
        {"id": f"rule-add:{rg}/{nsg}", "hook": "add_rule", "title": f"Add a rule to {nsg}",
         "note": (f"{nsg} is attached to {servers}. The rule gets a name of its own; one of that name, or a priority "
                  "another rule of its direction holds, is refused. A rule opening SSH, RDP or every port to the whole "
                  "internet, or denying SSH or RDP to a VM, is asked twice."),
         "fields": [*fixed,
                    {"name": "name", "label": "Rule name", "type": "text", "required": True, "placeholder": "allow-ssh-home"},
                    {"name": "direction", "label": "Direction", "type": "choice", "value": "Inbound",
                     "choices": [{"value": d, "title": d} for d in nsg_rules.DIRECTIONS]},
                    {"name": "access", "label": "Access", "type": "choice", "value": "Allow",
                     "choices": [{"value": a, "title": a} for a in nsg_rules.ACCESSES]},
                    {"name": "protocol", "label": "Protocol", "type": "choice", "value": "Tcp",
                     "choices": [{"value": p, "title": "any" if p == "*" else p} for p in nsg_rules.PROTOCOLS]},
                    {"name": "ports", "label": "Destination ports", "type": "text", "required": True,
                     "placeholder": "22, 80, 443, 8000-8100 or *"},
                    {"name": "source", "label": "Source", "type": "text", "placeholder": "your address, a CIDR, Internet or *",
                     "empty": "* (any source)"},
                    {"name": "destination", "label": "Destination", "type": "text", "placeholder": "* or a CIDR",
                     "empty": "* (any destination)"},
                    {"name": "priority", "label": "Priority", "type": "number", "min": nsg_rules.PRIORITY[0],
                     "max": nsg_rules.PRIORITY[1], "required": True, "placeholder": "300"},
                    {"name": "description", "label": "Description", "type": "text", "placeholder": "optional",
                     "empty": "none"},
                    accept],
         "submit": "Review the rule",
         "confirm": {"title": f"Add this rule to {nsg}?",
                     "words": ("{name}: {access} {direction} {protocol} to ports {ports} from {source} to {destination}, "
                               "priority {priority}, is added to {nsg}. Its other rules are kept."),
                     "yes": "Add the rule"}},
        {"id": f"rule-remove:{rg}/{nsg}", "hook": "remove_rule", "title": f"Remove a rule from {nsg}",
         "fields": [*fixed, {"name": "name", "label": "Rule", "type": "fixed"}, accept],
         "confirm": {"title": f"Remove this rule from {nsg}?",
                     "words": "{name} is removed from {nsg} (attached to " + servers + "). Its other rules are kept.",
                     "yes": "Remove the rule", "danger": True}},
    ]


def key_forms(groups: list) -> list:
    return [
        {"id": "key-add", "hook": "add_ssh_key", "title": "Add an SSH public key",
         "note": ("Stored in Azure as a resource of its own (it costs nothing), to be offered when a VM is made: RSA of 2048 "
                  "bits or more, or ED25519, the one line of its .pub file."),
         "fields": [{"name": "group", "label": "Resource group", "type": "choice",
                     "choices": [{"value": g["name"], "title": g["name"], "note": g["location"]} for g in groups]},
                    {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "my-laptop"},
                    {"name": "public_key", "label": "Public key", "type": "text", "required": True,
                     "placeholder": "ssh-ed25519 AAAA… you@host"},
                    {"name": "location", "label": "Location", "type": "text", "placeholder": "the group's",
                     "empty": "the resource group's location"}],
         "submit": "Review the key",
         "confirm": {"title": "Add this SSH key?", "words": "{name} is stored in {group}: {public_key}", "yes": "Add the key"}},
        {"id": "key-remove", "hook": "remove_ssh_key", "title": "Remove an SSH public key",
         "fields": [{"name": "group", "label": "Resource group", "type": "fixed"}, {"name": "name", "label": "Key", "type": "fixed"}],
         "confirm": {"title": "Remove this SSH key?",
                     "words": ("{name} in {group} is deleted from Azure. Keys aren't tied to a VM: a VM made with it keeps "
                               "the key it was made with."),
                     "yes": "Remove the key", "danger": True}},
    ]


def zones_writable(snap: Snapshot) -> list:
    return [z for z in snap.zones if isinstance(snap.records.get(zone_key(z["group"], z["name"])), list)]
