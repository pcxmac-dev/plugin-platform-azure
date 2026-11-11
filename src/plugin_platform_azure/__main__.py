"""`python -m plugin_platform_azure ...`: the plugin from the command line, its settings read from the environment (an
EnvironmentLogin: the variables as this shell has them).

    status                                   the subscription read, then the plugin's status (JSON)
    servers                                  the VMs: their power state, size, price and addresses
    groups | disks | ips | cost              the resource groups, the disks, the public IPs, the cost this month so far
    firewalls                                the network security groups and their rules
    domains                                  the Azure DNS zones
    records ZONE [--group G]                 a zone's record sets
    keys                                     the SSH public keys stored in Azure
    ddns [--now]                             a Dynamic DNS pass: a record set written where a host differs (--now: every host)
    power NAME start|restart|deallocate|poweroff [--group G]
                                             a VM's power changed, once you type yes (power off: twice, as it still bills)
    set ZONE NAME TYPE VALUE [--ttl N] [--group G]
                                             a record set, every other record kept, once you type yes
    remove ZONE NAME TYPE VALUE [--group G]  a record removed, the rest kept, once you type yes

--json prints the answer as JSON."""
from __future__ import annotations

import argparse
import json
import sys

from liminal_libs.machines.rest import RestError

from . import MACHINE, page
from . import rules as nsg_rules
from .page import BILLING, when

ALIASES = {"on": "start", "reboot": "restart", "off": "deallocate", "stop": "deallocate", "power-off": "poweroff",
           "poweroff": "poweroff", "start": "start", "restart": "restart", "deallocate": "deallocate"}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m plugin_platform_azure",
                                description="Microsoft Azure for Liminal: VMs, DNS, network security groups, SSH keys")
    p.add_argument("--json", action="store_true", help="print the answer as JSON")
    sub = p.add_subparsers(dest="what")
    sub.add_parser("status", help="the subscription read, then the plugin's status")
    for name in ("servers", "vms"):
        sub.add_parser(name, help="the VMs")
    for name in ("groups", "disks", "ips", "cost", "keys"):
        sub.add_parser(name, help=f"the {name}")
    for name in ("firewalls", "nsgs"):
        sub.add_parser(name, help="the network security groups and their rules")
    for name in ("domains", "zones"):
        sub.add_parser(name, help="the Azure DNS zones")
    r = sub.add_parser("records", help="a zone's record sets")
    r.add_argument("zone")
    r.add_argument("--group")
    d = sub.add_parser("ddns", help="a Dynamic DNS pass")
    d.add_argument("--now", action="store_true", help="every host's record set written, whether it differs or not")
    w = sub.add_parser("power", help="a VM's power changed")
    w.add_argument("name")
    w.add_argument("action", choices=sorted(ALIASES))
    w.add_argument("--group")
    s = sub.add_parser("set", help="a record set, every other record kept")
    for a in ("zone", "name", "type", "value"):
        s.add_argument(a)
    s.add_argument("--ttl", type=int)
    s.add_argument("--group")
    m = sub.add_parser("remove", help="a record removed, the rest kept")
    for a in ("zone", "name", "type", "value"):
        m.add_argument(a)
    m.add_argument("--group")
    return p


def confirmed(ask, say, words: str) -> bool:
    """The change in words, then yes typed on the terminal (anything else: nothing done)."""
    say(words)
    try:
        answer = ask("Type yes to go on: ")
    except EOFError:
        answer = ""
    return str(answer or "").strip().lower() == "yes"


def main(argv: list[str] | None = None, plugin=None, out=None, err=None, ask=None) -> int:
    p = plugin if plugin is not None else MACHINE
    say = out or (lambda s: print(s))
    tell = err or (lambda s: print(s, file=sys.stderr))
    ask = ask or input
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    what = args.what or "status"
    answer: object = None
    lines: list[str] = []
    try:
        if what == "status":
            if p.config().api_ready:
                try:
                    p.refresh()
                except (RestError, ValueError):
                    pass  # the status says it
            answer = p.status()
            say(json.dumps(answer, indent=1))
            return 0
        if what in ("servers", "vms"):
            p.refresh()
            snap = p.snapshot()
            answer = [{**v, "price": p._price_for(v)[0]} for v in snap.vms]
            for v in answer:
                price = f"{page.money(v['price']['hour'], v['price']['currency'])}/h" if v.get("price") else "–"
                lines.append(f"{v['name']:<24} {v['group']:<20} {v['power'] or '?':<12} {v['size']:<20} {price:<16} "
                             f"{', '.join(v['ipv4']) or '–'}")
            lines = lines or ["no VMs in the subscription"]
            lines.append(BILLING)
        elif what in ("groups", "disks", "ips", "keys"):
            p.refresh()
            snap = p.snapshot()
            answer = getattr(snap, what)
            if what == "groups":
                lines = [f"{g['name']:<32} {g['location']:<16} {snap.by_group.get(g['name'].lower(), 0)} resources" for g in answer]
            elif what == "disks":
                lines = [f"{d['name']:<32} {d['group']:<20} {d['sizeGb']} GiB {d['sku']:<14} {d['state']:<12} {d['vm'] or '–'}"
                         for d in answer]
            elif what == "ips":
                lines = [f"{x['name']:<28} {x['address'] or '–':<16} {x['allocation']:<8} {x['where'] or 'not attached'}"
                         for x in answer]
            else:
                lines = [f"{k['name']:<28} {k['group']:<20} {k['key']}" for k in answer]
            lines = lines or [f"no {what}"]
        elif what == "cost":
            p.refresh()  # the cost asked with it when it is due (at most every six hours: Cost Management throttles hard)
            with p._rt.lock:
                answer = {"cost": p._rt.cost, "error": p._rt.cost_error, "at": p._rt.cost_at}
            c = answer["cost"]
            lines = [f"{page.money(c['amount'], c['currency'])} this month so far (read {when(answer['at'])})" if c and not answer["error"]
                     else f"not read: {answer['error']}"]
        elif what in ("firewalls", "nsgs"):
            p.refresh()
            answer = p.nsgs()
            for g in answer:
                lines.append(f"{g['name']} ({g['group']}): attached to {', '.join(g['servers']) or 'no VM'}")
                for r in g["rules"]:
                    rule = nsg_rules.Rule(**{k: v for k, v in r.items()})
                    lines.append(f"  {nsg_rules.said(rule)}")
            lines = lines or ["no network security groups"]
        elif what in ("domains", "zones"):
            answer = p.zones()
            lines = [f"{z['name']:<32} {z['group']:<20} {z['sets']} record sets  {', '.join(z['servers'][:2])}" for z in answer]
            lines = lines or ["no Azure DNS zones"]
        elif what == "records":
            answer = p.records(args.zone, args.group)
            lines = [f"  {s['name']:<24} {s['type']:<6} {v}  ttl {s['ttl']}" for s in answer for v in (s["values"] or [f"alias of {s['alias']}" if s["alias"] else "–"])]
        elif what == "ddns":
            answer = p.ddns_update(force=args.now)
            lines = [f"{h['host']:<32} {h['address'] or '–':<16} {h['result']} (checked {when(h['checkedAt'])})" for h in answer]
        elif what == "power":
            action = ALIASES[args.action]
            p.refresh()
            snap = p.snapshot()
            found = [v for v in snap.vm_named(args.name) if not args.group or v["group"].lower() == args.group.lower()]
            if len(found) != 1:
                tell(f"refused: {args.name} is " + ("none of the subscription's VMs" if not found else
                                                    f"in {len(found)} resource groups: name one with --group"))
                return 1
            v = found[0]
            words = {"start": f"{v['name']} is started: its compute is billed again from then on.",
                     "restart": f"{v['name']} is restarted: what is not saved is lost; it stays billed.",
                     "deallocate": f"{v['name']} is deallocated: its compute is no longer billed (its disks still are).",
                     "poweroff": f"{v['name']} is powered off: it is STILL BILLED for its compute, as if it ran."}[action]
            if not confirmed(ask, say, words):
                tell("nothing done")
                return 1
            accept = False
            if action == "poweroff":
                if not confirmed(ask, say, "Powered off, it still bills; deallocate stops that charge. Power it off anyway?"):
                    tell("nothing done")
                    return 1
                accept = True
            answer = p.power(v["group"], v["name"], action, accept_still_billed=accept)
            lines = [answer["said"], *(f"  {x}" for x in answer["lines"])]
        else:  # set, remove
            z = p._zone(args.zone, args.group)
            if what == "set":
                words = f"{args.name} {args.type.upper()} {args.value} is set in {z['name']} (every other record kept)."
            else:
                words = f"{args.name} {args.type.upper()} {args.value} is removed from {z['name']} (the rest kept)."
            if not confirmed(ask, say, words):
                tell("nothing done")
                return 1
            if what == "set":
                answer = p.set_record(z["group"], z["name"], args.name, args.type, args.value, ttl=args.ttl)
            else:
                answer = p.remove_record(z["group"], z["name"], args.name, args.type, args.value)
            lines = [answer["said"], *(f"  {x}" for x in answer.get("lines") or [])]
    except RestError as e:
        tell(f"azure: {e}")
        return 1
    except (ValueError, RuntimeError) as e:  # a refusal (records.Refusal), a setting not set, a pass under way
        tell(f"refused: {e}")
        return 1
    if args.json:
        say(json.dumps(answer, indent=1, default=lambda o: getattr(o, "as_dict", lambda: str(o))()))
    else:
        for line in lines:
            say(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
