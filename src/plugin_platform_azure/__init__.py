"""Microsoft Azure for Liminal (the user, 2026-11-11: "lets roll plugins for EC2, vultr, azure and google cloud"; "Free changes
only"): a subscription through Azure Resource Manager, as a service principal sees it: the subscription and its resource
groups, the VMs with their power state, size and price an hour (Azure's Retail Prices API), disks, public IP addresses,
network security groups and their rules with the VMs they are attached to, Azure DNS zones and their records, SSH public
keys, the cost this month so far and how many of every other kind of resource it holds. It changes only what costs
nothing, each change confirmed on the platform's page first: a VM started (a deallocated one's compute charge starts
again: asked twice, its state read just before), restarted or deallocated (which stops its compute's charge), or powered
off (which does not: said so, and asked twice); DNS records set and removed (every other record kept); network security
rules added and removed (never one replaced; a risky one asked twice); SSH public keys added and removed (never one
replaced); and Dynamic DNS keeping hosts at this network's public IPv4 address through Azure DNS (the library's Keeper:
only a record that is its own, or that the user let it take over). Nothing that creates, resizes, restores or destroys a
billable thing.

Its settings are pairs asked of the login of the app it is attached to (settings.py: AZURE_TENANT_ID, AZURE_CLIENT_ID,
AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID, AZURE_DDNS_HOSTS, AZURE_DDNS_MINUTES), never a file of its own. Attached to the
platform app it reads the subscription every quarter of an hour and checks the Dynamic DNS hosts every few minutes in a
thread of its own (attached by another app, the charts app run alone, nothing of it runs on its own); detached, nothing
of it runs, and a pass under way writes nothing more. A read that failed for a passing reason (no connection, Azure busy)
leaves it valid, says so, and is tried again within minutes. Its status is what was read last (no request is made to
answer it).

    python -m plugin_platform_azure status | servers | groups | disks | ips | firewalls | domains | records ZONE | keys
        | cost | ddns [--now] | power NAME start|restart|deallocate|poweroff | set ZONE NAME TYPE VALUE | remove ZONE NAME TYPE VALUE
"""
from __future__ import annotations

import os
import threading
import time
from collections.abc import Mapping
from pathlib import Path

from liminal_libs.machines import ddns as dyndns
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.machines.rest import RestError, scrub

from . import model
from . import page
from . import records as recs
from . import rules as nsg_rules
from . import settings as settings_mod
from .api import HOURS_A_MONTH, AzureApi, pick_price, power_of, statuses_of
from .card import APIS, ARM_NAME, DNS_NAME, IDENTITY_NAME, PRICES_NAME
from .page import ACCEPT_BILLED, ACCEPT_COSTS, ACCEPT_RISKY, BILLING, plural, when
from .records import Refusal
from .settings import CREDENTIALS, KEYS, NAMES, Config

__version__ = "0.1.1"
REFRESH_S = 900.0  # the subscription read again at most this often while attached (or by Refresh)
CONFIG_S = 30.0  # the settings asked of the login again after this long
RETRY_S = 900.0  # a read that failed is taken as untried after this long while detached: attached again, it is tried again
RETRY_SOON_S = 60.0  # a read that failed for a passing reason tried again after this, then twice as long each time
ZONES_MAX = 12  # the zones whose record sets a refresh reads (the rest: `records ZONE`)
VIEWS_MAX = 10  # the VMs whose power state a refresh asks one by one when the list did not give it
PRICES_MAX = 20  # the VM sizes a refresh asks the price of (the rest the next time)
PRICE_KEEP_S = 86_400.0  # a size's price kept a day
COST_S = 6 * 3600.0  # the cost this month asked at most this often (Cost Management throttles hard)
SOON_S = 45.0  # after a power change, the VMs' states read again this soon (one request)
DIR_VAR = "LIMINAL_PLATFORM_DIR"  # the platform's own folder (its app's variable): the Dynamic DNS state goes under it
# the name servers asked for this network's public IPv4 address (dns.public_address): the plugin names them, as hw-stats does
PUBLIC_IPV4 = (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"), ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))
NOT_SET = ("not set up: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_SUBSCRIPTION_ID, a service "
           "principal's: an app registered in the Microsoft Entra admin center (https://entra.microsoft.com, App registrations) "
           "with a client secret, given a role on the subscription in the Azure portal (https://portal.azure.com, Subscriptions "
           "> Access control (IAM)) that reads everything (*/read) and makes only the free changes: the README's custom role "
           "(VMs started, restarted, deallocated and powered off; DNS record sets; security rules; SSH public keys)")
POWER_ACTIONS = {"start": "start", "restart": "restart", "deallocate": "deallocate", "poweroff": "powerOff"}
COSTLY_START = frozenset({"deallocated", "hibernated", "deallocating", ""})  # a start that starts the compute charge again
# ("" : its state could not be read just before: taken as the costly one)


def transient(e: BaseException) -> bool:
    """A failure that passes (no connection, Azure busy or failing, a rate limit): the plugin stays valid and tries again
    soon. A refusal (the credentials, a role, a subscription not found) is no passing trouble."""
    return isinstance(e, RestError) and (e.status == 0 or e.status == 429 or e.status >= 500)


def ddns_state_file() -> Path:
    """Where the Dynamic DNS keeper keeps what is its own: the platform's folder's azure/ddns.json (LIMINAL_PLATFORM_DIR,
    else the data folder's platform/)."""
    named = (os.environ.get(DIR_VAR) or "").strip()
    if named:
        return Path(named).expanduser() / "azure" / "ddns.json"
    from liminal_libs import layout

    return layout.data_dir() / "platform" / "azure" / "ddns.json"


def _fqdn(text: str) -> str:
    """A Dynamic DNS host as set (home.example.com, @.example.com, example.com.) as the keeper names it."""
    name = str(text or "").strip().rstrip(".").lower()
    return name[2:] if name.startswith("@.") else name


def accepted(value) -> bool:
    """A second confirmation counts only when it is exactly true (the page sends JSON true): "false", "yes" or 1 from a
    program on this PC is refused like none."""
    return value is True


class _Pass:
    """A Dynamic DNS pass's own: the settings and the API it was begun with, the zones as read then, its stop event (the
    plugin detached: nothing more is written), the record sets it read (written with their etags)."""

    def __init__(self, cfg: Config, api: AzureApi, snap: model.Snapshot, stop: threading.Event | None):
        self.cfg, self.api, self.snap, self.stop = cfg, api, snap, stop
        self.seen: dict = {}


class _Runtime:
    """What the plugin read and holds, shared by its copies (the registry's with_ makes them)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.config: tuple[float, Config] | None = None
        self.api: tuple[str, AzureApi] | None = None
        self.snap: model.Snapshot | None = None
        self.snap_print = ""  # the settings the snapshot was read with
        self.api_ok: bool | None = None  # the last refresh's outcome (None: none yet)
        self.api_error = ""
        self.api_error_at: float | None = None
        self.api_transient = False  # the last failure a passing one: still valid, tried again soon
        self.api_print = ""  # the settings that outcome is of
        self.prices: dict = {}  # (region, size, os, spot) -> (asked at, the price or None, why none)
        self.cost: dict | None = None
        self.cost_at: float | None = None
        self.cost_error = ""
        self.keeper: dyndns.Keeper | None = None
        self.ddns_print = ""
        self.ddns_at: float | None = None
        self.ddns_had: set[str] = set()  # the Dynamic DNS hosts of the last pass: one no longer set is let go
        self.passing = threading.local()  # the Dynamic DNS pass under way in this thread (_Pass)
        self.soon: float | None = None  # when the VMs' states are read again after a power change (monotonic)
        self.worker: threading.Thread | None = None
        self.stop: threading.Event | None = None
        self.wake = threading.Event()
        self.refreshing = threading.Lock()


class AzurePlugin(MachinePlugin):
    """Microsoft Azure: a subscription through Resource Manager, its free changes confirmed, and Dynamic DNS through Azure
    DNS; reading in the background while the platform has it attached."""

    name = "azure"
    title = "Microsoft Azure"
    about = ("Your Azure subscription: VMs with their power state and price, disks, public IPs, network security groups, "
             "Azure DNS zones and records, SSH keys and the cost this month; free changes only (VMs started, restarted, "
             "deallocated or powered off, records, rules and keys), each confirmed, and Dynamic DNS through Azure DNS")
    api = "2.2"
    order = 764
    ICON = "azure"  # Azure's mark (liminal-libs 1.49.0's icons.js)
    HOOKS = (*MachinePlugin.HOOKS, "refresh", "vms", "zones", "records", "nsgs", "ssh_keys", "power", "set_record",
             "remove_record", "add_rule", "remove_rule", "add_ssh_key", "remove_ssh_key", "ddns_update", "ddns_take_over")
    keys = KEYS
    signup = "https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal"
    limits = ("Azure Resource Manager: per region, 250 reads (refilled 25 a second), 200 writes and 200 deletes (10 a second) "
              "for each subscription and service principal; Azure DNS: per zone 200 changes and 60 lists a minute")
    apis = APIS

    def __init__(self, transport=None, public=None, clock=None, sleep=None, state: Path | None = None):
        self._transport = transport  # RestClient's (method, url, headers, body, timeout): a test's; else HTTPS
        self._public = public  # () -> (address, whose): a test's; else dns.public_address over PUBLIC_IPV4
        self._clock = clock or time.time
        self._sleep = sleep or time.sleep
        self._state = Path(state) if state is not None else None  # the Dynamic DNS state file (a test's); else ddns_state_file()
        self._rt = _Runtime()

    # -- the settings, the API, the keeper ----------------------------------------------------------------------------------
    def config(self, fresh: bool = False) -> Config:
        """The settings, asked of the login (the attached app's, else the environment's); kept CONFIG_S."""
        now = time.monotonic()
        with self._rt.lock:
            kept = self._rt.config
        if kept is not None and not fresh and now - kept[0] < CONFIG_S:
            return kept[1]
        cfg = settings_mod.read(self.login)
        with self._rt.lock:
            self._rt.config = (now, cfg)
        return cfg

    def settings_changed(self) -> None:
        """Its settings were just entered (the platform's Settings…, kept through the login): read anew at once."""
        with self._rt.lock:
            self._rt.config = None

    def client(self) -> AzureApi:
        """The APIs with the settings as they are (ValueError when they are not set)."""
        return self._client_for(self.config())

    def _client_for(self, cfg: Config) -> AzureApi:
        """The APIs for these settings (no settings read: a pass or a refresh under way keeps the ones it began with)."""
        if not cfg.api_ready:
            raise ValueError("the API is not set up: " + ("; ".join([*cfg.incomplete, *cfg.problems]) or NOT_SET))
        with self._rt.lock:
            held = self._rt.api
        if held is not None and held[0] == cfg.api_print:
            return held[1]
        made = AzureApi(cfg, transport=self._transport, clock=self._clock, sleep=self._sleep)
        with self._rt.lock:
            self._rt.api = (cfg.api_print, made)
        return made

    def keeper(self) -> dyndns.Keeper:
        with self._rt.lock:
            if self._rt.keeper is None:
                self._rt.keeper = dyndns.Keeper(read=self._ddns_read, write=self._ddns_write, servers=PUBLIC_IPV4,
                                                public=self._public, clock=self._clock,
                                                state=self._state if self._state is not None else ddns_state_file())
            return self._rt.keeper

    def snapshot(self) -> model.Snapshot | None:
        """What was read last, while the credentials are the ones it was read with."""
        return self._snap_of(self.config())

    def _snap_of(self, cfg: Config) -> model.Snapshot | None:
        with self._rt.lock:
            return self._rt.snap if self._rt.snap_print == cfg.api_print else None

    def _held(self) -> model.Snapshot:
        """What was read last; ValueError when nothing was (a change names what it changes as last read)."""
        snap = self.snapshot()
        if snap is None:
            raise ValueError("the subscription has not been read yet: Refresh first")
        return snap

    # -- the hooks ------------------------------------------------------------------------------------------------------------
    def present(self) -> bool:
        """Whether anything of it is set."""
        return bool(self.config().present)

    def refresh(self) -> dict:
        """The subscription read again now (its parts, the prices of new VM sizes, the cost when due); what the status
        shows until the next."""
        cfg = self.config(fresh=True)
        if not cfg.api_ready:
            raise ValueError("the API is not set up: " + ("; ".join([*cfg.incomplete, *cfg.problems]) or NOT_SET))
        if not self._rt.refreshing.acquire(timeout=120):
            raise RuntimeError("a refresh is under way")
        try:
            return self._refresh(cfg)
        finally:
            self._rt.refreshing.release()

    def _part(self, troubles: dict, part: str, read, default):
        """One part of a refresh read, its trouble kept (the page says it under its table) instead of failing the rest."""
        try:
            return read()
        except RestError as e:
            if e.status == 401:
                raise
            troubles[part] = str(e)
            return default

    def _refresh(self, cfg: Config) -> dict:
        now = self._clock()
        troubles: dict = {}
        try:
            api = self._client_for(cfg)
            sub = model.subscription_of(api.subscription_info())  # the one read that must work: the credentials' test
            groups = self._part(troubles, "groups", api.groups, [])
            resources = self._part(troubles, "resources", api.resources, [])
            vm_items = self._part(troubles, "vms", api.vms, [])
            statuses = self._part(troubles, "states", api.vm_statuses, []) if vm_items else []
            nic_items = self._part(troubles, "nics", api.nics, [])
            ip_items = self._part(troubles, "ips", api.public_ips, [])
            disk_items = self._part(troubles, "disks", api.disks, [])
            nsg_items = self._part(troubles, "nsgs", api.nsgs, [])
            zone_items = self._part(troubles, "zones", api.zones, [])
            key_items = self._part(troubles, "keys", api.ssh_keys, [])
        except (RestError, ValueError) as e:
            with self._rt.lock:
                self._rt.api_ok, self._rt.api_error, self._rt.api_error_at, self._rt.api_print = False, str(e), now, cfg.api_print
                self._rt.api_transient = transient(e)
            raise
        nics = model.nics_of(nic_items)
        ips = model.public_ips_of(ip_items)
        vms = model.vms_of(vm_items, statuses, nics, ips)
        views = self._views(api, vms, troubles)
        names = {v["key"]: v["name"] for v in vms}
        counts, by_group = model.counts_of(resources)
        snap = model.Snapshot(at=now, subscription=sub, groups=model.groups_of(groups), counts=counts, by_group=by_group,
                              vms=vms, disks=model.disks_of(disk_items, names), ips=model.ips_listed(ips, nics, names),
                              nsgs=model.nsgs_of(nsg_items, nics, vms), zones=model.zones_of(zone_items),
                              keys=model.keys_of(key_items), troubles=troubles, views=views)
        for z in snap.zones[:ZONES_MAX]:
            try:
                snap.records[z["key"]] = api.record_sets(z["group"], z["name"])
            except Exception as e:  # noqa: BLE001 - said under the zone's table; the rest of the refresh stands
                snap.records[z["key"]] = f"not read: {e if isinstance(e, RestError) else type(e).__name__ + ': ' + str(e)}"
        for z in snap.zones[ZONES_MAX:]:
            snap.records[z["key"]] = f"not read with the rest (more than {ZONES_MAX} zones): records {z['name']}"
        self._prices(api, vms)
        self._cost(api)
        with self._rt.lock:
            self._rt.snap, self._rt.snap_print = snap, cfg.api_print
            self._rt.api_ok, self._rt.api_error, self._rt.api_error_at, self._rt.api_print = True, "", None, cfg.api_print
            self._rt.api_transient = False
        return {"vms": len(vms), "zones": len(snap.zones), "nsgs": len(snap.nsgs), "readAt": when(now),
                "troubles": dict(troubles)}

    def _views(self, api: AzureApi, vms: list, troubles: dict) -> int:
        """The power state of VMs the statusOnly list did not give, asked one by one (at most VIEWS_MAX)."""
        asked = 0
        for v in vms:
            if v["power"] or asked >= VIEWS_MAX:
                continue
            asked += 1
            try:
                state, words = power_of(statuses_of(api.instance_view(v["group"], v["name"])))
            except RestError as e:
                troubles.setdefault("views", str(e))
                continue
            v["power"], v["powerWords"] = state, words
        return asked

    def _prices(self, api: AzureApi, vms: list) -> None:
        """The price an hour of each VM's size in its region (Linux or Windows, spot or regular), kept a day."""
        now = self._clock()
        asked = 0
        for v in vms:
            if not v["size"] or not v["location"]:
                continue
            key = (v["location"].lower(), v["size"], self._os_of(v), v["priority"].lower() == "spot")
            with self._rt.lock:
                kept = self._rt.prices.get(key)
            if kept is not None and now - kept[0] < PRICE_KEEP_S:
                continue
            if asked >= PRICES_MAX:
                break
            asked += 1
            try:
                found = pick_price(api.prices_of(v["location"].lower(), v["size"]), windows=key[2] == "windows", spot=key[3])
                why = "" if found else "no retail price found for this size here"
            except Exception as e:  # noqa: BLE001 - a price is extra: said in its cell, the refresh stands
                found, why = None, f"not read: {e if isinstance(e, RestError) else type(e).__name__}"
            with self._rt.lock:
                self._rt.prices[key] = (now, found, why)

    @staticmethod
    def _os_of(v: dict) -> str:
        """Which price a VM pays: Windows' own, or the base (Linux) one (a Windows VM under Azure Hybrid Benefit too)."""
        windows = v["os"].lower() == "windows" and v["license"] not in ("Windows_Server", "Windows_Client")
        return "windows" if windows else "linux"

    def _price_for(self, v: dict) -> tuple[dict | None, str]:
        key = (v["location"].lower(), v["size"], self._os_of(v), v["priority"].lower() == "spot")
        with self._rt.lock:
            kept = self._rt.prices.get(key)
        return (kept[1], kept[2]) if kept else (None, "not asked yet")

    def _cost(self, api: AzureApi, force: bool = False) -> None:
        """The cost this month so far, asked at most every COST_S (its trouble kept: a role without Cost Management's read,
        an offer it does not cover, its throttling)."""
        now = self._clock()
        with self._rt.lock:
            last = self._rt.cost_at
        if last is not None and now - last < COST_S and not force:
            return
        try:
            found, error = api.cost(), ""
        except Exception as e:  # noqa: BLE001 - the cost is extra: said in its fact, the refresh stands
            found, error = None, str(e) if isinstance(e, RestError) else f"{type(e).__name__}: {e}"
        with self._rt.lock:
            self._rt.cost_at = now
            if found is not None:
                self._rt.cost, self._rt.cost_error = found, ""
            else:
                self._rt.cost_error = error

    def vms(self) -> list[dict]:
        """The subscription's VMs and their power states, read now (the status's table keeps the rest of the last read)."""
        api = self.client()
        nics = model.nics_of(api.nics())
        ips = model.public_ips_of(api.public_ips())
        found = model.vms_of(api.vms(), api.vm_statuses(), nics, ips)
        self._keep(vms=found)
        return [{**v, "price": self._price_for(v)[0]} for v in found]

    def zones(self) -> list[dict]:
        """The subscription's Azure DNS zones, read now."""
        found = model.zones_of(self.client().zones())
        self._keep(zones=found)
        return found

    def records(self, zone: str, group: str | None = None) -> list[dict]:
        """A zone's record sets, read now."""
        z = self._zone(zone, group)
        found = self.client().record_sets(z["group"], z["name"])
        self._keep_records(z, found)
        return [s.as_dict() for s in found]

    def nsgs(self) -> list[dict]:
        """The network security groups and their rules, read now."""
        api = self.client()
        snap = self.snapshot()
        vms = snap.vms if snap is not None else []
        found = model.nsgs_of(api.nsgs(), model.nics_of(api.nics()), vms)
        self._keep(nsgs=found)
        return [{**g, "rules": [r.as_dict() for r in g["rules"]], "defaults": [r.as_dict() for r in g["defaults"]]} for g in found]

    def ssh_keys(self) -> list[dict]:
        """The SSH public keys kept in Azure, read now."""
        found = model.keys_of(self.client().ssh_keys())
        self._keep(keys=found)
        return found

    def _keep(self, **parts) -> None:
        with self._rt.lock:
            if self._rt.snap is not None:
                for k, v in parts.items():
                    setattr(self._rt.snap, k, v)
                    self._rt.snap.troubles.pop(k, None)

    def _keep_records(self, z: dict, sets: list) -> None:
        with self._rt.lock:
            if self._rt.snap is not None:
                self._rt.snap.records[z["key"]] = sets

    def _zone(self, zone: str, group: str | None = None) -> dict:
        """A zone as last read (its resource group named when two groups hold zones of that name)."""
        snap = self.snapshot()
        zones = snap.zones if snap is not None else model.zones_of(self.client().zones())
        if snap is None:
            self._keep(zones=zones)
        name = str(zone or "").strip().rstrip(".").lower()
        found = [z for z in zones if z["name"].lower() == name and (not group or z["group"].lower() == str(group).lower())]
        if not found:
            raise ValueError(f"{zone} is none of the subscription's Azure DNS zones as last read")
        if len(found) > 1:
            raise ValueError(f"{zone} is in {len(found)} resource groups: name the group ({', '.join(z['group'] for z in found)})")
        return found[0]

    # -- the free changes ---------------------------------------------------------------------------------------------------
    def power(self, group: str, name: str, action: str, accept_still_billed=False, accept_costs=False) -> dict:
        """A VM started, restarted, deallocated (its compute no longer billed) or powered off (still billed: refused until
        that is accepted, accept_still_billed). A start reads the VM's state just before: one that starts the compute
        charge again (a deallocated VM, or one whose state could not be read) is refused until that is accepted
        (accept_costs, its price said); a stopped one was billing all along. Each accept counts only when exactly true.
        Azure accepts the change and does it after; the VMs' states are read again soon after."""
        act = str(action or "").strip().lower().replace(" ", "").replace("_", "").replace("-", "")
        if act not in POWER_ACTIONS:
            raise ValueError(f"{action!r} is none of {', '.join(POWER_ACTIONS)}")
        v = self._vm(group, name)
        if act == "poweroff" and not accepted(accept_still_billed):
            raise Refusal(f"{v['name']} powered off stays allocated and is still billed for its compute by the hour, as "
                          "when it runs (deallocate stops that charge): it is powered off only once that is accepted "
                          f"({ACCEPT_BILLED})", accept=ACCEPT_BILLED)
        api = self.client()
        state = v["power"]
        if act == "start":
            state, words = power_of(statuses_of(api.instance_view(v["group"], v["name"])))  # read just before
            if state:
                self._set_power(v, state, words)
            if state in ("running", "starting"):
                raise Refusal(f"{v['name']} is {state} now (read just now): there is nothing to start")
            if state in COSTLY_START and not accepted(accept_costs):
                raise Refusal(self._start_costs(v, state), accept=ACCEPT_COSTS)
        answer = api.vm_action(v["group"], v["name"], POWER_ACTIONS[act])
        with self._rt.lock:
            self._rt.soon = time.monotonic() + SOON_S
        self._rt.wake.set()
        lines = {
            "start": page.start_words(state),
            "restart": "it stays allocated and billed",
            "deallocate": "its compute is no longer billed once it is deallocated (its disks and static IPs still are)",
            "poweroff": "it is still billed for its compute while powered off: deallocate it to stop that",
        }[act]
        verb = {"start": "started", "restart": "restarted", "deallocate": "deallocated", "poweroff": "powered off"}[act]
        return {"vm": v["name"], "group": v["group"], "action": act, "accepted": answer.status == 202, "ok": True,
                "said": f"{v['name']} is being {verb}" if answer.status == 202 else f"{v['name']} {verb}",
                "lines": [lines, "its state shows on the next read (in about a minute, or Refresh)"]}

    def _start_costs(self, v: dict, state: str) -> str:
        """What starting this VM costs, in words: which charge starts again, at what price (the refusal's words)."""
        price, _ = self._price_for(v)
        cost = (f", {page.money(price['hour'], price['currency'])} an hour (about "
                f"{page.money(price['hour'] * HOURS_A_MONTH, price['currency'])} a month: Azure's retail price for "
                f"{v['size']})") if price else f" (its size {v['size']}: its price is on Azure's pricing pages)"
        now = (f"{v['name']} is {state} now (read just now)" if state else
               f"{v['name']}'s power state could not be read just now, so it is taken as deallocated")
        return (f"{now}: starting it STARTS ITS COMPUTE CHARGE AGAIN, by the hour{cost}, until it is deallocated again. "
                f"It is started only once that is accepted ({ACCEPT_COSTS})")

    def _set_power(self, v: dict, state: str, words: str) -> None:
        with self._rt.lock:
            v["power"], v["powerWords"] = state, words

    def _vm(self, group: str, name: str) -> dict:
        snap = self._held()
        v = snap.vm(group, name)
        if v is None:
            raise ValueError(f"{name} in {group} is none of the subscription's VMs as last read: Refresh first")
        return v

    def set_record(self, group: str, zone: str, name: str, rtype: str, value: str, ttl=None) -> dict:
        """A record set in `zone` (records.plan_set): every other record set kept, the record set read just before and
        written only if it is still as read (its etag). A Dynamic DNS host's A record set here by hand is let go by
        Dynamic DNS (left as set until the user takes it over again)."""
        z = self._zone(zone, group)
        api = self.client()
        t = recs.record_type(rtype)
        n = recs.relative_name(name, z["name"])
        held = api.record_set(z["group"], z["name"], t, n)
        others = [x for x in self._types_at(api, self.snapshot(), z, n) if x != t]
        plan = recs.plan_set(z["name"], z["group"], n, t, value, held, others, ttl=ttl)
        report = self._send(api, z, plan)
        if plan.changed and t == "A":
            fqdn = z["name"].lower() if n == "@" else f"{n}.{z['name']}".lower()
            if fqdn in {h.fqdn for h in self.ddns_hosts(self.config())[0]}:
                self.keeper().let_go(fqdn)
                report["lines"].append(f"{fqdn} is a Dynamic DNS host: it is left as you set it until you take it over again")
        return report

    def remove_record(self, group: str, zone: str, name: str, rtype: str, value: str = "") -> dict:
        """A record removed from its record set (`value` names it); the last one deletes the record set."""
        z = self._zone(zone, group)
        api = self.client()
        t = str(rtype or "").strip().upper()
        n = recs.relative_name(name, z["name"])
        held = api.record_set(z["group"], z["name"], t, n) if t in recs.TYPES else None
        plan = recs.plan_remove(z["name"], z["group"], n, t, value, held)
        report = self._send(api, z, plan)
        if plan.changed and t == "A" and plan.records is None:
            fqdn = z["name"].lower() if n == "@" else f"{n}.{z['name']}".lower()
            if fqdn in {h.fqdn for h in self.ddns_hosts(self.config())[0]}:
                report["lines"].append(f"{fqdn} is still a Dynamic DNS host: its next pass makes its A record again "
                                       f"(take it out of {settings_mod.DDNS_HOSTS} to stop that)")
        return report

    def _types_at(self, api: AzureApi, snap: model.Snapshot | None, z: dict, name: str) -> list[str]:
        """The record types a name holds in a zone (as last read; read now when the zone was not)."""
        held = snap.records.get(z["key"]) if snap is not None else None
        if not isinstance(held, list):
            held = api.record_sets(z["group"], z["name"])
            self._keep_records(z, held)
        return sorted(model.names_holding(held, name))

    def _send(self, api: AzureApi, z: dict, plan: recs.Plan) -> dict:
        report = {"zone": z["name"], "group": z["group"], "name": plan.name, "type": plan.type, "changed": plan.changed,
                  "said": plan.said, "ok": True}
        if not plan.changed:
            report["lines"] = []
            return report
        if plan.records is None:
            api.delete_record_set(plan)
            after = None
        else:
            after = api.put_record_set(plan)
        self._replace_set(z, plan, after)
        report["lines"] = [f"{plan.name} {plan.type} now holds {', '.join(after.values)}" if after is not None else
                           f"{plan.name} {plan.type} is gone from {z['name']}",
                           "every other record set of the zone was left as it was"]
        return report

    def _replace_set(self, z: dict, plan: recs.Plan, after: recs.RecordSet | None) -> None:
        with self._rt.lock:
            snap = self._rt.snap
            held = snap.records.get(z["key"]) if snap is not None else None
            if not isinstance(held, list):
                return
            rest = [s for s in held if not (s.name.lower() == plan.name.lower() and s.type == plan.type)]
            snap.records[z["key"]] = rest + ([after] if after is not None else [])

    def add_rule(self, group: str, nsg: str, name: str, direction: str, access: str, protocol: str, ports: str,
                 source=None, destination=None, priority=None, description=None, accept_risky=False) -> dict:
        """A security rule added to a network security group, the group read just before: a rule of that name (made since
        the last read too) or a priority another rule of its direction holds is refused, and none is ever replaced (sent
        with If-None-Match: *). One opening every port or a service of rules.RISKY to the whole internet, or denying SSH
        or RDP on a group attached to a VM, only once that is accepted (accept_risky, exactly true)."""
        g = self._nsg(group, nsg)
        rule = nsg_rules.rule_of(name, direction, access, protocol, ports, source, destination, priority, description)
        api = self.client()
        rules_now, _, servers = self._nsg_now(api, g)
        if any(r.name.lower() == rule.name.lower() for r in rules_now):
            raise Refusal(f"{g['name']} has a rule named {rule.name} (read just now): it is never replaced here; remove it "
                          "first, or name this one otherwise")
        taken = next((r for r in rules_now if r.direction == rule.direction and r.priority == rule.priority), None)
        if taken is not None:
            raise Refusal(f"priority {rule.priority} is {taken.name}'s ({rule.direction.lower()}): each rule's is its own")
        risk = nsg_rules.risk_of_adding(rule, servers)
        if risk and not accepted(accept_risky):
            raise Refusal(f"{nsg_rules.said(rule)}: {risk}. It is added only once that is accepted ({ACCEPT_RISKY})",
                          accept=ACCEPT_RISKY)
        try:
            answer = api.put_rule(g["group"], g["name"], rule)
        except RestError as e:
            if e.status == 412:  # made meanwhile, between the read and the write: not replaced
                raise Refusal(f"a rule named {rule.name} was made in {g['name']} meanwhile: it is not replaced") from None
            raise
        made = nsg_rules.parse(answer) if answer else rule
        self._replace_rule(g, made)
        return {"nsg": g["name"], "group": g["group"], "rule": made.as_dict(), "ok": True, "said": f"added {nsg_rules.said(made)}",
                "lines": [*([f"{risk} (accepted)"] if risk else []), f"{g['name']}'s other rules were left as they were"]}

    def remove_rule(self, group: str, nsg: str, name: str, accept_risky=False) -> dict:
        """A security rule removed, the group read just before (its default rules cannot be); the rule letting SSH or RDP
        in to a VM the group is attached to, or a Deny keeping a later rule from opening a risky service to the whole
        internet, only once that is accepted (accept_risky, exactly true)."""
        g = self._nsg(group, nsg)
        api = self.client()
        rules_now, defaults_now, servers = self._nsg_now(api, g)
        wanted = str(name or "").strip().lower()
        rule = next((r for r in rules_now if r.name.lower() == wanted), None)
        if rule is None:
            if any(r.name.lower() == wanted for r in defaults_now or g["defaults"]):
                raise Refusal(f"{name} is one of {g['name']}'s default rules: those cannot be removed")
            raise Refusal(f"{g['name']} has no rule named {name} (read just now)")
        risk = nsg_rules.risk_of_removing(rule, servers, others=rules_now)
        if risk and not accepted(accept_risky):
            raise Refusal(f"{nsg_rules.said(rule)}: {risk}. It is removed only once that is accepted ({ACCEPT_RISKY})",
                          accept=ACCEPT_RISKY)
        api.delete_rule(g["group"], g["name"], rule.name)
        self._replace_rule(g, None, gone=rule.name)
        return {"nsg": g["name"], "group": g["group"], "ok": True, "said": f"removed {nsg_rules.said(rule)}",
                "lines": [*([f"{risk} (accepted)"] if risk else []), f"{g['name']}'s other rules were left as they were"]}

    def _nsg(self, group: str, name: str) -> dict:
        g = self._held().nsg(group, name)
        if g is None:
            raise ValueError(f"{name} in {group} is none of the subscription's network security groups as last read: Refresh first")
        return g

    def _nsg_now(self, api: AzureApi, g: dict) -> tuple[list, list, list[str]]:
        """A network security group read again just before a change: its rules, its default rules, and the VMs it is
        attached to (by name as last read; said as its interfaces or subnets when it was attached since)."""
        data = api.nsg(g["group"], g["name"])
        if data is None:
            raise Refusal(f"{g['name']} is not in {g['group']} any more (read just now): Refresh")
        props = data.get("properties") if isinstance(data.get("properties"), Mapping) else {}
        rules_now = sorted((nsg_rules.parse(r) for r in props.get("securityRules") or [] if isinstance(r, Mapping)),
                           key=lambda r: (r.direction != "Inbound", r.priority, r.name.lower()))
        defaults_now = [nsg_rules.parse(r, default=True) for r in props.get("defaultSecurityRules") or [] if isinstance(r, Mapping)]
        attached = bool(props.get("networkInterfaces") or props.get("subnets"))
        servers = (list(g["servers"]) or ["the network interfaces or subnets it is attached to"]) if attached else []
        with self._rt.lock:
            g["rules"] = rules_now
        return rules_now, defaults_now, servers

    def _replace_rule(self, g: dict, rule, gone: str | None = None) -> None:
        with self._rt.lock:
            rules = [r for r in g["rules"] if r.name.lower() != (gone or (rule.name if rule else "")).lower()]
            if rule is not None:
                rules.append(rule)
            g["rules"] = sorted(rules, key=lambda r: (r.direction != "Inbound", r.priority, r.name.lower()))

    def add_ssh_key(self, group: str, name: str, public_key: str, location=None) -> dict:
        """An SSH public key stored in Azure (RSA of 2048 bits or more, or ED25519; a private key refused without a word of
        it said back), in a resource group of the subscription (in its location unless one is named). A key of that name
        (made since the last read too) is refused, and none is ever replaced (sent with If-None-Match: *)."""
        snap = self._held()
        g = snap.group(group)
        if g is None:
            raise ValueError(f"{group} is none of the subscription's resource groups as last read: Refresh first")
        n = model.key_name(name)
        line, described = model.check_key(public_key)
        api = self.client()
        if api.ssh_key(g["name"], n) is not None:
            raise Refusal(f"{g['name']} holds an SSH key named {n} (read just now): it is never replaced here; remove it "
                          "first, or name this one otherwise")
        where = "".join(str(location or "").split()).lower() or g["location"]
        try:
            answer = api.put_ssh_key(g["name"], n, where, line)
        except RestError as e:
            if e.status == 412:
                raise Refusal(f"an SSH key named {n} was made in {g['name']} meanwhile: it is not replaced") from None
            raise
        made = model.keys_of([answer])[0] if answer else {"name": n, "group": g["name"], "location": where, "key": described}
        with self._rt.lock:
            snap.keys = sorted([*(k for k in snap.keys if not (k["group"].lower() == g["name"].lower() and k["name"] == n)), made],
                               key=lambda k: (k["group"].lower(), k["name"].lower()))
        return {"key": made, "ok": True, "said": f"stored the SSH key {n} in {g['name']}", "lines": [described]}

    def remove_ssh_key(self, group: str, name: str) -> dict:
        """An SSH public key deleted from Azure (a VM made with it keeps its own copy)."""
        snap = self._held()
        k = snap.key(group, name)
        if k is None:
            raise ValueError(f"{name} in {group} is none of the subscription's SSH keys as last read: Refresh first")
        self.client().delete_ssh_key(k["group"], k["name"])
        with self._rt.lock:
            snap.keys = [x for x in snap.keys if x is not k]
        return {"ok": True, "said": f"removed the SSH key {k['name']} from {k['group']}", "lines": [k["key"]]}

    # -- Dynamic DNS through Azure DNS (the library's Keeper) -----------------------------------------------------------------
    @staticmethod
    def _ddns_zone(snap: model.Snapshot, host: dyndns.Host) -> dict:
        """The zone a host is kept in: the one of its name (a name two resource groups hold is refused: which is live is
        not the plugin's to guess)."""
        found = [x for x in snap.zones if x["name"].lower() == host.zone]
        if not found:
            raise ValueError(f"{host.zone} is none of the subscription's Azure DNS zones as last read")
        if len(found) > 1:
            raise ValueError(f"{host.zone} is a zone in {len(found)} resource groups ({', '.join(z['group'] for z in found)}): "
                             "Dynamic DNS writes to none of them")
        return found[0]

    def _passing(self) -> _Pass:
        ctx = getattr(self._rt.passing, "current", None)
        if ctx is None:
            raise RuntimeError("no Dynamic DNS pass is under way")
        return ctx

    def _ddns_read(self, host: dyndns.Host) -> list[str] | None:
        """A host's A record set as it is now (the Keeper's read): its addresses ([] when it has none)."""
        ctx = self._passing()
        z = self._ddns_zone(ctx.snap, host)
        held = ctx.api.record_set(z["group"], z["name"], "A", host.name)
        ctx.seen[host.fqdn] = held
        if held is None:
            return []
        if held.unwritable:
            raise ValueError(f"its A record set is {held.unwritable}")
        return held.values

    def _ddns_write(self, host: dyndns.Host, address: str) -> str:
        """A host's A record set holding this network's address alone (the Keeper's write), with the etag it was read with
        (a new one If-None-Match: *); nothing once the plugin is detached."""
        ctx = self._passing()
        if ctx.stop is not None and ctx.stop.is_set():
            raise RuntimeError("the plugin was detached: nothing written")
        z = self._ddns_zone(ctx.snap, host)
        held = ctx.seen.pop(host.fqdn) if host.fqdn in ctx.seen else ctx.api.record_set(z["group"], z["name"], "A", host.name)
        if host.name != "@" and held is None and "CNAME" in self._types_at(ctx.api, ctx.snap, z, host.name):
            raise Refusal(f"{host.fqdn} is a CNAME: it holds no A record beside it")
        plan = recs.plan_address(z["name"], z["group"], host.name, address, held)
        after = ctx.api.put_record_set(plan)
        self._replace_set(z, plan, after)
        return plan.said

    def ddns_hosts(self, cfg: Config) -> tuple[list, list]:
        """The Dynamic DNS hosts in the subscription's zones (as last read), and the entries in none, in words (with
        every setting's value taken out: a secret pasted into the hosts is never shown)."""
        snap = self._snap_of(cfg)
        if snap is None:
            return [], []
        hosts, wrong = dyndns.hosts_of(", ".join(cfg.hosts), zones=[z["name"] for z in snap.zones])
        secrets = [*cfg.secrets, *(s.lower() for s in cfg.secrets)]
        return hosts, [scrub(w, secrets) for w in wrong]

    def _ddns_pass(self, cfg: Config, hosts: list, force: bool = False, stop: threading.Event | None = None,
                   wait: float = 120.0) -> list[dict]:
        """A Dynamic DNS pass over `hosts` with these settings (none read again during it), the zones as last read, and
        `stop` (the plugin detached ends it before its next write). The hosts taken out of the settings are let go."""
        snap = self._snap_of(cfg)
        if snap is None:
            raise ValueError("the subscription's zones are not read yet")
        keeper = self.keeper()
        named = {_fqdn(text) for text in cfg.hosts}  # as set, whatever zones were read (a zone not read lets none go)
        known = getattr(keeper, "known", None)  # liminal-libs 1.49.4: every host it holds, from before a restart too
        with self._rt.lock:
            held = set(known()) if callable(known) else set(self._rt.ddns_had)
            gone, self._rt.ddns_had = held - named, {h.fqdn for h in hosts} | (self._rt.ddns_had & named)
        for fqdn in sorted(gone):
            keeper.let_go(fqdn)
        self._rt.passing.current = _Pass(cfg, self._client_for(cfg), snap, stop)
        try:
            out = keeper.run_pass(hosts, force=bool(force), wait=wait, stop=stop)
        finally:
            self._rt.passing.current = None
        with self._rt.lock:
            self._rt.ddns_print, self._rt.ddns_at = cfg.ddns_print, self._clock()
        return out

    def _ddns_ready(self, cfg: Config) -> list:
        """The hosts a pass asked now goes over (the subscription read first when it was not); ValueError when none."""
        if not cfg.ddns_ready:
            raise ValueError("Dynamic DNS is not set up: " + (f"{settings_mod.DDNS_HOSTS} is not set" if cfg.api_ready else
                                                              "the API is not set up (" + ", ".join(CREDENTIALS) + ")"))
        if self._snap_of(cfg) is None:
            self.refresh()
        hosts, wrong = self.ddns_hosts(cfg)
        if not hosts:
            raise ValueError("no Dynamic DNS host is in the subscription's Azure DNS zones" + (f": {'; '.join(wrong)}" if wrong else ""))
        return hosts

    def ddns_update(self, force: bool = True) -> list[dict]:
        """A Dynamic DNS pass now (the page's Update DNS now, confirmed: `force`, every host that is the keeper's own
        written whether it differs or not, never one holding another address; the command line's `ddns` without --now
        writes only where it differs)."""
        cfg = self.config(fresh=True)
        hosts = self._ddns_ready(cfg)
        return self._ddns_pass(cfg, hosts, force=bool(force), stop=self._rt.stop)

    def ddns_take_over(self, host: str, holds=None) -> dict:
        """A host the keeper left as it is (it holds another address, or several) taken over (the page's Take over…, once
        confirmed: its words name what it holds), then a pass for that host: its A record set to this network's address
        alone, and kept there."""
        cfg = self.config(fresh=True)
        hosts = self._ddns_ready(cfg)
        want = str(host or "").strip().rstrip(".").lower()
        h = next((x for x in hosts if x.fqdn == want), None)
        if h is None:
            raise ValueError(f"{host} is none of the Dynamic DNS hosts in the subscription's zones ({settings_mod.DDNS_HOSTS})")
        keeper = self.keeper()
        keeper.take_over(h.fqdn)
        out = self._ddns_pass(cfg, [h], force=False, stop=self._rt.stop)
        st = out[0] if out else {}
        lines = [f"it held {holds}" if holds else "", "kept at this network's address from now on"]
        return {"host": h.fqdn, "ok": bool(st.get("ok")), "said": f"{h.fqdn} taken over: {st.get('result') or 'set on the next pass'}",
                "lines": [x for x in lines if x], "state": st}

    # -- attached: the reading in the background ------------------------------------------------------------------------------
    def attach(self, app, login=None) -> dict:
        """Attached: its settings asked of the app's login from now on. By the platform, the subscription read and the
        Dynamic DNS hosts checked in the background; by any other app (the charts app run alone attaches every plugin it
        finds), nothing of it runs on its own."""
        interface = super().attach(app, login)
        with self._rt.lock:
            self._rt.config = None
        if getattr(app, "NAME", "") == "platform":
            self._start()
        return interface

    def detach(self) -> None:
        """Detached (the platform ending, the plugin disabled or not valid): the background reading ends, and a pass under
        way writes nothing more."""
        self._stop()
        super().detach()
        with self._rt.lock:
            self._rt.config = None

    @property
    def working(self) -> bool:
        with self._rt.lock:
            t = self._rt.worker
        return t is not None and t.is_alive()

    def _start(self) -> None:
        with self._rt.lock:
            if self._rt.worker is not None and self._rt.worker.is_alive():
                return
            stop = threading.Event()
            t = threading.Thread(target=self._work, args=(stop,), name="azure", daemon=True)
            self._rt.worker, self._rt.stop = t, stop
            self._rt.wake.clear()
        t.start()

    def _stop(self) -> None:
        with self._rt.lock:
            t, stop = self._rt.worker, self._rt.stop
            self._rt.worker = self._rt.stop = None
        if stop is not None:
            stop.set()
            self._rt.wake.set()
        if t is not None and t is not threading.current_thread():
            t.join(timeout=10)

    def _work(self, stop: threading.Event) -> None:
        """The background: the subscription read every REFRESH_S (a read failed for a passing reason again after
        RETRY_SOON_S, then twice as long each time), the VMs' states soon after a power change, the Dynamic DNS hosts
        checked every AZURE_DDNS_MINUTES once the zones are read; nothing done for what is not set."""
        next_api = next_ddns = 0.0
        failures = 0
        while not stop.is_set():
            now = time.monotonic()
            cfg = None
            snap = None
            try:
                cfg = self.config()
                with self._rt.lock:
                    soon = self._rt.soon
                if cfg.api_ready and now >= next_api:
                    if self._rt.refreshing.acquire(blocking=False):  # Refresh asked meanwhile: that one is enough
                        try:
                            self._refresh(cfg)
                            failures, next_api = 0, now + REFRESH_S
                            with self._rt.lock:
                                self._rt.soon = None
                        except Exception as e:  # noqa: BLE001 - kept as its outcome (api_error), shown by the status
                            failures += 1
                            next_api = now + (min(REFRESH_S, RETRY_SOON_S * 2 ** (failures - 1)) if transient(e) else REFRESH_S)
                        finally:
                            self._rt.refreshing.release()
                    else:
                        next_api = now + REFRESH_S
                elif cfg.api_ready and soon is not None and now >= soon:
                    with self._rt.lock:
                        self._rt.soon = None
                    try:
                        self._reread_states(cfg)
                    except Exception:  # noqa: BLE001 - the next refresh reads them anyway
                        pass
                snap = self._snap_of(cfg)
                if cfg.ddns_ready and snap is not None and now >= next_ddns and not stop.is_set():
                    next_ddns = now + cfg.minutes * 60.0
                    hosts, _ = self.ddns_hosts(cfg)
                    if hosts:  # none in the subscription's zones: not even this network's address is asked
                        try:
                            self._ddns_pass(cfg, hosts, force=False, stop=stop, wait=0.5)
                        except Exception:  # noqa: BLE001 - a pass under way (Update DNS now), or its trouble kept by the hosts
                            pass
            except Exception:  # noqa: BLE001 - the background never ends on a trouble; the status says it
                pass
            with self._rt.lock:
                soon = self._rt.soon
            ddns_due = cfg is not None and cfg.ddns_ready and snap is not None
            due = [t for t, on in ((next_api, cfg is not None and cfg.api_ready), (soon or 0.0, soon is not None),
                                   (next_ddns, ddns_due)) if on]
            wait = min([60.0, *(t - time.monotonic() for t in due)])
            self._rt.wake.wait(max(1.0, wait))
            self._rt.wake.clear()

    def _reread_states(self, cfg: Config) -> None:
        """The VMs' power states read again (one request: List All with statusOnly)."""
        api = self._client_for(cfg)
        statuses = api.vm_statuses()
        power = {}
        for s in statuses:
            state, words = power_of(statuses_of(s))
            if state:
                power[model.key_of(str(s.get("id") or ""))] = (state, words)
        with self._rt.lock:
            snap = self._rt.snap
            if snap is None:
                return
            for v in snap.vms:
                if v["key"] in power:
                    v["power"], v["powerWords"] = power[v["key"]]

    # -- what it learned of its APIs (plugin API 2.2): nothing asked to answer it ------------------------------------------------
    def api_facts(self) -> dict:
        with self._rt.lock:
            held = self._rt.api
            snap, cost, cost_at, cost_error = self._rt.snap, self._rt.cost, self._rt.cost_at, self._rt.cost_error
            prices = len(self._rt.prices)
        if held is None:
            return {}
        api = held[1]
        arm = api.arm.facts({"x-ms-ratelimit-remaining-subscription-reads": "Reads left (subscription)",
                             "x-ms-ratelimit-remaining-subscription-writes": "Writes left (subscription)",
                             "x-ms-ratelimit-remaining-subscription-deletes": "Deletes left (subscription)",
                             "x-ms-ratelimit-remaining-tenant-reads": "Reads left (tenant)",
                             "x-ms-ratelimit-remaining-subscription-global-reads": "Reads left (all principals)",
                             "x-ms-ratelimit-remaining-resource": "Left of the provider's own limit"})
        if snap is not None:
            arm["Last read"] = when(snap.at)
            if snap.views:
                arm["Power states asked one by one"] = str(snap.views)
        if cost_at:
            arm["Cost this month"] = (f"{page.money(cost['amount'], cost['currency'])}, read {when(cost_at)}" if cost and not cost_error
                                      else f"not read ({cost_error[:120]})" if cost_error else "–")
            arm["Cost Management queries"] = api.costs.facts({})["Requests"]
        dns = api.dns.facts({"x-ms-ratelimit-remaining-subscription-reads": "Reads left (subscription)",
                             "x-ms-ratelimit-remaining-subscription-writes": "Writes left (subscription)",
                             "x-ms-ratelimit-remaining-subscription-deletes": "Deletes left (subscription)"})
        if snap is not None:
            dns["Zones read"] = f"{len(snap.zones)} ({sum(len(x) for x in snap.records.values() if isinstance(x, list))} record sets)"
        identity = api.login.facts({})
        if api.token_at:
            identity["Token"] = f"given {when(api.token_at)}, lasting {api.token_lasts / 60:.0f} min"
        out = {ARM_NAME: arm, DNS_NAME: dns, IDENTITY_NAME: identity}
        priced = api.prices.facts({})
        priced["Prices kept"] = f"{prices} VM sizes, a day each"
        out[PRICES_NAME] = priced
        return out

    # -- what the platform's page shows ------------------------------------------------------------------------------------
    def status(self) -> dict:
        """What was read last, asking nothing of Azure: the settings set (by name), the summary, valid (set up, and the
        last read worked, is untried, or failed for a passing reason: said as a problem and tried again soon) and why
        not, the facts, the tables, the actions and the forms."""
        cfg = self.config()
        if not cfg.present:
            return {"present": False, "valid": False, "why": NOT_SET, "summary": "not set up", "settingsNotSet": ", ".join(NAMES),
                    "billing": BILLING, "tables": [], "actions": [], "forms": []}
        rt, now, attached = self._rt, self._clock(), self.app is not None
        with rt.lock:
            snap = rt.snap if rt.snap_print == cfg.api_print else None
            api_ok, api_error, api_error_at, api_print = rt.api_ok, rt.api_error, rt.api_error_at, rt.api_print
            passing = rt.api_transient
            cost, cost_at, cost_error, keeper, ddns_print = rt.cost, rt.cost_at, rt.cost_error, rt.keeper, rt.ddns_print
        prices = {v["key"]: self._price_for(v) for v in snap.vms} if snap is not None else {}
        notes = [*cfg.incomplete, *cfg.problems]
        out: dict = {"present": True}
        failing = False
        if not cfg.api_ready:
            out.update({"valid": False, "why": "; ".join(notes) or NOT_SET, "summary": "set up halfway"})
            works = False
        else:
            works = api_ok if api_print == cfg.api_print else None
            failing = works is False and passing  # a passing failure: still valid, tried again soon
            if works is False and not failing and not attached and api_error_at is not None and now - api_error_at >= RETRY_S:
                works = None  # tried again once the platform attaches it
            out["valid"] = works is not False or failing
            if not out["valid"]:
                out["why"] = f"the API: {api_error}"
        hosts, wrong = self.ddns_hosts(cfg) if cfg.ddns_ready else ([], [])
        states = {s.fqdn.lower(): s for s in (keeper.states() if keeper is not None else [])}
        tried = [states[h.fqdn] for h in hosts if h.fqdn in states and states[h.fqdn].ok is not None]
        ddns_troubles = [f"{s.fqdn}: {s.result}" for s in tried if s.ok is False and ddns_print == cfg.ddns_print]
        troubles = ([f"the last read failed ({when(api_error_at)}) and is tried again within minutes: {api_error}"]
                    if failing else [])
        if out["valid"] and (troubles or notes or wrong or ddns_troubles):
            out["problem"] = "; ".join([*troubles, *notes, *(f"Dynamic DNS: {w}" for w in wrong),
                                        *(f"Dynamic DNS: {t}" for t in ddns_troubles)])
        out["summary"] = self._summary(cfg, works, failing, api_error, attached, snap, cost, hosts, states)
        out["settingsSet"] = ", ".join(n for n in NAMES if n in cfg.present)
        missing = [n for n in NAMES if n not in cfg.present]
        if missing:
            out["settingsNotSet"] = ", ".join(missing)
        if snap is not None:
            sub = snap.subscription
            out["subscription"] = f"{sub['name']} ({sub['state']})" if sub.get("name") else sub.get("state") or "–"
            if sub.get("offer"):
                out["offer"] = sub["offer"]
            if sub.get("spendingLimit"):
                out["spendingLimit"] = sub["spendingLimit"]
            out["readAt"] = when(snap.at)
        if cost and not cost_error:
            out["costThisMonth"] = f"{page.money(cost['amount'], cost['currency'])} so far (read {when(cost_at)})"
        elif cost_error:
            out["costThisMonth"] = f"not read: {cost_error[:160]}"
        out["billing"] = BILLING
        if cfg.ddns_ready:
            out["ddnsEvery"] = f"every {cfg.minutes:g} min" + ("" if attached else ", once attached")
        writable = bool(cfg.api_ready) and out["valid"] and snap is not None
        out["tables"] = self._tables(cfg, snap, prices, hosts, writable, attached)
        out["forms"] = self._forms(snap) if writable else []
        if writable and cfg.ddns_ready:
            keeper = self.keeper()
            out["forms"] += [keeper.take_form(), keeper.now_form()]
        out["actions"] = ([{"hook": "refresh", "args": [], "title": "Refresh",
                            "note": "the subscription read again now (a dozen requests or so)"}] if cfg.api_ready else []) + \
                         ([{"form": dyndns.NOW_FORM, "title": "Update DNS now"}] if writable and cfg.ddns_ready and hosts else [])
        return out

    def _summary(self, cfg, works, failing, error, attached, snap, cost, hosts, states) -> str:
        if not cfg.api_ready:
            return "set up halfway"
        if works is False and not failing:
            return f"the API: {error[:120]}"
        if snap is None:
            if failing:
                return "the first read failed: it is tried again within minutes"
            return "reading the subscription…" if attached else "the subscription is read once attached"
        running = sum(1 for v in snap.vms if v["power"] == "running")
        bits = [plural(len(snap.vms), "VM") + (f" ({running} running)" if snap.vms else ""), plural(len(snap.zones), "DNS zone")]
        if cost:
            bits.append(f"{page.money(cost['amount'], cost['currency'])} this month")
        if cfg.ddns_ready:
            mine = [states[h.fqdn] for h in hosts if h.fqdn in states]
            if len(hosts) == 1 and mine and mine[0].ok:
                bits.append(f"{mine[0].fqdn} at {mine[0].address}")
            elif any(s.ok is not None for s in mine):
                bits.append(f"Dynamic DNS: {sum(1 for s in mine if s.ok)} of {plural(len(hosts), 'host')} current")
            else:
                bits.append("Dynamic DNS: the first check is under way" if attached else "Dynamic DNS: checked once attached")
        if failing:
            bits.append("the last read failed: tried again soon")
        return " · ".join(bits)

    def _tables(self, cfg, snap, prices, hosts, writable, attached) -> list:
        out = []
        if cfg.ddns_ready:
            out.append(self.keeper().table(hosts, cfg.minutes, attached=attached, take=writable,
                                           empty=None if snap is not None else "The subscription's zones are read first."))
        if snap is None:
            return out
        out.append(page.vm_table(snap, prices, writable))
        out += page.nsg_tables(snap, writable)
        out += page.zone_tables(snap, writable)
        out.append(page.key_table(snap, writable and not snap.troubles.get("keys")))
        out.append(page.ip_table(snap))
        out.append(page.disk_table(snap))
        out.append(page.group_table(snap))
        out.append(page.others_table(snap))
        return out

    @staticmethod
    def _forms(snap) -> list:
        forms = page.vm_forms() if snap.vms else []
        for g in snap.nsgs:
            forms += page.rule_forms(g)
        for z in page.zones_writable(snap):
            forms += page.record_forms(z)
        if snap.groups and not snap.troubles.get("keys"):  # the keys not read: none is added blind
            forms += page.key_forms(snap.groups)
        return forms


MACHINE = AzurePlugin()
