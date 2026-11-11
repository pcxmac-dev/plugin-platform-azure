"""The plugin's settings, read through the library's Login interface and nothing else (as every cloud plugin's: the user's
settings are the signed-in user's, kept by the login). Each is a pair named by its variable (AZURE_CLIENT_SECRET is the pair
`azure-client-secret`: apps.authorization.pair_name), asked of the login of the app the plugin is attached to: the
platform's EnvironmentLogin today, the login app's pairs once the platform binds it. Not attached (the command line), an
EnvironmentLogin of its own. The plugin keeps no settings file: a value is never written anywhere, never shown, and only
the names of the settings set are said.

The four credentials are a service principal's (an app registered in Microsoft Entra ID, with a client secret and a role on
the subscription): the README says how to make one whose role allows the reads and the free changes alone."""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from liminal_libs.apps import EnvironmentLogin, Login
from liminal_libs.machines import ddns
from liminal_libs.sources.keys import KeyVar

TENANT_ID = "AZURE_TENANT_ID"
CLIENT_ID = "AZURE_CLIENT_ID"
CLIENT_SECRET = "AZURE_CLIENT_SECRET"
SUBSCRIPTION_ID = "AZURE_SUBSCRIPTION_ID"
DDNS_HOSTS = "AZURE_DDNS_HOSTS"
DDNS_MINUTES = "AZURE_DDNS_MINUTES"

# what the platform's Settings… lists (and the login app's "Pairs your plugins ask for", once it lists the platform's)
KEYS = (
    KeyVar(TENANT_ID, label="Directory (tenant) ID", secret=False,
           hint="Microsoft Entra admin center > Entra ID > App registrations > your app > Overview: Directory (tenant) ID"),
    KeyVar(CLIENT_ID, label="Application (client) ID", secret=False,
           hint="the same Overview: Application (client) ID of the app the plugin signs in as"),
    KeyVar(CLIENT_SECRET, label="Client secret",
           hint="the app's Certificates & secrets > Client secrets > New client secret: its Value (shown once)"),
    KeyVar(SUBSCRIPTION_ID, label="Subscription ID", secret=False,
           hint="Azure portal > Subscriptions: the ID of the subscription the app was given its role on"),
    KeyVar(DDNS_HOSTS, label="Dynamic DNS hosts", secret=False,
           hint="optional: hosts kept at this network's address, comma separated: home.example.com, @.example.com "
                "(the zone itself); their zones in the subscription's Azure DNS"),
    KeyVar(DDNS_MINUTES, label="Dynamic DNS minutes", secret=False,
           hint="optional: minutes between Dynamic DNS checks, 1 to 1440 (5 unless set)"),
)
NAMES = tuple(k.name for k in KEYS)
CREDENTIALS = (TENANT_ID, CLIENT_ID, CLIENT_SECRET, SUBSCRIPTION_ID)

GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DOMAIN = re.compile(r"^(?=.{3,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


@dataclass(frozen=True)
class Config:
    """The settings as read (`present`: the names of those set; `problems`: what was set but could not be taken, in words
    that never hold a value)."""

    tenant: str = field(default="", repr=False)
    client_id: str = field(default="", repr=False)
    client_secret: str = field(default="", repr=False)
    subscription: str = field(default="", repr=False)
    hosts: tuple[str, ...] = ()  # the Dynamic DNS hosts as typed (split against the subscription's zones once they are read)
    minutes: float = ddns.MINUTES[2]
    present: frozenset = frozenset()
    problems: tuple[str, ...] = ()

    @property
    def api_ready(self) -> bool:
        """The four credentials set, each in its form."""
        return bool(self.tenant and self.client_id and self.client_secret and self.subscription)

    @property
    def ddns_ready(self) -> bool:
        """Dynamic DNS goes through Azure DNS: the API set up and the hosts named."""
        return self.api_ready and bool(self.hosts)

    @property
    def incomplete(self) -> tuple[str, ...]:
        """What the credentials set halfway lack, in words (nothing when none is set, or all are)."""
        missing = [n for n in CREDENTIALS if n not in self.present]
        if not missing or len(missing) == len(CREDENTIALS):
            return ()
        return (f"{' and '.join(missing)} {'is' if len(missing) == 1 else 'are'} not set (the API needs all four)",)

    @property
    def secrets(self) -> tuple[str, ...]:
        """The values taken out of every message the plugin gives: the secret and the IDs (a setting's value is never
        shown, and Azure's errors name the subscription and the client)."""
        return tuple(v for v in (self.client_secret, self.tenant, self.client_id, self.subscription) if v)

    def print_of(self, *names: str) -> str:
        """A fingerprint of these settings' values (kept in memory to notice a change; never shown nor written)."""
        values = {TENANT_ID: self.tenant, CLIENT_ID: self.client_id, CLIENT_SECRET: self.client_secret,
                  SUBSCRIPTION_ID: self.subscription, DDNS_HOSTS: repr(self.hosts), DDNS_MINUTES: str(self.minutes)}
        return hashlib.sha256("\0".join(f"{n}={values[n]}" for n in names).encode("utf-8")).hexdigest()

    @property
    def api_print(self) -> str:
        return self.print_of(*CREDENTIALS)

    @property
    def ddns_print(self) -> str:
        return self.print_of(*CREDENTIALS, DDNS_HOSTS)


def parse(values: Mapping[str, str]) -> Config:
    """The settings from their values by variable (those not set left out or empty)."""
    v = {n: str(values.get(n) or "").strip() for n in NAMES}
    present = frozenset(n for n in NAMES if v[n])
    problems: list[str] = []
    tenant = v[TENANT_ID]
    if tenant and not (GUID.match(tenant) or DOMAIN.match(tenant)):
        problems.append(f"{TENANT_ID} is neither a tenant ID (a GUID) nor the tenant's domain name (contoso.onmicrosoft.com)")
        tenant = ""
    client_id = v[CLIENT_ID]
    if client_id and not GUID.match(client_id):
        problems.append(f"{CLIENT_ID} is not an application (client) ID: a GUID, as the app's Overview shows it")
        client_id = ""
    subscription = v[SUBSCRIPTION_ID]
    if subscription and not GUID.match(subscription):
        problems.append(f"{SUBSCRIPTION_ID} is not a subscription ID: a GUID, as the Azure portal's Subscriptions shows it")
        subscription = ""
    minutes = ddns.MINUTES[2]
    if v[DDNS_MINUTES]:
        try:
            minutes = min(max(float(v[DDNS_MINUTES]), ddns.MINUTES[0]), ddns.MINUTES[1])
        except ValueError:
            problems.append(f"{DDNS_MINUTES} is not a number of minutes: {ddns.MINUTES[2]:g} is used")
    hosts = tuple(h.strip() for h in re.split(r"[,;\s]+", v[DDNS_HOSTS]) if h.strip())
    return Config(tenant=tenant, client_id=client_id.lower(), client_secret=v[CLIENT_SECRET], subscription=subscription.lower(),
                  hosts=hosts, minutes=minutes, present=present, problems=tuple(problems))


def read(login: Login | None = None) -> Config:
    """The settings as `login` furnishes them (the login of the app the plugin is attached to), else an EnvironmentLogin's:
    the variables set, by their pairs' names; a login that cannot be asked furnishes none, and says so."""
    asked = login if login is not None else EnvironmentLogin()
    try:
        values = asked.variables(NAMES)
    except Exception as e:  # noqa: BLE001 - a login that cannot be asked: nothing set, and why
        return Config(problems=(f"the settings could not be read from the login: {type(e).__name__}",))
    return parse(values)
