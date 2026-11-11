# plugin-platform-azure

Microsoft Azure for Liminal's platform: a subscription's virtual machines with their power state and price, disks,
public IP addresses, network security groups, Azure DNS zones and records, SSH keys and the cost this month, through
Azure Resource Manager; free changes only, each confirmed first; and Dynamic DNS through Azure DNS.

The user's words (2026-11-11): "lets roll plugins for EC2, vultr, azure and google cloud"; for the cloud plugins, "Free
changes only": show everything, change only what costs nothing, each change confirmed.

## What it shows

A machine plugin of the platform (`liminal_libs.machines.MachinePlugin`, plugin API 2.2, its icon Azure's mark):

- **The subscription**: its name and state, its offer (quotaId), its spending limit, and the **cost this month so far**
  (Cost Management's query, read at most every six hours: it throttles hard).
- **Virtual machines**: each VM's power state (running, stopped, deallocated ...) and whether its compute is billed in
  that state, its size, OS and image, its **price an hour and a month** (Azure's Retail Prices API: Linux or Windows,
  regular or spot, pay as you go, 730 hours a month), its public IPv4 and IPv6 addresses, when it was made.
- **Network security groups** (Azure's firewalls): each group, the VMs it is attached to (through a VM's network
  interface or its subnet), and a table of its rules, the default rules among them.
- **Azure DNS**: the zones (record sets used of the most, name servers) and a table of each zone's records.
- **SSH public keys** stored in Azure (type, size, SHA256 fingerprint), **public IP addresses** (static or dynamic, what
  each is on), **disks** (size, SKU, attached or not), **resource groups** (and how many resources each holds), and how
  many of **every other kind** of resource the subscription holds (Kubernetes clusters, load balancers, databases, apps,
  snapshots, images ...: one list of its resources).

**A powered-off VM still bills.** Azure's own words for Power Off: "You are still charged for this virtual machine." A
VM stopped from inside its OS is in the same state (Stopped). Only a deallocated VM stops its compute charge, and its
disks and static public IPs still bill. The page says so beside the VMs, in its facts and in each power form.

## What it changes, and how

Only what costs nothing, each through a form on the platform's page that names the exact change and is confirmed first:

| Change | Asked | What it does to the bill |
|---|---|---|
| **Start** a VM | once | its compute is billed again from then on |
| **Restart** a VM | once | none: it stays allocated and billed |
| **Deallocate** a VM | once | its compute is no longer billed (a dynamic public IP is released; the temporary disk's data may be lost) |
| **Power off** a VM | **twice** | none: it is still billed, as if it ran (said, and asked again) |
| **Set a record** in a zone | once | none (Azure DNS bills zones and queries, not records) |
| **Remove a record** | once | none |
| **Add a security rule** | once; **twice** when risky | none |
| **Remove a security rule** | once; **twice** when risky | none |
| **Add / remove an SSH public key** | once | none (a key resource is free) |

A risky rule is one that opens SSH (22), RDP (3389) or every port to the whole internet (`*`, `Internet`, `0.0.0.0/0`,
`::/0`), an inbound Deny covering SSH or RDP on a group attached to a VM, or the removal of the inbound Allow rule that
lets SSH or RDP in to a VM the group is attached to. The hook refuses it naming `accept_risky`, and the page asks a
second, explicit confirmation before it sends it. Power off is refused the same way, naming `accept_still_billed`.

How each change is made, as Azure's references give it:

- **A VM's power**: `POST .../virtualMachines/{vm}/start | restart | deallocate | powerOff` (api-version 2026-04-01),
  accepted by Azure (202) and done after; the VMs' states are read again about a minute later. Power off is graceful
  (`skipShutdown` is never sent): no hard power-off is offered.
- **A record**: Azure DNS writes a record set (every record of one name and type) whole. The record set is read just
  before, changed (an A, AAAA, CNAME or PTR record replaces the name's records of its type; an MX, TXT, NS, SRV or CAA
  record is added beside the others), and written back with `If-Match` its etag (a new one with `If-None-Match: *`), so a
  change someone made meanwhile is never written over; its TTL and metadata are kept, and every other record set of the
  zone is left as it is. Removing the last record of a set deletes the set (`If-Match` too). Refused before anything is
  sent: the zone's own SOA and apex NS records, an alias record set (changed in the portal), a CNAME beside other records
  or at the apex.
- **A security rule**: `PUT` or `DELETE .../networkSecurityGroups/{nsg}/securityRules/{rule}` (api-version 2026-01-01);
  the group's other rules are never touched. A new rule needs a name of its own and a priority (100 to 4096) no rule of
  its direction holds; the default rules cannot be removed.
- **An SSH public key**: `PUT` or `DELETE .../sshPublicKeys/{name}`: RSA of 2048 bits or more, or ED25519, the one line
  of a `.pub` file, stored in a resource group (in its location unless one is named).

## What it never does

Nothing that creates, resizes, restores or destroys a billable thing: no VM made, resized, redeployed, reimaged,
captured or deleted; no disk, snapshot, image or public IP made or deleted; no DNS zone made (a zone is billed by the
month); no backup; no template deployed. The client (`api.py`) sends a change only through one gate that knows the free
changes alone (`WRITES`), and its tests check that its source holds none of the other calls' paths: those are named on
the plugin's API card alone, marked as what would start or raise a charge.

## Setting it up

The plugin signs in as a **service principal**: an app registered in your Microsoft Entra tenant, with a client secret,
given a role on the subscription.

1. **Register an app**: the Microsoft Entra admin center (https://entra.microsoft.com) > Entra ID > App registrations >
   New registration (accounts in this organizational directory only). Its Overview shows the **Directory (tenant) ID**
   and the **Application (client) ID**.
2. **Make a client secret**: the app's Certificates & secrets > Client secrets > New client secret. Copy its **Value**
   (not its ID): it is shown only once. Choose an expiry; the plugin says when Azure refuses an expired one.
3. **Give it a role on the subscription**, limited to the reads and the free changes. Save this as `liminal-azure.json`,
   with your subscription's ID:

   ```json
   {
     "Name": "Liminal Azure (reads and free changes)",
     "IsCustom": true,
     "Description": "Reads everything; starts, restarts, deallocates and powers off VMs; writes DNS record sets; changes security rules; adds and removes SSH public keys.",
     "Actions": [
       "*/read",
       "Microsoft.Compute/virtualMachines/start/action",
       "Microsoft.Compute/virtualMachines/restart/action",
       "Microsoft.Compute/virtualMachines/deallocate/action",
       "Microsoft.Compute/virtualMachines/powerOff/action",
       "Microsoft.Compute/sshPublicKeys/write",
       "Microsoft.Compute/sshPublicKeys/delete",
       "Microsoft.Network/networkSecurityGroups/securityRules/write",
       "Microsoft.Network/networkSecurityGroups/securityRules/delete",
       "Microsoft.Network/dnszones/A/write", "Microsoft.Network/dnszones/A/delete",
       "Microsoft.Network/dnszones/AAAA/write", "Microsoft.Network/dnszones/AAAA/delete",
       "Microsoft.Network/dnszones/CNAME/write", "Microsoft.Network/dnszones/CNAME/delete",
       "Microsoft.Network/dnszones/MX/write", "Microsoft.Network/dnszones/MX/delete",
       "Microsoft.Network/dnszones/TXT/write", "Microsoft.Network/dnszones/TXT/delete",
       "Microsoft.Network/dnszones/NS/write", "Microsoft.Network/dnszones/NS/delete",
       "Microsoft.Network/dnszones/SRV/write", "Microsoft.Network/dnszones/SRV/delete",
       "Microsoft.Network/dnszones/CAA/write", "Microsoft.Network/dnszones/CAA/delete",
       "Microsoft.Network/dnszones/PTR/write", "Microsoft.Network/dnszones/PTR/delete"
     ],
     "NotActions": [],
     "AssignableScopes": ["/subscriptions/<your subscription ID>"]
   }
   ```

   then make it and give it to the app (the Azure CLI, signed in as the subscription's owner):

   ```
   az role definition create --role-definition liminal-azure.json
   az role assignment create --assignee <the app's client ID> --role "Liminal Azure (reads and free changes)" --scope /subscriptions/<your subscription ID>
   ```

   (`--assignee` takes the service principal's name: the app's client ID), or, in the Azure portal
   (https://portal.azure.com): Subscriptions > your subscription > Access control (IAM) > Add > Add custom role, its
   Basics tab's Baseline permissions: Start from JSON (this file); then Add > Add role assignment > that role > the app.
   `*/read` (what the built-in Reader role holds) covers every read, the cost this month among them (Cost Management
   asks read access to the subscription). With Reader alone, the plugin reads everything and Azure refuses every change
   in its own words.
4. **Enter the settings**: on the platform's page, the plugin's **Settings…** asks for each one below, the secret typed
   hidden; a value is never shown back. They are pairs the plugin asks of the login of the app it is attached to, each
   named by its variable (AZURE_CLIENT_SECRET is the pair `azure-client-secret`): today the platform's login keeps them
   as your user environment variables, and the plugin reads them at once. Setting the variables yourself works too.

| Variable | | Where it is made |
|---|---|---|
| `AZURE_TENANT_ID` | the API | the app's Overview: Directory (tenant) ID (a GUID, or the tenant's domain name) |
| `AZURE_CLIENT_ID` | the API | the app's Overview: Application (client) ID |
| `AZURE_CLIENT_SECRET` | the API (secret) | the app's Certificates & secrets: the client secret's Value |
| `AZURE_SUBSCRIPTION_ID` | the API | the Azure portal's Subscriptions: the subscription the role is on |
| `AZURE_DDNS_HOSTS` | optional | the hosts kept at this network's address, comma separated: `home.example.com`, `@.example.com` (the zone itself); their zones in the subscription's Azure DNS |
| `AZURE_DDNS_MINUTES` | optional | minutes between Dynamic DNS checks, 1 to 1440 (5 unless set) |

The plugin keeps no settings file and never shows a value (nor the IDs, which Azure's errors would otherwise name: they
are taken out of every message); its status names the settings that are set.

## Dynamic DNS

Each host in `AZURE_DDNS_HOSTS` that is in one of the subscription's Azure DNS zones is kept at this network's public
IPv4 address (the library's `machines.ddns.Keeper`): the address is asked of OpenDNS's resolver
(`myip.opendns.com`), else Google's (`o-o.myaddr.l.google.com`), each by its own address; each host's A record set is
read and written only when it differs (Update DNS now writes every host), with its etag, its TTL and metadata kept (a
new one made with a TTL of 300 seconds). An alias record set, or a name that is a CNAME, is not written: its row says
why. A host in no zone of the subscription is said in the plugin's problem.

## Valid, and the platform

The plugin is valid while its four credentials are set and the last read worked or has not been tried yet; the
platform disables a plugin that is not valid. A read that failed is taken as untried a quarter of an hour later (the
platform attaches it again and it is tried again), or at once when its settings change. A part of the subscription that
cannot be read (a role without one provider's read, a provider the subscription is not registered for) is said under
its table, and the rest is shown. While attached, it reads the subscription every quarter of an hour (about a dozen
requests, the record sets of at most 12 zones, the price of a VM size once a day, the cost every six hours) and checks
the Dynamic DNS hosts every `AZURE_DDNS_MINUTES`, in a thread of its own; detached, nothing of it runs.

## Its hooks

`present`, `status` (the summary, the facts, `tables`, `actions`, `forms`), `refresh()`, `vms()`, `zones()`,
`records(zone, group=None)`, `nsgs()`, `ssh_keys()`, `power(group, name, action, accept_still_billed=False)` (action:
start, restart, deallocate, poweroff), `set_record(group, zone, name, rtype, value, ttl=None)`,
`remove_record(group, zone, name, rtype, value="")`, `add_rule(group, nsg, name, direction, access, protocol, ports,
source=None, destination=None, priority=None, description=None, accept_risky=False)`, `remove_rule(group, nsg, name,
accept_risky=False)`, `add_ssh_key(group, name, public_key, location=None)`, `remove_ssh_key(group, name)`,
`ddns_update(force=True)`. A change's answer: `said`, `lines`, `ok`.

## From the command line

Its settings read from the environment (as this shell has them):

```
python -m plugin_platform_azure status
python -m plugin_platform_azure servers
python -m plugin_platform_azure groups | disks | ips | keys | cost
python -m plugin_platform_azure firewalls
python -m plugin_platform_azure domains
python -m plugin_platform_azure records example.com
python -m plugin_platform_azure ddns [--now]
python -m plugin_platform_azure power web1 start | restart | deallocate | poweroff
python -m plugin_platform_azure set example.com home A 203.0.113.7 --ttl 300
python -m plugin_platform_azure remove example.com home A 203.0.113.7
```

Each change asks you to type `yes` first (power off twice). `--json` before the command prints the answer as JSON;
`--group` names the resource group when a VM or a zone's name is in more than one.

## Its API

The plugin attaches to four of Microsoft's APIs, each on its page's API card with its parts (those used and the rest),
its calls, its limits and costs:

- **Azure Resource Manager** (https://management.azure.com): the subscription, resource groups, resources, Compute
  (VMs 2026-04-01, disks 2026-03-02, SSH public keys), Network (2026-01-01: network interfaces, public IPs, network
  security groups and their rules) and Cost Management (2026-06-01). Its reference:
  https://learn.microsoft.com/en-us/rest/api/azure/ ; its limits (per region, per subscription and service principal:
  250 reads refilled 25 a second, 200 writes and 200 deletes refilled 10 a second; the `x-ms-ratelimit-remaining-*`
  headers, kept on the card's facts):
  https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling ; what each VM
  state bills: https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing
- **Azure DNS** (Resource Manager's Microsoft.Network/dnszones, 2018-05-01): https://learn.microsoft.com/en-us/rest/api/dns/
- **Azure Retail Prices** (https://prices.azure.com/api/retail/prices, public, no sign-in):
  https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices
- **Microsoft identity platform** (the client credentials grant at
  `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, scope `https://management.azure.com/.default`):
  https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow

The global Azure cloud alone (not Azure Government nor Azure operated by 21Vianet).

## Install

```
pip install "plugin-platform-azure @ git+https://github.com/pcxmac-dev/plugin-platform-azure@main"
```

or, for the platform's preview, a checkout in the plugin directory (`LIMINAL_PLUGINS`). Its tests use a stand-in for
Azure alone (`python -m pytest`): none reaches Microsoft or the network. `LIMINAL_VENDOR_PAGES=1` also asks every
address on its API card once.
