# Changelog

## 0.1.5 (2026-11-25)

Its changes are asked only from the page (`PAGE_ONLY_HOOKS`, liminal-libs 1.66.0's word): the independent review's
finding PLT-H1, and the sweep of every plugin's hooks that followed it. The user, 2026-11-25, chose "Plugin releases":
each plugin says which of its hooks only its page asks.

- **What only the page asks**: `power`, `set_record`, `remove_record`, `add_rule`, `remove_rule`, `add_ssh_key`,
  `remove_ssh_key`, `ddns_update` and `ddns_take_over`. Another plugin's ask of one is refused (403), and so is an ask
  that names no asker; liminal-platform 0.34.0 refuses one over HTTP (401) unless its login shows that you are at the
  page. A platform that holds no login asks them as before. The 401 rests on the login's word that your browser is
  signed in, and a local login signs `secret` and `default` in with no password, so a program on this PC can sign
  itself in and ask them still: a proof that a program cannot make is the login's and the platform's to give, not this
  plugin's.
- **Before**, the platform handed an ask of any program on this PC (`POST /api/machines/azure/ask`, with a header
  anyone can send and a Host the client chooses, no sign-in) straight to the hook it named, and the hook acted as your
  service principal. The page's dialogs were the only confirmation, and a second confirmation is an argument the
  asker sets: `power` with `[group, name, "start", false, true]` started a deallocated VM, its compute charge
  beginning again; `add_rule` with `accept_risky` true opened SSH to the whole internet, and `remove_rule` took out
  the rule letting SSH in (the rule in words, which it needs, is in the status anyone reads); `ddns_take_over` with
  `[host, null, true]` pointed a Dynamic DNS host holding another address at this network. `set_record` set the
  domain's own address to another and `remove_record` took a value out of a record set, neither asked twice.
- **As before**: its reads (`present`, `status`, `refresh` and the lists) are asked by anyone. The background (the
  subscription read every quarter of an hour, the Dynamic DNS checks) and the command line call the plugin's code
  themselves, not through an ask. The library floor stays 1.49.9: a library before 1.66.0 does not read the word, and
  asks the hooks as it did.
- Tests: `tests/test_who_asks.py`, through the library's own App over the stand-in Azure: each of the nine refused to
  another plugin and to no one, no request made (not a token asked for); the same nine asked from the page, each sent;
  the reads answered to a plugin; a Dynamic DNS pass run by the plugin's own code. A hook taken out of
  `PAGE_ONLY_HOOKS` fails it. Skipped on a library before 1.66.0.

## 0.1.4 (2026-11-24)

A security rule is removed only while it is the one shown (the review of 2026-11-21, item 26). `remove_rule` took
the rule's name alone, so a rule changed since the page showed it (other ports, other sources, another access) was
removed unseen. It now carries the rule in words as shown (`rule`: `rules.said`, needed, as Linode's and Vultr's
removals do): each group's table's Remove sends it, the form shows it ("As shown"), and a rule that reads otherwise
now is refused, nothing sent. Test: a removal without the words refused; one whose rule changed after it was shown
refused with nothing written; as read again, removed.

## 0.1.3 (2026-11-14)

Drawn under the platform's Cloud plugins section, in the list on the left (the user: "classify the cloud plugins under the 'cloud plugins' section which should be on the far left"): `SECTION = "cloud"`. That is liminal-libs
1.51.0's machine-plugin attribute; liminal-platform 0.25.0 draws it, and an older platform keeps the plugin under Machine
plugins. Nothing else changes.

## 0.1.2 (2026-11-11)

What the re-verification of the audit's fixes found in Dynamic DNS (liminal-libs 1.49.7), fixed:

- **Take over… is asked twice.** It sets the record at once and drops every address it holds, so the keeper refuses
  until `accept_take_over` is exactly true (`ddns.TakeOverRefused`), which the page asks as a second confirmation (the
  take form's third field). Before it, the host must be in the setting and its record still hold what the page showed
  (read again); else nothing is taken over.
- **A host taken out of the setting is let go, while the plugin ran or not** (`Keeper.settle`): with the whole
  `AZURE_DDNS_HOSTS` setting, after each refresh and before each pass, and only once the subscription's zones are read
  (never on a zone list not read). Put back in the setting later, it is left as it is, its row offering Take over…
  again. It replaces the plugin's own letting go.
- The third round of checks (liminal-libs 1.49.8): a take-over is used up once its write lands (the host the keeper's
  own from then on); only the serving platform's plugin settles, so its own command line, run from a shell without
  `AZURE_DDNS_HOSTS`, never empties `ddns.json`; a Take over… refused because the record changed brings the host's row
  up to date first, so it offers what the record holds now.
- Needs liminal-libs 1.49.8.

Needs liminal-libs>=1.49.9: a take-over's consent is bound to the addresses it drops (a record changed after
a failed write is asked about again); the state file keeps each take-over's addresses.

## 0.1.1 (2026-11-11)

What the audit of the six cloud plugins found before any key went in (session 87405e6a: eight reviewers, a skeptic per
finding; every serious finding confirmed), fixed. Needs liminal-libs 1.49.2.

- **Dynamic DNS changes only what is its own** (the library's Keeper): a host with no A record (made), one pointing here
  or at the address it set last, or one you took over. Any other record (another address, or several) is left as it is
  and said so, its row offering **Take over…** (a confirmed form, `ddns_take_over`, then a pass for that host); several
  addresses are never cut to one. What is its own is kept in the platform's folder (`azure/ddns.json`), so a restart after
  the network's address changed still knows its record. **Update DNS now** is a confirmed form. A host taken out of the
  settings is let go; one whose A record you set by hand on the page is let go too (left as you set it). A zone name two
  resource groups hold is written in neither; with no host in the subscription's zones, not even this network's address
  is asked.
- **Starting a deallocated VM is asked twice** (`accept_costs`), the refusal saying which charge resumes and at what
  price; the VM's state is read just before the start (its instance view), not taken from a read up to a quarter hour
  old; a stopped one, billing all along, stays asked once.
- **A rule or an SSH key is never replaced**: the group (or the key) is read just before, one of that name is refused,
  and the PUT is sent with `If-None-Match: *`. With the key list not read, no key is offered to add. A rule's Source must
  be named (an empty one was the whole internet); an Allow opening a database, Docker's API, WinRM, SMB, Telnet, VNC
  (or SSH, RDP, every port) to the whole internet is asked twice, and so is removing a Deny that keeps a later rule from
  opening one.
- **A read failing for a passing reason** (no connection, a 5xx, a 429) leaves the plugin valid, its last tables shown and
  the failure said, and is tried again after a minute, then twice as long each time: the platform no longer detaches it,
  so Dynamic DNS goes on. A refusal (a role missing, the credentials) is still not valid.
- **The background reading starts only when the platform attaches it**: the charts app run alone attaches every plugin it
  finds, and nothing of this one runs then. A pass ends once the plugin is detached (nothing more written) and reads no
  settings while it runs.
- **A second confirmation counts only when exactly true** (`accept_still_billed`, `accept_costs`, `accept_risky`): a
  "false", "yes" or 1 from a program on this PC is refused like none.
- A private key pasted as a public key is refused without a word of it said back (the platform logs no hook's values
  since 0.20.1); a secret pasted into the Dynamic DNS hosts is taken out of the page; a Resource Manager answer naming an
  API version it does not serve (NoRegisteredProviderFound) is said under its table, never shown as "nothing there"; a
  price list's next page on its own host followed.
- The card: Network Security Groups - Get and SSH Public Keys - Get (read just before a change), the start call's
  words.

The platform's one-shot commands (status, machine: `PlatformApp.once`, liminal-platform 0.20.1) start none of its background work.

## 0.1.0 (2026-11-11)

The first release (the user: "lets roll plugins for EC2, vultr, azure and google cloud"; for the cloud plugins, "Free
changes only"; and "each plugin should reflect the the API its attached to, and present links that provide
documentation"):

- a machine plugin of the platform (plugin API 2.2, liminal-libs 1.49.0), its icon Azure's mark;
- its settings read through the library's Login interface alone, as pairs named by their variables
  (`azure-client-secret` for AZURE_CLIENT_SECRET): AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and
  AZURE_SUBSCRIPTION_ID (a service principal's), AZURE_DDNS_HOSTS and AZURE_DDNS_MINUTES; no settings file; the status
  names the settings set, never a value, and every message has the secret and the IDs taken out;
- its HTTP through the library's RestClient: a Resource Manager token by the Microsoft identity platform's client
  credentials grant (TokenSource: kept until a minute before it ends, asked anew when refused); Azure Resource Manager
  for the subscription, resource groups and every resource's count, the VMs (List All, their power states at once with
  statusOnly, one by one when it does not give them), disks, network interfaces, public IPs, network security groups
  and their rules, SSH public keys, and the cost this month (Cost Management's query, every six hours at most); Azure
  DNS for the zones and their record sets; the Retail Prices API for each VM size's price an hour (Linux or Windows,
  regular or spot, kept a day); a list followed across its pages on Resource Manager's own host alone; a part that
  cannot be read said under its table, the rest shown;
- the free changes, each through a form the platform's page confirms: a VM started (its confirmation says which applies
  to that VM: a deallocated one's compute charge starts again, a stopped one was billing all along; the start call marked
  as costing on the card), restarted, deallocated or powered off (power off still bills: said, and asked a second time,
  `accept_still_billed`); a DNS record set and removed, the
  record set read just before and written whole with its etag, every other record kept, the zone's own SOA and NS, alias
  record sets and a CNAME beside other records refused; a security rule added or removed (one opening SSH, RDP or every
  port to the whole internet, denying SSH or RDP to a VM, or removing the rule that lets SSH in to one, asked twice,
  `accept_risky`); an SSH public key added (RSA of 2048 bits or more, or ED25519) or removed;
- nothing that creates, resizes, restores or destroys a billable thing: the client sends a change only through a gate
  that knows the free changes alone, and its source holds none of the other calls' paths (a test checks it);
- Dynamic DNS through Azure DNS (the library's Keeper): this network's IPv4 address asked of OpenDNS, else Google, each
  host's A record set written only where it differs (Update DNS now: every host);
- while attached to the platform app: the subscription read every quarter of an hour, the VMs' states again soon after
  a power change, the Dynamic DNS hosts every AZURE_DDNS_MINUTES (5), in a thread of its own; detached, nothing runs.
  Valid while set up and the last read worked or is untried;
- its API card: Azure Resource Manager, Azure DNS, Azure Retail Prices and the Microsoft identity platform, each with
  Microsoft's pages (reference, guides, limits, pricing, status, changes, specification, console, CLI, SDK, roles),
  every part of it (used or not), the calls it makes and the notable others (those that would start a charge marked),
  read 2026-11-11; its facts (requests made, the last answer, the rate limit left, the token's life, the cost) from what
  the client already learned;
- `python -m plugin_platform_azure status | servers | groups | disks | ips | keys | cost | firewalls | domains | records |
  ddns | power | set | remove` (each change asked yes first, power off twice).
