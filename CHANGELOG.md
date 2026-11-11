# Changelog

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
- the free changes, each through a form the platform's page confirms: a VM started, restarted, deallocated or powered
  off (power off still bills: said, and asked a second time, `accept_still_billed`); a DNS record set and removed, the
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
