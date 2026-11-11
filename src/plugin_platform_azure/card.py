"""What the plugin attaches to (plugin API 2.2, liminal_libs.sources.apis): Azure Resource Manager, Azure DNS (a provider of
it with a reference of its own), the Azure Retail Prices API and the Microsoft identity platform's token endpoint, each as
Microsoft's own pages give it (read 2026-11-11): what it is, its parts (those the plugin uses and the rest), the calls the
plugin makes and the notable others (those that would start or raise a charge marked: the plugin's client holds none of
them), its limits and costs, and the pages about it."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

from .api import (COST, DISKS, GROUPS, NICS, NSG, NSGS, PUBLIC_IPS, RECORD_SET, RESOURCES, RETAIL, RULE, SSH_KEY, SSH_KEYS,
                  SUBSCRIPTION, TOKEN, V_COMPUTE, V_COST, V_DISKS, V_DNS, V_NETWORK, V_PRICES, V_RESOURCES, V_SUBSCRIPTIONS,
                  VM, VM_DEALLOCATE, VM_POWER_OFF, VM_RESTART, VM_START, VM_VIEW, VMS, ZONE_ALL, ZONES)

VERIFIED = "2026-11-11"
ARM_NAME = "Azure Resource Manager"
DNS_NAME = "Azure DNS"
PRICES_NAME = "Azure Retail Prices"
IDENTITY_NAME = "Microsoft identity platform"

L = "https://learn.microsoft.com/en-us"
REST = f"{L}/rest/api"
COMPUTE = f"{REST}/compute"
NETWORK = f"{REST}/virtualnetwork"
PORTAL = "https://portal.azure.com/"
STATUS = "https://azure.status.microsoft/en-us/status"
RG = SUBSCRIPTION + "/resourceGroups/{resourceGroupName}"
ZONE = RG + "/providers/Microsoft.Network/dnsZones/{zoneName}"


def call(method: str, path: str, about: str, area: str, used: str = "", docs: str = "", writes: bool = False,
         costs: bool = False) -> Call:
    return Call(f"{method} {path}", about, area, used, docs, writes or method in ("PUT", "PATCH", "DELETE") or costs, costs)


ARM = Api(
    name=ARM_NAME,
    maker="Microsoft",
    about=("Azure's control plane: every Azure resource (virtual machines, disks, networks, DNS zones, SSH keys, budgets) "
           "is read and changed through it, at one HTTPS address, as JSON, each resource provider with an api-version of "
           "its own. Who may do what is Azure RBAC's: a role assigned on the subscription decides what a service "
           "principal's token may read and change."),
    kind="rest",
    base="https://management.azure.com",
    version=(f"Resources {V_RESOURCES}, Subscriptions {V_SUBSCRIPTIONS}, Compute {V_COMPUTE} (Disks {V_DISKS}), "
             f"Network {V_NETWORK}, Cost Management {V_COST}"),
    auth=("A bearer token from the Microsoft identity platform (the client credentials grant, scope "
          "https://management.azure.com/.default) for a service principal; the roles it holds on the subscription "
          "decide what it may do."),
    limits=("Per region, a token bucket for each subscription and service principal: 250 reads (refilled 25 a second), "
            "200 writes and 200 deletes (10 a second each), and 15 times those across all principals; what is left comes "
            "back in the x-ms-ratelimit-remaining-subscription-* headers, and past it a 429 with Retry-After. Compute: "
            "listing VMs 900 at most (300 a minute) a subscription; a VM's start, restart, power off or deallocation 12 "
            "at most (4 a minute) a VM. Network: 10,000 reads and 1,000 writes in 5 minutes."),
    costs=("Asking costs nothing. A running VM bills its compute by the hour, and so does a stopped (powered-off) one; "
           "a deallocated one does not, though its disks and networking still bill, and starting it starts its compute "
           "charge again (the plugin's Start says so first). Creating VMs, disks, snapshots or public IPs, resizing and "
           "backups start or raise charges: the plugin does none of them."),
    links=(
        Link("Azure REST API reference", f"{REST}/azure/", "docs"),
        Link("Resource Manager REST API", f"{REST}/resources/", "reference"),
        Link("Compute: Virtual Machines", f"{COMPUTE}/virtual-machines", "reference"),
        Link("Virtual Networks: Network Security Groups", f"{NETWORK}/network-security-groups", "reference"),
        Link("Cost Management REST APIs", f"{REST}/cost-management/", "reference"),
        Link("What is Azure Resource Manager?", f"{L}/azure/azure-resource-manager/management/overview", "guide"),
        Link("Track asynchronous Azure operations", f"{L}/azure/azure-resource-manager/management/async-operations", "guide"),
        Link("States and billing status of Azure VMs", f"{L}/azure/virtual-machines/states-billing", "guide"),
        Link("Network security groups", f"{L}/azure/virtual-network/network-security-groups-overview", "guide"),
        Link("Service tags", f"{L}/azure/virtual-network/service-tags-overview", "guide"),
        Link("SSH keys in the Azure portal", f"{L}/azure/virtual-machines/ssh-keys-portal", "guide"),
        Link("How Resource Manager throttles requests", f"{L}/azure/azure-resource-manager/management/request-limits-and-throttling", "limits"),
        Link("Compute throttling limits", f"{L}/azure/virtual-machines/compute-throttling-limits", "limits"),
        Link("Azure subscription and service limits", f"{L}/azure/azure-resource-manager/management/azure-subscription-service-limits", "limits"),
        Link("Linux VM pricing", "https://azure.microsoft.com/en-us/pricing/details/virtual-machines/linux/", "pricing"),
        Link("Windows VM pricing", "https://azure.microsoft.com/en-us/pricing/details/virtual-machines/windows/", "pricing"),
        Link("Managed disks pricing", "https://azure.microsoft.com/en-us/pricing/details/managed-disks/", "pricing"),
        Link("IP addresses pricing", "https://azure.microsoft.com/en-us/pricing/details/ip-addresses/", "pricing"),
        Link("Bandwidth pricing", "https://azure.microsoft.com/en-us/pricing/details/bandwidth/", "pricing"),
        Link("Pricing calculator", "https://azure.microsoft.com/en-us/pricing/calculator/", "pricing"),
        Link("Azure status", STATUS, "status"),
        Link("Azure updates", "https://azure.microsoft.com/en-us/updates/", "changelog"),
        Link("Azure REST API specifications", "https://github.com/Azure/azure-rest-api-specs", "spec"),
        Link("Azure portal", PORTAL, "console"),
        Link("Azure CLI", f"{L}/cli/azure/", "tool"),
        Link("Azure SDK for Python", "https://github.com/Azure/azure-sdk-for-python", "sdk"),
        Link("Azure custom roles", f"{L}/azure/role-based-access-control/custom-roles", "auth"),
        Link("Azure built-in roles", f"{L}/azure/role-based-access-control/built-in-roles", "auth"),
        Link("Compute permissions (RBAC actions)", f"{L}/azure/role-based-access-control/permissions/compute", "auth"),
        Link("Networking permissions (RBAC actions)", f"{L}/azure/role-based-access-control/permissions/networking", "auth"),
    ),
    areas=(
        Area("Subscriptions", "the subscription: its name, state, offer and spending limit", f"{REST}/resources/subscriptions",
             "the account's facts"),
        Area("Resource groups", "the groups every resource is in", f"{REST}/resources/resource-groups", "the Resource groups table"),
        Area("Resources", "every resource of the subscription, whatever its kind", f"{REST}/resources/resources",
             "the counts of every kind (Other resources)"),
        Area("Virtual machines", "VMs: their model, run-time state and power", f"{COMPUTE}/virtual-machines",
             "the Virtual machines table; started, restarted, deallocated and powered off"),
        Area("Disks", "managed disks: OS and data disks, attached or not", f"{COMPUTE}/disks", "the Disks table"),
        Area("SSH public keys", "public keys kept as resources, offered when a VM is made", f"{COMPUTE}/ssh-public-keys",
             "the SSH keys table; keys added and removed"),
        Area("Network interfaces", "a VM's network cards: their addresses, subnets and security group",
             f"{NETWORK}/network-interfaces", "which VM each address and security group belongs to"),
        Area("Public IP addresses", "addresses reachable from the internet, static or dynamic", f"{NETWORK}/public-ip-addresses",
             "the Public IP addresses table and the VMs' addresses"),
        Area("Network security groups", "Azure's firewalls: rules on a VM's network interface or subnet",
             f"{NETWORK}/network-security-groups", "a table of each group's rules, with the VMs it is attached to"),
        Area("Security rules", "a network security group's rules, one by one", f"{NETWORK}/security-rules",
             "rules added and removed (the risky ones asked twice)"),
        Area("Cost Management", "costs and usage by scope: queries, budgets, exports", f"{REST}/cost-management/",
             "the cost this month so far (Query - Usage)"),
        Area("Deployments", "templates (ARM, Bicep) deployed to a scope", f"{REST}/resources/deployments"),
        Area("Providers", "the resource providers and whether the subscription is registered for each", f"{REST}/resources/providers"),
        Area("Tags", "names and values on resources", f"{REST}/resources/tags"),
        Area("Management locks", "locks that keep resources from being changed or deleted", f"{REST}/resources/management-locks"),
        Area("Authorization", "role definitions and assignments (Azure RBAC)", f"{REST}/authorization/"),
        Area("Policy", "Azure Policy's definitions and assignments", f"{REST}/policy/"),
        Area("Virtual machine sizes", "the sizes a region offers", f"{COMPUTE}/virtual-machine-sizes"),
        Area("Resource SKUs", "the SKUs a subscription may use, by region and zone", f"{COMPUTE}/resource-skus"),
        Area("Snapshots", "copies of disks at a point in time", f"{COMPUTE}/snapshots"),
        Area("Images", "managed images VMs are made from", f"{COMPUTE}/images"),
        Area("Galleries", "Azure Compute Gallery: images and applications shared", f"{COMPUTE}/galleries"),
        Area("Virtual machine scale sets", "groups of identical VMs, scaled together", f"{COMPUTE}/virtual-machine-scale-sets"),
        Area("Availability sets", "VMs spread across fault and update domains", f"{COMPUTE}/availability-sets"),
        Area("Usage", "the subscription's compute quotas and their use, by region", f"{COMPUTE}/usage"),
        Area("Virtual machine run commands", "scripts run inside a VM by its agent", f"{COMPUTE}/virtual-machine-run-commands"),
        Area("Virtual machine extensions", "agents and software installed in a VM", f"{COMPUTE}/virtual-machine-extensions"),
        Area("Virtual networks", "private networks and their address spaces", f"{NETWORK}/virtual-networks"),
        Area("Subnets", "a virtual network's ranges", f"{NETWORK}/subnets"),
        Area("NAT gateways", "outbound internet for a subnet", f"{NETWORK}/nat-gateways"),
        Area("Bastion hosts", "SSH and RDP to VMs through the portal", f"{NETWORK}/bastion-hosts"),
        Area("Load balancers", "layer 4 load balancing", f"{REST}/load-balancer/"),
        Area("Application gateways", "layer 7 load balancing and a web application firewall", f"{REST}/application-gateway/"),
        Area("Network gateways", "VPN and ExpressRoute gateways", f"{REST}/network-gateway/"),
        Area("Consumption", "usage details, budgets, price sheets", f"{REST}/consumption/"),
        Area("Billing", "billing accounts, profiles and invoices", f"{REST}/billing/"),
        Area("Kubernetes Service (AKS)", "managed Kubernetes clusters", f"{REST}/aks/"),
        Area("App Service", "web apps, functions and their plans", f"{REST}/appservice/"),
        Area("SQL Database", "Azure SQL servers and databases", f"{REST}/sql/"),
        Area("Database for PostgreSQL", "managed PostgreSQL servers", f"{REST}/postgresql/"),
        Area("Database for MySQL", "managed MySQL servers", f"{REST}/mysql/"),
        Area("Cosmos DB", "Cosmos DB accounts", f"{REST}/cosmos-db-resource-provider/"),
        Area("Storage accounts", "blob, file, queue and table storage accounts", f"{REST}/storagerp/"),
        Area("Key Vault", "keys, secrets and certificates", f"{REST}/keyvault/"),
        Area("Container Instances", "containers run without a cluster", f"{REST}/container-instances/"),
        Area("Container Registry", "private container image registries", f"{REST}/containerregistry/"),
        Area("Monitor", "metrics, logs, alerts and diagnostic settings", f"{REST}/monitor/"),
        Area("Resource Graph", "queries across subscriptions' resources", f"{REST}/azure-resourcegraph/"),
        Area("Recovery Services", "backups and site recovery", f"{REST}/recoveryservices/"),
        Area("Traffic Manager", "DNS-based traffic routing", f"{REST}/trafficmanager/"),
        Area("CDN and Front Door", "content delivery profiles and endpoints", f"{REST}/cdn/"),
    ),
    calls=(
        call("GET", SUBSCRIPTION, "Subscriptions - Get: the subscription's details", "Subscriptions", "the account's facts",
             f"{REST}/resources/subscriptions/get"),
        call("GET", GROUPS, "Resource Groups - List", "Resource groups", "the Resource groups table", f"{REST}/resources/resource-groups/list"),
        call("GET", RESOURCES, "Resources - List: every resource of the subscription", "Resources",
             "the counts of every kind of resource", f"{REST}/resources/resources/list"),
        call("GET", VMS, "Virtual Machines - List All (and with statusOnly=true, every VM's power state at once)",
             "Virtual machines", "the Virtual machines table and their power states", f"{COMPUTE}/virtual-machines/list-all"),
        call("GET", VM_VIEW, "Virtual Machines - Instance View: a VM's run-time state", "Virtual machines",
             "a power state the list did not give; a VM's state read just before it is started",
             f"{COMPUTE}/virtual-machines/instance-view"),
        call("POST", VM_START, "Virtual Machines - Start: starts the compute charge again for a deallocated VM (a stopped "
             "one was billing all along)", "Virtual machines",
             "Start… (its state read just before: a start that starts the compute charge again is asked twice, its "
             "price said)",
             f"{COMPUTE}/virtual-machines/start", writes=True, costs=True),
        call("POST", VM_RESTART, "Virtual Machines - Restart", "Virtual machines", "Restart…", f"{COMPUTE}/virtual-machines/restart",
             writes=True),
        call("POST", VM_DEALLOCATE, "Virtual Machines - Deallocate: shut down, its compute released and no longer billed",
             "Virtual machines", "Deallocate…", f"{COMPUTE}/virtual-machines/deallocate", writes=True),
        call("POST", VM_POWER_OFF, "Virtual Machines - Power Off: stopped, still billed", "Virtual machines",
             "Power off… (asked twice: it still bills)", f"{COMPUTE}/virtual-machines/power-off", writes=True),
        call("GET", DISKS, "Disks - List", "Disks", "the Disks table", f"{COMPUTE}/disks/list"),
        call("GET", SSH_KEYS, "SSH Public Keys - List By Subscription", "SSH public keys", "the SSH keys table",
             f"{COMPUTE}/ssh-public-keys/list-by-subscription"),
        call("GET", SSH_KEY, "SSH Public Keys - Get", "SSH public keys", "a key of that name looked for just before one is added",
             f"{COMPUTE}/ssh-public-keys/get"),
        call("PUT", SSH_KEY, "SSH Public Keys - Create: a public key kept as a resource (free); sent with If-None-Match: * "
             "so none of its name is replaced", "SSH public keys", "Add an SSH key…", f"{COMPUTE}/ssh-public-keys/create"),
        call("DELETE", SSH_KEY, "SSH Public Keys - Delete", "SSH public keys", "Remove (a key)", f"{COMPUTE}/ssh-public-keys/delete"),
        call("GET", NICS, "Network Interfaces - List All", "Network interfaces", "which VM each address and security group is on",
             f"{NETWORK}/network-interfaces/list-all"),
        call("GET", PUBLIC_IPS, "Public IP Addresses - List All", "Public IP addresses", "the Public IP addresses table",
             f"{NETWORK}/public-ip-addresses/list-all"),
        call("GET", NSGS, "Network Security Groups - List All (their rules with them)", "Network security groups",
             "the tables of each group's rules", f"{NETWORK}/network-security-groups/list-all"),
        call("GET", NSG, "Network Security Groups - Get", "Network security groups",
             "the group read just before a rule is added or removed (its rules and attachments as they are now)",
             f"{NETWORK}/network-security-groups/get"),
        call("PUT", RULE, "Security Rules - Create Or Update; sent with If-None-Match: * so none of its name is replaced",
             "Security rules", "Add a rule… (a new name only)", f"{NETWORK}/security-rules/create-or-update"),
        call("DELETE", RULE, "Security Rules - Delete", "Security rules", "Remove (a rule)", f"{NETWORK}/security-rules/delete"),
        call("POST", COST, "Query - Usage: costs by scope (a read, by POST)", "Cost Management",
             "the cost this month so far, every six hours", f"{REST}/cost-management/query/usage"),
        call("PUT", VM, "Virtual Machines - Create Or Update: a new VM, or its model changed", "Virtual machines", "",
             f"{COMPUTE}/virtual-machines/create-or-update", costs=True),
        call("PATCH", VM, "Virtual Machines - Update: a VM changed (its size among it)", "Virtual machines", "",
             f"{COMPUTE}/virtual-machines/update", costs=True),
        call("DELETE", VM, "Virtual Machines - Delete", "Virtual machines", "", f"{COMPUTE}/virtual-machines/delete"),
        call("GET", VM + "/vmSizes", "Virtual Machines - List Available Sizes: the sizes a VM can be resized to",
             "Virtual machines", "", f"{COMPUTE}/virtual-machines/list-available-sizes"),
        call("POST", VM + "/redeploy", "Virtual Machines - Redeploy: moved to a new host", "Virtual machines", "",
             f"{COMPUTE}/virtual-machines/redeploy", writes=True),
        call("POST", VM + "/reimage", "Virtual Machines - Reimage: its OS disk made anew", "Virtual machines", "",
             f"{COMPUTE}/virtual-machines/reimage", writes=True),
        call("POST", VM + "/capture", "Virtual Machines - Capture: its disks copied as an image", "Virtual machines", "",
             f"{COMPUTE}/virtual-machines/capture", costs=True),
        call("POST", VM + "/runCommand", "Virtual Machines - Run Command: a script run inside it", "Virtual machines", "",
             f"{COMPUTE}/virtual-machines/run-command", writes=True),
        call("PUT", RG + "/providers/Microsoft.Compute/disks/{diskName}", "Disks - Create Or Update", "Disks", "",
             f"{COMPUTE}/disks/create-or-update", costs=True),
        call("DELETE", RG + "/providers/Microsoft.Compute/disks/{diskName}", "Disks - Delete", "Disks", "", f"{COMPUTE}/disks/delete"),
        call("PUT", RG + "/providers/Microsoft.Compute/snapshots/{snapshotName}", "Snapshots - Create Or Update", "Snapshots", "",
             f"{COMPUTE}/snapshots/create-or-update", costs=True),
        call("POST", SSH_KEY + "/generateKeyPair", "SSH Public Keys - Generate Key Pair: a new key pair, its private key "
             "returned once", "SSH public keys", "", f"{COMPUTE}/ssh-public-keys/generate-key-pair", writes=True),
        call("PUT", RG + "/providers/Microsoft.Network/publicIPAddresses/{publicIpAddressName}",
             "Public IP Addresses - Create Or Update", "Public IP addresses", "",
             f"{NETWORK}/public-ip-addresses/create-or-update", costs=True),
        call("DELETE", RG + "/providers/Microsoft.Network/publicIPAddresses/{publicIpAddressName}", "Public IP Addresses - Delete",
             "Public IP addresses", "", f"{NETWORK}/public-ip-addresses/delete"),
        call("PUT", NSG, "Network Security Groups - Create Or Update", "Network security groups", "",
             f"{NETWORK}/network-security-groups/create-or-update"),
        call("DELETE", NSG, "Network Security Groups - Delete", "Network security groups", "",
             f"{NETWORK}/network-security-groups/delete"),
        call("GET", RG + "/providers/Microsoft.Network/networkSecurityGroups/{networkSecurityGroupName}/securityRules",
             "Security Rules - List", "Security rules", "", f"{NETWORK}/security-rules/list"),
        call("PUT", RG + "/providers/Microsoft.Resources/deployments/{deploymentName}", "Deployments - Create Or Update: "
             "a template deployed", "Deployments", "", f"{REST}/resources/deployments/create-or-update", costs=True),
        call("POST", SUBSCRIPTION + "/providers/{resourceProviderNamespace}/register", "Providers - Register",
             "Providers", "", f"{REST}/resources/providers/register", writes=True),
    ),
    verified=VERIFIED,
)

DNS = Api(
    name=DNS_NAME,
    maker="Microsoft",
    about=("Azure's DNS hosting: public zones answered by Azure's name servers, managed as Resource Manager resources "
           "(Microsoft.Network/dnszones) at the same address with the same token. A record set is every record of one "
           "name and type, read and written whole with its etag, so a change made meanwhile is never written over."),
    kind="rest",
    base="https://management.azure.com (Microsoft.Network/dnszones)",
    version=V_DNS,
    auth=("The Resource Manager token; Azure RBAC decides (the DNS Zone Contributor role, or each record type's write "
          "and delete actions, Microsoft.Network/dnszones/A/write ...)."),
    limits=("Per zone: record sets created, updated or deleted 200 a minute, read 2,000 a minute, listed 60 a minute; "
            "zones listed 60 a minute. At most 250 public zones a subscription, 10,000 record sets a zone and 20 records "
            "a record set (400 TXT records)."),
    costs=("Each hosted zone is billed by the month and its queries by the million (Azure DNS pricing); records cost "
           "nothing more. Making a zone starts a charge: the plugin never makes one."),
    links=(
        Link("Azure DNS REST API", f"{REST}/dns/", "docs"),
        Link("Zones", f"{REST}/dns/zones", "reference"),
        Link("Record Sets", f"{REST}/dns/record-sets", "reference"),
        Link("What is Azure DNS?", f"{L}/azure/dns/dns-overview", "guide"),
        Link("DNS zones and records", f"{L}/azure/dns/dns-zones-records", "guide"),
        Link("Azure DNS FAQ", f"{L}/azure/dns/dns-faq", "guide"),
        Link("Alias records", f"{L}/azure/dns/dns-alias", "guide"),
        Link("DNSSEC", f"{L}/azure/dns/dnssec", "guide"),
        Link("Azure DNS limits", f"{L}/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-dns-limits",
             "limits"),
        Link("Azure DNS pricing", "https://azure.microsoft.com/en-us/pricing/details/dns/", "pricing"),
        Link("Azure status", STATUS, "status"),
        Link("Azure portal", PORTAL, "console"),
        Link("az network dns", f"{L}/cli/azure/network/dns", "tool"),
    ),
    areas=(
        Area("Zones", "the subscription's public DNS zones and their name servers", f"{REST}/dns/zones", "the DNS zones table"),
        Area("Record sets", "every record of a name and type, written whole", f"{REST}/dns/record-sets",
             "each zone's records; records set and removed; Dynamic DNS"),
        Area("DNS resource reference", "the record sets that refer to Azure resources", f"{REST}/dns/dns-resource-reference"),
        Area("Alias record sets", "A, AAAA and CNAME record sets kept at an Azure resource's address", f"{L}/azure/dns/dns-alias",
             "shown, never written (changed in the portal)"),
        Area("DNSSEC", "signed zones", f"{L}/azure/dns/dnssec"),
        Area("Private DNS zones", "zones answered inside virtual networks", f"{L}/azure/dns/dns-private-records"),
        Area("DNS Private Resolver", "resolving between virtual networks and on-premises networks",
             f"{L}/azure/dns/dns-private-resolver-overview"),
    ),
    calls=(
        call("GET", ZONES, "Zones - List: the subscription's zones", "Zones", "the DNS zones table", f"{REST}/dns/zones/list"),
        call("GET", ZONE_ALL, "Record Sets - List All By Dns Zone", "Record sets", "each zone's records table",
             f"{REST}/dns/record-sets/list-all-by-dns-zone"),
        call("GET", RECORD_SET, "Record Sets - Get", "Record sets", "a record set read just before it is changed; Dynamic DNS",
             f"{REST}/dns/record-sets/get"),
        call("PUT", RECORD_SET, "Record Sets - Create Or Update (If-Match its etag; a new one If-None-Match: *)", "Record sets",
             "Set a record…, Remove (one of several), Dynamic DNS", f"{REST}/dns/record-sets/create-or-update"),
        call("DELETE", RECORD_SET, "Record Sets - Delete (If-Match its etag)", "Record sets", "Remove (the last record of a set)",
             f"{REST}/dns/record-sets/delete"),
        call("PATCH", RECORD_SET, "Record Sets - Update", "Record sets", "", f"{REST}/dns/record-sets/update"),
        call("GET", ZONE + "/{recordType}", "Record Sets - List By Type", "Record sets", "", f"{REST}/dns/record-sets/list-by-type"),
        call("PUT", ZONE, "Zones - Create Or Update: a new zone (billed by the month)", "Zones", "",
             f"{REST}/dns/zones/create-or-update", costs=True),
        call("DELETE", ZONE, "Zones - Delete: the zone and every record in it", "Zones", "", f"{REST}/dns/zones/delete"),
        call("GET", ZONE, "Zones - Get", "Zones", "", f"{REST}/dns/zones/get"),
        call("PATCH", ZONE, "Zones - Update (its tags)", "Zones", "", f"{REST}/dns/zones/update"),
    ),
    verified=VERIFIED,
)

PRICES = Api(
    name=PRICES_NAME,
    maker="Microsoft",
    about=("Microsoft's public price list: the retail price of every Azure meter (pay as you go, reservations, savings "
           "plans) by region and SKU, with no sign-in. The plugin asks it for the hourly price of each VM size and region "
           "it sees."),
    kind="rest",
    base="https://prices.azure.com/api/retail/prices",
    version=V_PRICES,
    auth="None: public and unauthenticated.",
    limits=("1,000 prices a page (NextPageLink for the rest); no rate limit is published. The plugin asks once a day for "
            "each VM size and region."),
    costs="",
    links=(
        Link("Azure Retail Prices REST API overview", f"{REST}/cost-management/retail-prices/azure-retail-prices", "docs"),
        Link("Linux VM pricing", "https://azure.microsoft.com/en-us/pricing/details/virtual-machines/linux/", "pricing"),
        Link("Windows VM pricing", "https://azure.microsoft.com/en-us/pricing/details/virtual-machines/windows/", "pricing"),
        Link("Pricing calculator", "https://azure.microsoft.com/en-us/pricing/calculator/", "pricing"),
    ),
    areas=(
        Area("Pay-as-you-go prices", "a meter's price by the hour (type Consumption)", "",
             "a VM size's price an hour: Linux or Windows, regular or spot"),
        Area("Primary meters", "the meters charges are billed by (meterRegion='primary')", "", "the only meters asked"),
        Area("Reservation prices", "one- and three-year reservations (priceType Reservation)"),
        Area("Savings plan prices", "one- and three-year savings plans (this API version alone)"),
        Area("Currencies", "prices in a currency other than USD (currencyCode), for reference"),
    ),
    calls=(
        call("GET", RETAIL, "the prices a filter names ($filter on serviceName, armRegionName, armSkuName, priceType ...)",
             "Pay-as-you-go prices", "each VM's price an hour and a month"),
    ),
    verified=VERIFIED,
)

IDENTITY = Api(
    name=IDENTITY_NAME,
    maker="Microsoft",
    about=("Microsoft Entra ID's OAuth 2.0 and OpenID Connect endpoints, where an app proves who it is and gets a token "
           "for an API. The plugin uses the client credentials grant: a service principal's ID and secret, no user, for "
           "a Resource Manager token."),
    kind="rest",
    base="https://login.microsoftonline.com/{tenant}/oauth2/v2.0",
    version="v2.0",
    auth="The app's client ID and client secret (the client credentials grant), form-encoded.",
    limits=("A token lasts about an hour (expires_in; 3,599 seconds in its example): the plugin asks again only a minute "
            "before it ends, or when Resource Manager refuses it."),
    costs="",
    links=(
        Link("The OAuth 2.0 client credentials flow", f"{L}/entra/identity-platform/v2-oauth2-client-creds-grant-flow", "docs"),
        Link("Microsoft identity platform documentation", f"{L}/entra/identity-platform/", "docs"),
        Link("Error codes (AADSTS)", f"{L}/entra/identity-platform/reference-error-codes", "reference"),
        Link("Register an app and create a service principal", f"{L}/entra/identity-platform/howto-create-service-principal-portal",
             "guide"),
        Link("Register an application", f"{L}/entra/identity-platform/quickstart-register-app", "guide"),
        Link("Scopes and the .default scope", f"{L}/entra/identity-platform/scopes-oidc", "guide"),
        Link("Access tokens", f"{L}/entra/identity-platform/access-tokens", "guide"),
        Link("Microsoft Entra admin center", "https://entra.microsoft.com/", "console"),
        Link("Azure status", STATUS, "status"),
    ),
    areas=(
        Area("Client credentials grant", "an app's own token, with its secret, a certificate or a federated credential",
             f"{L}/entra/identity-platform/v2-oauth2-client-creds-grant-flow", "a Resource Manager token, with the client secret"),
        Area("Authorization code flow", "a signed-in user's token for an app", f"{L}/entra/identity-platform/v2-oauth2-auth-code-flow"),
        Area("Device code flow", "a user signing in on another device", f"{L}/entra/identity-platform/v2-oauth2-device-code"),
        Area("On-behalf-of flow", "an API calling another as its user", f"{L}/entra/identity-platform/v2-oauth2-on-behalf-of-flow"),
        Area("Certificate credentials", "an app proving itself with a certificate instead of a secret",
             f"{L}/entra/identity-platform/certificate-credentials"),
        Area("Workload identity federation", "an app proving itself with another identity provider's token",
             f"{L}/entra/workload-id/workload-identity-federation"),
        Area("OpenID Connect", "signing users in; the discovery document", f"{L}/entra/identity-platform/v2-protocols-oidc"),
        Area("Access tokens", "what a token holds and how long it lasts", f"{L}/entra/identity-platform/access-tokens",
             "its expires_in kept"),
    ),
    calls=(
        call("POST", TOKEN, "a token by the client credentials grant (client_id, scope, client_secret, grant_type)",
             "Client credentials grant", "the Resource Manager token, about once an hour",
             f"{L}/entra/identity-platform/v2-oauth2-client-creds-grant-flow", writes=False),
        call("GET", "/{tenant}/oauth2/v2.0/authorize", "a user's sign-in for an authorization code", "Authorization code flow",
             "", f"{L}/entra/identity-platform/v2-oauth2-auth-code-flow"),
        call("POST", "/{tenant}/oauth2/v2.0/devicecode", "a device code for a user to sign in with elsewhere", "Device code flow",
             "", f"{L}/entra/identity-platform/v2-oauth2-device-code"),
        call("GET", "/{tenant}/adminconsent", "an administrator's consent to an app's permissions", "Client credentials grant",
             "", f"{L}/entra/identity-platform/v2-oauth2-client-creds-grant-flow"),
        call("GET", "/{tenant}/v2.0/.well-known/openid-configuration", "the OpenID Connect discovery document", "OpenID Connect",
             "", f"{L}/entra/identity-platform/v2-protocols-oidc"),
    ),
    verified=VERIFIED,
)

APIS = (ARM, DNS, PRICES, IDENTITY)
