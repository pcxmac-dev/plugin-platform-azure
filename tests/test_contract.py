"""Every plugin here conforms to the class contract (plugin API 2.2): liminal_libs.sources.conformance, read from the
plugin alone (nothing runs); its settings are pairs named by their variables; and its client holds nothing that would start
or raise a charge: every change it can send is one of the free changes, and the calls that create, resize, restore or
destroy a billable thing are named on its API card alone."""
from __future__ import annotations

import ast
import inspect
import re

import pytest

import plugin_platform_azure as module
import plugin_platform_azure.api as api_mod
from liminal_libs.sources.conformance import assert_module_conforms
from plugin_platform_azure.api import WRITES, AzureApi
from plugin_platform_azure.settings import Config


def test_every_plugin_here_conforms_to_the_class_contract():
    found = assert_module_conforms(module)
    assert found and all(p.api == "2.2" and not p.is_record for p in found)
    assert {p.SYSTEM for p in found} == {"platform"} and {p.KIND for p in found} == {"machine"}
    assert {(p.name, p.title, p.order, p.ICON) for p in found} == {("azure", "Microsoft Azure", 764, "azure")}
    assert module.__version__ == "0.1.0"


def test_its_settings_are_pairs_named_by_their_variables():
    p = module.MACHINE
    assert [k.pair for k in p.keys] == ["azure-tenant-id", "azure-client-id", "azure-client-secret", "azure-subscription-id",
                                         "azure-ddns-hosts", "azure-ddns-minutes"]
    assert {k.name for k in p.keys if k.secret} == {"AZURE_CLIENT_SECRET"}
    assert all(k.hint.startswith("optional") for k in p.keys if k.name.startswith("AZURE_DDNS"))
    hooks = p.interface()["hooks"]
    assert {"present", "status", "refresh", "vms", "zones", "records", "nsgs", "ssh_keys", "power", "set_record",
            "remove_record", "add_rule", "remove_rule", "add_ssh_key", "remove_ssh_key", "ddns_update"} <= set(hooks)
    assert not {"setup", "run", "check"} & set(hooks)


def test_its_icon_is_its_makers_mark_drawn_by_the_library():
    from liminal_libs.ui import STATIC

    drawn = set(re.findall(r"^\s*([a-z]+):\s*'", (STATIC / "icons.js").read_text(encoding="utf-8"), re.M))
    assert module.MACHINE.ICON == "azure" and "azure" in drawn


BILLABLE = (  # what would start or raise a charge, or destroy what bills: none of it in the client's source
    "Microsoft.Compute/snapshots", "Microsoft.Compute/images", "Microsoft.Compute/galleries", "virtualMachineScaleSets",
    "/capture", "/redeploy", "/reimage", "/convertToManagedDisks", "/generateKeyPair", "/vmSizes", "Microsoft.Resources/deployments",
    "Microsoft.RecoveryServices", "/register", "publicIPAddresses/{", "disks/{", "dnsZones/{zoneName}?", "networkSecurityGroups/{networkSecurityGroupName}?",
)


def test_nothing_billable_is_in_the_clients_source():
    source = inspect.getsource(api_mod)
    for path in BILLABLE:
        assert path not in source, path
    # every change it can send: the free ones, each by POST (a VM's power), PUT or DELETE of a record set, a rule, a key
    allowed = {("POST", api_mod.VM_START), ("POST", api_mod.VM_RESTART), ("POST", api_mod.VM_DEALLOCATE),
               ("POST", api_mod.VM_POWER_OFF), ("PUT", api_mod.RECORD_SET), ("DELETE", api_mod.RECORD_SET),
               ("PUT", api_mod.RULE), ("DELETE", api_mod.RULE), ("PUT", api_mod.SSH_KEY), ("DELETE", api_mod.SSH_KEY)}
    assert WRITES == allowed
    assert not any(t in (api_mod.VM, api_mod.VMS) for _, t in WRITES)  # no VM made, changed, resized or deleted


def test_every_change_goes_through_the_gate_and_the_gate_refuses_the_rest():
    """The client's methods send a change only through `_write` (a read by POST only through `_read_post`, the token
    only through its own client); `_write` refuses anything not in WRITES, sending nothing."""
    tree = ast.parse(inspect.getsource(api_mod))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for call in ast.walk(node):
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
                    verb = call.func.attr
                    if verb in ("put", "patch", "delete"):
                        pytest.fail(f"{node.name} calls .{verb}( directly")
                    if verb == "post":
                        assert node.name == "_fetch_token", f"{node.name} posts directly"
                    if verb == "request":
                        assert node.name in ("_write", "_read_post"), f"{node.name} sends a request directly"
    sent = []
    api = AzureApi(Config(tenant="t" * 8, client_id="c" * 8, client_secret="s" * 8, subscription="x" * 8),
                   transport=lambda *a: sent.append(a) or (200, {}, b""))
    for method, template in (("PUT", api_mod.VM), ("PATCH", api_mod.VM), ("DELETE", api_mod.VM),
                             ("PUT", api_mod.SUBSCRIPTION + "/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/disks/{diskName}"),
                             ("POST", api_mod.VM + "/capture"), ("DELETE", api_mod.ZONES)):
        with pytest.raises(RuntimeError, match="not one of the plugin's free changes"):
            api._write(method, template, {"resourceGroupName": "rg", "vmName": "vm", "diskName": "d"}, {"api-version": "x"})
    with pytest.raises(RuntimeError, match="not one of the plugin's reads"):
        api._read_post(api_mod.VMS, {}, {})
    assert sent == []
