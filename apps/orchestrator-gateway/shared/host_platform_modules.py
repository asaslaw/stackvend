"""Golden modules that belong to the StackVend host platform, not to workloads: the one source of truth.

`infra/modules/` holds both the workload golden modules and one module only the host platform uses
(`infra/platform/main.tf` calls it; that use is unchanged). Every stage that offers golden modules to a workload
reads this file:

- the red-team critic's golden-module catalog (architect_agent/red_team_critic.py, FD-4AM-c / FD-4AM-d) offers every
  built-in module payload key except HOST_PLATFORM_ONLY_MODULES;
- the TI-2 typed-IaC module catalog (scripts/build_iac_catalog.py -> shared/iac_intent/module_catalog.json) lists them
  under `platform_only` with the reasons below, never as AI-instantiable;
- the developer stage (developer_agent/terraform_engine.get_canonical_module_files, FD-4CB-b) never vendors
  NOT_VENDORED_TO_WORKLOADS into a workload repository, so a workload `module` block whose source is such a module
  fails the content policy (V2j POLICY.MODULE_SOURCE_NOT_LOCAL: not a directory of this run's vendored files).

`workflows` deploys StackVend's own orchestrator / SRE workflows: its main.tf reads
`${path.module}/../../../workflows/*.yaml`, which exists only in the StackVend repository, so it cannot work in a
workload repository (FD-4CB). `workflows-dag` is a separate workload module and stays offered everywhere.

The gateway image is built from its committed shared/ copy: apps/orchestrator-gateway/shared/host_platform_modules.py
must stay byte-identical (tests/test_fd4cb_b_host_platform_modules.py).
"""
from typing import FrozenSet, Mapping

# {module id: why it is host-platform-only}. The reasons are the typed-IaC catalog's `platform_only` values.
HOST_PLATFORM_ONLY_MODULE_REASONS: Mapping[str, str] = {
    "workflows": "orchestrator / SRE identities",
}

HOST_PLATFORM_ONLY_MODULES: FrozenSet[str] = frozenset(HOST_PLATFORM_ONLY_MODULE_REASONS)

# Host-only modules the developer stage never vendors into a workload repository (FD-4CB-b, owner 10-24): every
# host-only module.
NOT_VENDORED_TO_WORKLOADS: FrozenSet[str] = frozenset({"workflows"})

assert NOT_VENDORED_TO_WORKLOADS <= HOST_PLATFORM_ONLY_MODULES
