"""FD-4CI-b (register row FD-4CI-b, owner 10-21): platform compute defaults for Agent-mode Cloud Run services.

Settings > FinOps "Enforce Scale-to-Zero by Default" and Settings > Orchestration "Default Container Memory (MB)" /
"Default Container vCPU" are read ONCE per developer dispatch (strict read) and passed to the deterministic assembly
(`AssemblyInputs.compute_defaults`), so the assembly stays a function of (draft, inputs).

`PlatformComputeDefaults()` (and None) is today's behaviour, byte for byte: min_instances 0 when the spec states no
minimum, and the resource-sizing tier profile (512Mi / 1 vCPU for a standard service) unchanged.
"""

from dataclasses import dataclass, replace
import logging
from typing import Any, Optional

logger = logging.getLogger("castor-developer-agent")

TODAY_MEMORY_MB = 512
TODAY_CPU = 1

# Cloud Run services: the memory a vCPU count allows (MiB, inclusive) -- cloud.google.com/run/docs/configuring/
# services/memory-limits and .../cpu. The lower bound 512 MiB is the smallest value valid on both execution
# environments. A combination outside this table is not applied (the sizing profile stays as it is).
CLOUD_RUN_MEMORY_MIB_BY_CPU = {1: (512, 4096), 2: (512, 8192), 4: (2048, 16384), 6: (4096, 24576), 8: (4096, 32768)}

# The memory_limit strings the resource-sizing profiles use (shared/resource_sizing.py), in MiB.
_PROFILE_MEMORY_MIB = {"512Mi": 512, "1Gi": 1024, "2Gi": 2048}


@dataclass(frozen=True)
class PlatformComputeDefaults:
    default_min_instances: int = 0     # 0: Enforce Scale-to-Zero on (default); 1: off
    memory_mb: int = TODAY_MEMORY_MB   # Default Container Memory (MB), treated as MiB
    cpu: int = TODAY_CPU               # Default Container vCPU


def resolve_platform_compute_defaults(project_id: Optional[str] = None, read: Any = None) -> PlatformComputeDefaults:
    """One strict settings read. Unreadable / invalid settings, or an unusable value, give today's value for that
    field (logged by the reader). Never raises."""
    try:
        from shared.settings import get_platform_settings, is_setting_int, strict_setting_value
    except ImportError:  # pragma: no cover - the gateway image always ships shared/
        return PlatformComputeDefaults()
    reader = read if read is not None else get_platform_settings
    try:
        settings = reader(project_id=project_id, strict=True)
    except Exception as err:  # noqa: BLE001 - settings unknown: today's behaviour
        logger.error(f"{getattr(err, 'code', 'PLATFORM_SETTINGS_UNAVAILABLE')}: compute defaults could not be read "
                     f"({type(err).__name__}: {err}); scale to zero and 512 MB / 1 vCPU apply.")
        return PlatformComputeDefaults()

    def same(**_kw):
        return settings

    scale_to_zero = strict_setting_value("finops", "enforce_scale_to_zero_default", True, read=same,
                                         accept=lambda v: isinstance(v, bool))
    memory_mb = strict_setting_value("orchestration", "default_container_memory_mb", TODAY_MEMORY_MB, read=same,
                                     accept=lambda v: is_setting_int(v) and v > 0)
    cpu = strict_setting_value("orchestration", "default_container_cpu", TODAY_CPU, read=same,
                               accept=lambda v: is_setting_int(v) and v > 0)
    return PlatformComputeDefaults(default_min_instances=0 if scale_to_zero else 1, memory_mb=memory_mb, cpu=cpu)


def default_min_instances(defaults: Optional[PlatformComputeDefaults]) -> int:
    return defaults.default_min_instances if defaults is not None else 0


def cloud_run_combination_valid(memory_mib: int, cpu: int) -> bool:
    bounds = CLOUD_RUN_MEMORY_MIB_BY_CPU.get(cpu)
    return bounds is not None and bounds[0] <= memory_mib <= bounds[1]


def apply_platform_container_baseline(profile: Any, defaults: Optional[PlatformComputeDefaults]) -> Any:
    """The sizing profile with the platform baseline applied: each of memory and vCPU becomes the larger of the
    profile's value and the setting (a data / compute tier never shrinks). Returns `profile` itself (unchanged) when
    the settings are today's defaults, when the profile's values are not ones this module knows, or when the result
    is a combination Cloud Run cannot run (logged)."""
    if defaults is None or (defaults.memory_mb, defaults.cpu) == (TODAY_MEMORY_MB, TODAY_CPU):
        return profile
    profile_mib = _PROFILE_MEMORY_MIB.get(getattr(profile, "memory_limit", None))
    try:
        profile_cpu = int(getattr(profile, "gcloud_cpu", ""))
    except (TypeError, ValueError):
        profile_cpu = None
    if profile_mib is None or profile_cpu is None:
        logger.warning(f"Container sizing profile {getattr(profile, 'memory_limit', None)!r} / "
                       f"{getattr(profile, 'gcloud_cpu', None)!r} not recognised; the platform baseline is not applied.")
        return profile
    memory = max(profile_mib, int(defaults.memory_mb))
    cpu = max(profile_cpu, int(defaults.cpu))
    if (memory, cpu) == (profile_mib, profile_cpu):
        return profile
    if not cloud_run_combination_valid(memory, cpu):
        logger.error(f"Default Container Memory {memory} MB with {cpu} vCPU is not a Cloud Run combination "
                     f"(allowed per vCPU: {CLOUD_RUN_MEMORY_MIB_BY_CPU}); the sizing profile "
                     f"{profile.memory_limit} / {profile.gcloud_cpu} vCPU is used instead.")
        return profile
    return replace(profile, memory_limit=f"{memory}Mi", cpu_limit=f"{cpu * 1000}m", gcloud_cpu=str(cpu))
