"""SECURITY-LENS-PLATFORM-FACTS (owner 11-13): ONE typed platform-facts object for every QA lens.

Before, the trusted PLATFORM FACTS (QA-STAGE2-PLATFORM-FACTS and the rows that extended it) and the facets the
platform handles (ADHERENCE-PLATFORM-SATISFIED) were wired into the adherence lens only; the security lens got neither,
so a Public app's per-service access limitation still blocked there (live example 02, `ex02-1113`).

Now `run_qa` builds one `PlatformFacts` per Stage 2 run (`build_platform_facts`, from typed records only), the
coordinator refuses to run without it, and passes the SAME object to every lens. Every lens renders it with the same
helper (`PlatformFacts.section`), so the facts each judge reads are byte-identical. The handled/advisory decision stays
typed in each lens (a judge facet in the closed set `platform_satisfied.FACETS` + `PlatformFacts.handled`); a handled
finding is an advisory in the report, never dropped (invariant 8).

`tests/test_ex02_platform_findings.py` fails when a lens of `qa_auditor` does not take `platform_facts`, when the
coordinator calls a lens without the object, or when two lens prompts render it differently.
"""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional, Sequence

from .judge_input import platform_facts_section, platform_facts_text, platform_rendered_paths
from .platform_satisfied import PlatformHandling


@dataclass(frozen=True)
class PlatformFacts:
    """The trusted platform facts of one Stage 2 run.

    `text`: the PLATFORM FACTS lines (judge_input.platform_facts_text); `handled`: the facets the platform handles for
    this workload (platform_satisfied.platform_handlings), the typed input of every lens's advisory decision;
    `platform_rendered_paths` (RT F1): the committed files the platform itself writes (judge_input.
    platform_rendered_paths, exact membership): a "documented platform limitation" finding is an advisory only on one
    of these. Seam for the single ownership predicate (Ownership.PLATFORM_RENDERED) when it lands."""

    text: str
    handled: Mapping[str, PlatformHandling] = field(default_factory=dict)
    platform_rendered_paths: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        # RT F4: one object shared by every lens thread: a read-only copy of the handled facets, a frozen path set
        object.__setattr__(self, "handled", MappingProxyType(dict(self.handled or {})))
        object.__setattr__(self, "platform_rendered_paths", frozenset(self.platform_rendered_paths or ()))

    def section(self) -> str:
        """The PLATFORM FACTS prompt section, the same text for every lens."""
        return platform_facts_section(self.text)


def build_platform_facts(vcs_provider: Optional[str], iac_mode: str, task_dag: Optional[Sequence[Any]], *,
                         python_runtime_pin: Optional[str] = None, direct_iap_cloud_run: bool = False,
                         platform_handled: Optional[Mapping[str, PlatformHandling]] = None,
                         test_layout_services: Any = None, committed_paths: Iterable[Any] = (),
                         app_admin_count: Optional[int] = None) -> PlatformFacts:
    """The one facts object of a Stage 2 run (the arguments are those of judge_input.platform_facts_text, plus the
    committed tree (path to content, so the runtime pin is checked by content) for `platform_rendered_paths`, the one
    ownership predicate of PLATFORM-RENDERED-FINDING; none = an empty set, so no limitation finding is handled)."""
    handled: Dict[str, PlatformHandling] = dict(platform_handled or {})
    text = platform_facts_text(vcs_provider, iac_mode, task_dag, python_runtime_pin=python_runtime_pin,
                               direct_iap_cloud_run=direct_iap_cloud_run, platform_handled=handled,
                               test_layout_services=test_layout_services,
                               app_admin_count=app_admin_count)   # APP-ADMIN-IAP-CONTRACT
    return PlatformFacts(text=text, handled=handled, platform_rendered_paths=platform_rendered_paths(committed_paths))


def section_of(facts: Optional[PlatformFacts]) -> str:
    """A lens's PLATFORM FACTS section: the object's own rendering, or "" for a direct lens call without one."""
    return facts.section() if facts is not None else ""


def handled_of(facts: Optional[PlatformFacts]) -> Dict[str, PlatformHandling]:
    return dict(facts.handled) if facts is not None else {}


def rendered_of(facts: Optional[PlatformFacts]) -> FrozenSet[str]:
    """The committed platform-rendered paths of the run (empty for a direct lens call without facts)."""
    return facts.platform_rendered_paths if facts is not None else frozenset()
