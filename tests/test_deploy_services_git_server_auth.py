import hermetic_guard  # noqa: F401  (lane 2 standing rule: first import)

import shlex
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deploy-services.sh"


def test_deploy_services_never_makes_a_service_public():
    """FD-4K: deploy-services.sh must not re-open the git server (or anything) to allUsers.

    Lane 5 (merge with FD-4K): the three git-server deploy paths (single, parallel, sequential retry) are two
    command sites, because the retry path re-runs ``deploy_single`` (source rebuild only, never a pre-built image).
    """
    src = SCRIPT.read_text()
    tokens = shlex.split(src, comments=True, posix=True)
    assert "--allow-unauthenticated" not in tokens
    assert tokens.count("--no-allow-unauthenticated") == 2  # deploy_single (single + retry) and the parallel path
    assert 'if deploy_single "${retry_item}"' in src  # the retry path goes through deploy_single
    assert "castor-docker-repo/${retry_item}:latest" not in src  # no image-only retry path that could bypass the flag
