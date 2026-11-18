"""The top-level installer scripts are executable in git (mode 100755).

Live finding 11-10: scripts/pre-bootstrap.sh was committed as 100644, so `./scripts/pre-bootstrap.sh` failed with
"permission denied" on a fresh clone (fixed in ffd97d3a). Users run these scripts as `./scripts/<name>.sh` as well as
`bash scripts/<name>.sh`, so every top-level scripts/*.sh, and every one the user docs name, must be 100755.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import re
import subprocess
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = ["README.md", "CHANGELOG.md", "documentation", "apps/control-center/guide"]
RUN_RE = re.compile(r"(?:\./|bash )scripts/([A-Za-z0-9_.-]+\.sh)\b")


def _git(*args):
    return subprocess.run(["git", "-C", REPO] + list(args), capture_output=True, text=True, check=True).stdout


def _modes():
    """{scripts/<name>.sh: mode} for the top-level scripts tracked in git."""
    out = {}
    for line in _git("ls-files", "-s", "--", "scripts").splitlines():
        meta, path = line.split("\t", 1)
        if re.fullmatch(r"scripts/[^/]+\.sh", path):
            out[path] = meta.split()[0]
    return out


def _doc_named_scripts():
    names = set()
    for path in _git("ls-files", "--", *DOCS).splitlines():
        if not path.endswith(".md"):
            continue
        with open(os.path.join(REPO, path), encoding="utf-8") as f:
            names.update(RUN_RE.findall(f.read()))
    return names


class TestScriptsExecutableBit(unittest.TestCase):
    def test_docs_name_the_installer_scripts(self):
        names = _doc_named_scripts()
        for required in ("pre-bootstrap.sh", "bootstrap.sh", "apply.sh"):
            self.assertIn(required, names)

    def test_doc_named_scripts_are_100755(self):
        modes = _modes()
        for name in sorted(_doc_named_scripts()):
            with self.subTest(script=name):
                self.assertIn(f"scripts/{name}", modes, "docs name a script that is not tracked at scripts/")
                self.assertEqual(modes[f"scripts/{name}"], "100755",
                                 f"scripts/{name} is not executable in git: git update-index --chmod=+x scripts/{name}")

    def test_every_top_level_script_is_100755(self):
        modes = _modes()
        self.assertIn("scripts/pre-bootstrap.sh", modes)
        bad = {p: m for p, m in modes.items() if m != "100755"}
        self.assertEqual(bad, {}, "run: git update-index --chmod=+x <path>")


if __name__ == "__main__":
    unittest.main()
