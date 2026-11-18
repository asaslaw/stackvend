"""
Unit tests for shared/hcl_utils.py (x5 byte-identical replicas): the read-only OpenTofu/Terraform `fmt` parser
helpers and replica parity.
The CIDR / WIF rewriters (and their tests, which asserted the mutation of valid HCL) were deleted by
Wave 1 lane 8; their negative and tombstone tests live in tests/test_lane8_deletions.py.
The semantic dedup (and its two cases) was deleted by FD-55 W1 (no production caller); tests/test_fd55_w1_dead_code.py.
FD-55 W6b (register FD55-W6b+W6d) deleted the delimiter checker / "balancer" (validate_hcl_syntax_tree,
self_correct_hcl_syntax) and the parser-gated orphaned depends_on repair (heal_orphaned_resource_syntax,
heal_orphaned_root_resource_syntax, auto_wire_network_graph_dependencies) with their last caller; their absence and the
"committed bytes reach the workspace" negatives live in tests/test_fd55_w6bd_no_writeback.py. FD-55 W6b + W6c deleted
the locals pair (extract_declared_locals / sanitize_hcl_locals_invariants, HA-17) with its last callers (tombstone in the
same file). The parser fixtures below stay as fixtures of the read-only hcl_parse_errors.
"""

import os
import sys
import unittest


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


class TestHCLUtils(unittest.TestCase):
    def test_hcl_utils_monorepo_parity(self):
        import hashlib
        replicas = [
            os.path.join(REPO_ROOT, "shared", "hcl_utils.py"),
            os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "developer_agent", "hcl_utils.py"),
            os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "shared", "hcl_utils.py"),
            os.path.join(REPO_ROOT, "apps", "control-center", "shared", "hcl_utils.py"),  # FD-4DC RT F1 pre-flight
            os.path.join(REPO_ROOT, "mcp-servers", "terraform", "hcl_utils.py"),
            os.path.join(REPO_ROOT, "mcp-servers", "terraform", "shared", "hcl_utils.py"),
        ]
        hashes = {}
        for p in replicas:
            self.assertTrue(os.path.exists(p), f"Missing replica: {p}")
            with open(p, "rb") as f:
                hashes[p] = hashlib.md5(f.read()).hexdigest()
        unique_hashes = set(hashes.values())
        self.assertEqual(len(unique_hashes), 1, f"Monorepo replica drift detected: {hashes}")


TESTPLAN02_A_ORPHANED = """
resource "google_compute_network" "vpc_network" {
  name = "testplan02-a-vpc"
}
resource "google_vpc_access_connector" "serverless_connector" {
  project       = "testplan02-a-project"
  name          = "vpc-connector"
  region        = "us-central1"
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.vpc_network.name
  min_instances = 2
  max_instances = 3
,
    google_compute_network.vpc_network
}
"""

# M3: VALID HCL with nested blocks whose heredoc body matched the deleted healer's regex (",\n  b\n}").
M3_VALID_NESTED = """resource "google_compute_network" "vpc_network" {
  name = "app-vpc"
}

resource "google_cloud_run_v2_service" "svc" {
  name     = "app"
  location = var.region
  template {
    scaling {
      min_instance_count = 1
    }
    containers {
      image = var.container_image
      env {
        name  = "BOOTSTRAP_JS"
        value = <<-EOT
          const settings = {
            region,
            network
          }
        EOT
      }
    }
  }
}
"""


class TestHclParser(unittest.TestCase):
    """The read-only parser helper: OpenTofu/Terraform `fmt -` on stdin (offline). Real-binary cases skip where no
    binary is installed."""

    def setUp(self):
        import shared.hcl_utils as hu
        self.hu = hu
        self.parser_bin = hu.find_hcl_parser_binary()

    def test_hcl_parse_errors_unavailable_binary_is_none(self):
        self.assertIsNone(self.hu.hcl_parse_errors("x = 1\n", "a.tf", parser_bin="/nonexistent/stackvend-tofu"))

    def test_real_parser_classifies_fixtures(self):
        if not self.parser_bin:
            self.skipTest("no tofu/terraform binary installed")
        self.assertEqual(self.hu.hcl_parse_errors(M3_VALID_NESTED, "custom.tf"), [])
        errs = self.hu.hcl_parse_errors(TESTPLAN02_A_ORPHANED, "custom.tf")
        self.assertTrue(errs and "Argument or block definition required" in errs[0], errs)


_FAKE_PARSER_SCRIPT = """#!/bin/sh
# Fake `tofu fmt -`: consumes stdin, counts calls, records $HOME, then behaves per call number.
cat > /dev/null
d=$(dirname "$0")
n=$(cat "$d/count" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$d/count"
echo "$HOME" > "$d/home_$n"
if [ "$n" = 1 ]; then
{first}
fi
exit 0
"""


@unittest.skipIf(os.name == "nt", "fake parser is a POSIX shell script")
class TestHclParseGateExitContract(unittest.TestCase):
    """Lane 8 RT-2 F1 (Invariant 1): only fmt exit 2 means "parser rejects"; any other failure is "not proven"."""

    def setUp(self):
        import tempfile
        import shared.hcl_utils as hu
        self.hu = hu
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _fake_parser(self, first_call: str) -> str:
        path = os.path.join(self.dir, "tofu")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_FAKE_PARSER_SCRIPT.format(first=first_call))
        os.chmod(path, 0o755)
        return path

    def _calls(self) -> int:
        try:
            with open(os.path.join(self.dir, "count"), encoding="utf-8") as fh:
                return int(fh.read().strip())
        except FileNotFoundError:
            return 0


    def test_hcl_parse_errors_exit_code_contract(self):
        cases = (
            ("  exit 0", []),
            ("  kill -9 $$", None),
            ("  exit 1", None),
            ("  exit 3", None),
        )
        for first, expected in cases:
            with self.subTest(first.strip()):
                for name in os.listdir(self.dir):
                    os.remove(os.path.join(self.dir, name))
                fake = self._fake_parser(first)
                self.assertEqual(self.hu.hcl_parse_errors("x = 1\n", "a.tf", parser_bin=fake), expected)
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        fake = self._fake_parser("  echo 'Error: Argument or block definition required' >&2; exit 2")
        errs = self.hu.hcl_parse_errors("x = 1\n", "a.tf", parser_bin=fake)
        self.assertEqual(errs, ["HCL parse error in a.tf: Error: Argument or block definition required"])

    def test_timeout_is_inert(self):
        import subprocess
        from unittest import mock
        fake = self._fake_parser("  exit 2")
        with mock.patch.object(self.hu.subprocess, "run", side_effect=subprocess.TimeoutExpired("tofu", 15)):
            self.assertIsNone(self.hu.hcl_parse_errors("x = 1\n", "a.tf", parser_bin=fake))

    def test_fmt_runs_with_a_throwaway_home_and_utf8_input(self):
        fake = self._fake_parser("  :")
        self.assertEqual(self.hu.hcl_parse_errors('x = "café → \U0001F600"\n', "a.tf", parser_bin=fake), [])
        with open(os.path.join(self.dir, "home_1"), encoding="utf-8") as fh:
            home = fh.read().strip()
        self.assertNotEqual(home, os.environ.get("HOME", ""))
        self.assertIn("stackvend-hcl-fmt-", home)
        self.assertFalse(os.path.exists(home), "the temp HOME is removed after the call")


if __name__ == "__main__":
    unittest.main()
