"""FD-4Y HB-02: `terraform_engine.extract_hcl_blocks` is built on python-hcl2 (assembly.index_blocks) instead of a line
regex plus raw `{`/`}` counting.

Contract (unchanged for valid HCL): top-level resource/module/output/data/locals blocks, in file order, as dicts
{block_type, type_label, name_label, raw_text}; raw_text is the block's exact whole lines.
New: braces inside strings/heredocs and `resource ...` lines inside heredocs no longer cut or invent blocks; a text
python-hcl2 cannot parse yields [] (never a partial guess); a missing python-hcl2 raises HclUnavailable.

Do No Harm evidence: on real generated custom.tf samples (tests/fixtures/hb02, copied from the 10-18 Gate A / Gate B
result trees), every golden module .tf and every golden render, the result is identical to the legacy extractor
(kept below only as a frozen test oracle)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import glob
import os
import re
import sys
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:  # acceptance evidence: fail loudly, never skip
    import hcl2  # noqa: F401,E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt (python-hcl2==7.3.1)",
                pytrace=False)

from developer_agent import assembly  # noqa: E402
from developer_agent.terraform_engine import (  # noqa: E402
    extract_hcl_blocks,
    generate_golden_main_tf,
    generate_golden_moved_tf,
    generate_golden_outputs_tf,
    generate_golden_variables_tf,
    generate_human_override_tf_template,
    generate_human_tf_template,
)

FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures", "hb02")
ARCHETYPES = ("cloudrun", "gce-bastion", "gke-autopilot", "event-worker")


def _legacy_extract_hcl_blocks(hcl_text: str) -> List[Dict[str, Any]]:
    """FROZEN ORACLE: main `9e5d595`'s extract_hcl_blocks, verbatim. Test-only; never imported by product code."""
    blocks = []
    if not hcl_text:
        return blocks
    lines = hcl_text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m_res = re.match(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"', line)
        m_mod = re.match(r'^\s*module\s+"([^"]+)"', line)
        m_out = re.match(r'^\s*output\s+"([^"]+)"', line)
        m_data = re.match(r'^\s*data\s+"([^"]+)"\s+"([^"]+)"', line)
        m_loc = re.match(r'^\s*locals\s*\{', line)
        block_type = None
        type_label = ""
        name_label = ""
        if m_res:
            block_type, type_label, name_label = "resource", m_res.group(1), m_res.group(2)
        elif m_mod:
            block_type, name_label = "module", m_mod.group(1)
        elif m_out:
            block_type, name_label = "output", m_out.group(1)
        elif m_data:
            block_type, type_label, name_label = "data", m_data.group(1), m_data.group(2)
        elif m_loc:
            block_type, type_label, name_label = "locals", "locals", ""
        if block_type and "{" in line:
            depth = 0
            block_lines = []
            while i < len(lines):
                cur_line = lines[i]
                depth += cur_line.count("{") - cur_line.count("}")
                block_lines.append(cur_line)
                i += 1
                if depth <= 0:
                    break
            blocks.append({"block_type": block_type, "type_label": type_label, "name_label": name_label,
                           "raw_text": "\n".join(block_lines)})
            continue
        i += 1
    return blocks


def _real_samples():
    out = {}
    for p in sorted(glob.glob(os.path.join(FIXTURES, "*.tf.txt"))):
        with open(p, encoding="utf-8") as fh:
            out[os.path.basename(p)] = fh.read()
    return out


def _golden_samples():
    out = {}
    for p in sorted(glob.glob(os.path.join(REPO_ROOT, "infra", "modules", "**", "*.tf"), recursive=True)):
        with open(p, encoding="utf-8") as fh:
            out[os.path.relpath(p, REPO_ROOT)] = fh.read()
    for a in ARCHETYPES:
        out[f"render:main:{a}"] = generate_golden_main_tf("shop", a, "")
        out[f"render:outputs:{a}"] = generate_golden_outputs_tf("shop", a)
        out[f"render:moved:{a}"] = generate_golden_moved_tf("shop", a)
    out["render:variables"] = generate_golden_variables_tf("shop", "owner/shop")
    out["render:human"] = generate_human_tf_template()
    out["render:human_override"] = generate_human_override_tf_template()
    return out


def test_fixtures_are_present_and_parse():
    real = _real_samples()
    assert len(real) == 3
    for name, text in real.items():
        assert assembly.index_blocks(text), name


@pytest.mark.parametrize("name", sorted(_real_samples()) + sorted(_golden_samples()))
def test_do_no_harm_identical_to_legacy_on_valid_hcl(name):
    text = {**_real_samples(), **_golden_samples()}[name]
    assert extract_hcl_blocks(text) == _legacy_extract_hcl_blocks(text)


def test_real_samples_and_their_concatenation_cover_every_kind():
    real = _real_samples()
    joined = "\n\n".join(real.values())  # bespoke_root_text joins root files with a blank line
    got = extract_hcl_blocks(joined)
    assert got == _legacy_extract_hcl_blocks(joined)
    assert {b["block_type"] for b in got} == {"resource", "module", "output", "data", "locals"}
    for b in got:
        assert b["raw_text"] in joined  # the gatekeeper's custom.tf cure relies on str.replace(raw_text, ...)


def test_kinds_are_unchanged_variable_provider_terraform_moved_not_returned():
    text = ('terraform {\n  required_version = ">= 1.5"\n}\nprovider "google" {\n  project = var.project_id\n}\n'
            'variable "x" {\n  type = string\n}\nmoved {\n  from = a.b\n  to   = a.c\n}\n'
            'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n')
    assert extract_hcl_blocks(text) == [{"block_type": "resource", "type_label": "google_pubsub_topic",
                                         "name_label": "t", "raw_text": 'resource "google_pubsub_topic" "t" {\n'
                                                                       '  name = "t"\n}'}]


def test_brace_in_string_no_longer_cuts_the_block():
    text = ('resource "google_storage_bucket" "b" {\n  name = "x"\n  labels = {\n    note = "}"\n  }\n}\n'
            'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n')
    legacy = _legacy_extract_hcl_blocks(text)
    assert legacy[0]["raw_text"] == "\n".join(text.split("\n")[0:5])  # the oracle cut the bucket short
    got = extract_hcl_blocks(text)
    assert [(b["type_label"], b["name_label"]) for b in got] == [("google_storage_bucket", "b"),
                                                                 ("google_pubsub_topic", "t")]
    assert got[0]["raw_text"] == "\n".join(text.split("\n")[0:6])


def test_heredoc_braces_no_longer_swallow_the_next_block():
    text = ('resource "google_cloudfunctions_function" "f" {\n  name = "f"\n  description = <<EOT\n'
            'resource "fake" "y" {\n{{{\nEOT\n}\n'
            'output "o" {\n  value = 1\n}\n')
    legacy = _legacy_extract_hcl_blocks(text)
    assert len(legacy) == 1 and legacy[0]["raw_text"] == text  # the oracle swallowed output "o"
    got = extract_hcl_blocks(text)
    assert [(b["block_type"], b["type_label"], b["name_label"]) for b in got] == [
        ("resource", "google_cloudfunctions_function", "f"), ("output", "", "o")]
    assert got[0]["raw_text"] == "\n".join(text.split("\n")[0:7])


def test_heredoc_resource_line_does_not_invent_a_block():
    text = ('variable "tpl" {\n  type    = string\n  default = <<EOT\nresource "fake" "y" {\n}\nEOT\n}\n'
            'output "o" {\n  value = var.tpl\n}\n')
    legacy = _legacy_extract_hcl_blocks(text)
    assert [(b["type_label"], b["name_label"]) for b in legacy] == [("fake", "y"), ("", "o")]  # invented "fake"
    got = extract_hcl_blocks(text)
    assert [(b["block_type"], b["type_label"], b["name_label"]) for b in got] == [("output", "", "o")]


def test_unparseable_text_yields_nothing_never_a_partial_list():
    text = 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\nresource "google_storage_bucket" "b" {\n  name = \n'
    assert _legacy_extract_hcl_blocks(text)  # the oracle guessed a partial list
    assert extract_hcl_blocks(text) == []


def test_terraform_invalid_label_count_blanks_the_whole_file():
    """python-hcl2 accepts a label count Terraform rejects; index_blocks has no exact range for it, so nothing is
    guessed from the file (never a partial list). V1b (`tofu validate`) reports the block; the repair loop fixes it."""
    good = 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'
    for bad in ('resource "google_storage_bucket" {\n  name = "x"\n}\n', 'resource "a" "b" "c" {\n  x = 1\n}\n',
                'module {\n  source = "x"\n}\n', 'module "m" "n" {\n  source = "x"\n}\n', 'output {\n  value = 1\n}\n'):
        assert _legacy_extract_hcl_blocks(good + bad)[0]["name_label"] == "t"  # the oracle kept the valid block
        assert extract_hcl_blocks(good + bad) == []
    # FD-4Y RT F6: the skip count covers every kind, so an invalid label count on a kind this extractor does not
    # return (variable / provider / terraform) also blanks the text (stricter than HB-02 alone, never partial)
    for bad in ('variable {\n  type = string\n}\n', 'provider {\n  project = "p"\n}\n', 'terraform "x" {\n  a = 1\n}\n',
                'locals "x" {\n  a = 1\n}\n', 'data "google_project" {\n  project_id = "p"\n}\n'):
        assert extract_hcl_blocks(good + bad) == []
    assert [b["name_label"] for b in extract_hcl_blocks(good)] == ["t"]  # Do No Harm: the valid file alone is unchanged
    assert [b["name_label"] for b in extract_hcl_blocks(good + 'variable "v" {}\nmoved {\n  from = a.b\n  to = a.c\n}\n'
                                                         'check "h" {\n  assert {\n    condition = true\n'
                                                         '    error_message = "x"\n  }\n}\n')] == ["t"]


def test_empty_and_whitespace():
    assert extract_hcl_blocks("") == []
    assert extract_hcl_blocks(None) == []  # type: ignore[arg-type]  (callers pass `files.get(...)`)
    assert extract_hcl_blocks("\n  \n") == []


def test_missing_python_hcl2_is_a_typed_error():
    with patch.object(assembly, "_loads_with_meta", side_effect=assembly.HclUnavailable("python-hcl2 is not installed")):
        with pytest.raises(assembly.HclUnavailable):
            extract_hcl_blocks('resource "a" "b" {}\n')


# The HD-03 `resolve_service_archetype` caller of extract_hcl_blocks is DELETED (FD-55 W8, register FD55-W8): a CI
# workflow's kind comes from the typed compute intent (tests/test_fd55_w8_legacy_path.py).
