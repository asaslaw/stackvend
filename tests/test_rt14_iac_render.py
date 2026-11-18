"""RT14 group iac-render-golden, render half (full-scope red-team scan 11-14,
docs/planning/rt14-iac-render-golden-plan.md).

* RT14-08: the Firestore index renderer wrote collection ids and field paths from app code unescaped into the
  platform-owned infra/workload/indexes.tf (HCL injection). Every quoted value the terraform engine renders now goes
  through `hcl_quoted` (shared.iac_intent.hcl_string_literal), ids outside Firestore's grammar are refused with a typed
  error, and an AST guard keeps new raw `"{value}"` interpolations out of the engine.
* RT14-12: a Cloud Run service the repository's custom.tf declares (a person's) was spliced out by the multi-service
  reconcile; it is now kept byte-identical and reported, and only this run's AI draft is replaced.
Every behaviour change has a Do No Harm negative (valid input -> unchanged). Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt; this file must not skip",
                pytrace=False)

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF, repository_custom_tf_keys  # noqa: E402
from developer_agent.firestore_scanner import FirestoreFieldSpec, FirestoreIndexRequirement  # noqa: E402
from shared.diagnostics import AssemblyRecord  # noqa: E402

ENGINE = os.path.join(GATEWAY, "developer_agent", "terraform_engine.py")
HANDLER = os.path.join(GATEWAY, "developer_agent", "handler.py")
W = "infra/workload/"


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()

# ================================================================================================ RT14-08
def _req(coll="orders", fields=(("user_id", "ORDER", "ASCENDING"), ("created_at", "ORDER", "DESCENDING")),
         scope="COLLECTION"):
    return FirestoreIndexRequirement(collection_id=coll, query_scope=scope,
                                     fields=[FirestoreFieldSpec(field_path=p, mode=m, order=o) for p, m, o in fields])


# The renderer's output for valid ids, pinned before RT14-08 (the pre-change renderer wrote '"' + value + '"').
VALID_PIN = '''# ==============================================================================
# STACKVEND: GOOGLE CLOUD FIRESTORE COMPOSITE INDEXES
# Deterministically extracted via Python AST query scanner.
# Guarantees runtime compound queries execute without FailedPrecondition (400) errors.
# ==============================================================================

resource "google_firestore_index" "idx_orders_user_id_created_at" {
  project     = var.project_id
  database    = "(default)"
  collection  = "orders"
  query_scope = "COLLECTION"

  fields {
    field_path = "user_id"
    order      = "ASCENDING"
  }

  fields {
    field_path = "created_at"
    order      = "DESCENDING"
  }

  depends_on = [module.foundation]
}

resource "google_firestore_index" "idx_articles_tags_author_name" {
  project     = var.project_id
  database    = "(default)"
  collection  = "articles"
  query_scope = "COLLECTION_GROUP"

  fields {
    field_path   = "tags"
    array_config = "CONTAINS"
  }

  fields {
    field_path = "author.name"
    order      = "ASCENDING"
  }

  depends_on = [module.foundation]
}
'''


def test_rt14_08_valid_ids_render_byte_identically():
    """Do No Harm: valid collection ids and field paths (nested path included) render exactly as before."""
    reqs = [_req(), _req("articles", (("tags", "ARRAY", "CONTAINS"), ("author.name", "ORDER", "ASCENDING")),
                         "COLLECTION_GROUP")]
    assert te.generate_golden_indexes_tf(reqs) == VALID_PIN
    assert te.generate_golden_indexes_tf([]) is None


@pytest.mark.parametrize("value", ["orders", "user_id", "a.b", "Ünïcode-名前", "with space", "x" * 200])
def test_rt14_08_hcl_quoted_is_byte_identical_for_plain_values(value):
    assert te.hcl_quoted(value) == '"' + value + '"'


@pytest.mark.parametrize("value,expected", [
    ('a"b', r'"a\"b"'), ("a\\b", r'"a\\b"'), ("a\nb", r'"a\nb"'), ("${var.x}", '"$${var.x}"'), ("%{if}", '"%%{if}"'),
])
def test_rt14_08_hcl_quoted_escapes_everything_that_could_leave_the_string(value, expected):
    assert te.hcl_quoted(value) == expected
    parsed = hcl2.loads(f"x = {expected}\n")["x"]
    # python-hcl2 keeps an escaped template sequence as written; every other value round-trips exactly
    assert parsed == value or value.startswith(("${", "%{"))


INJECTION = 'orders"\n  database = "(default)"\n}\nresource "google_storage_bucket_iam_member" "x" {\n  bucket = "b'


@pytest.mark.parametrize("req", [
    _req(INJECTION),                                               # the report's payload: closes the string
    _req("orders", (("a\nb", "ORDER", "ASCENDING"), ("c", "ORDER", "ASCENDING"))),   # control char in a field path
    _req("a/b"), _req("."), _req(".."), _req("__reserved__"), _req(""),   # Firestore collection-id grammar
    _req("x" * 1501),                                              # > 1,500 bytes
    _req("orders", ((("", "ORDER", "ASCENDING")),)),               # empty field path
    _req(scope="COLLECTION\"\n"),                                  # not one of the two scopes
], ids=["injection", "field-newline", "slash", "dot", "dotdot", "reserved", "empty", "too-long", "empty-field",
        "scope"])
def test_rt14_08_ids_outside_the_grammar_are_refused_typed(req):
    with pytest.raises(te.FirestoreIndexIdInvalid) as e:
        te.generate_golden_indexes_tf([req])
    assert e.value.error_class == "FIRESTORE_INDEX_ID_INVALID" and e.value.stage
    with pytest.raises(te.FirestoreIndexIdInvalid):
        te.generate_firestore_indexes_json([req])


def test_rt14_08_boundary_values_are_accepted():
    """Do No Harm: exactly 1,500 bytes, `__name__` as a field and `__x` as a collection are valid Firestore ids."""
    out = te.generate_golden_indexes_tf([_req("x" * 1500), _req("__x", (("__name__", "ORDER", "ASCENDING"),
                                                                          ("b", "ORDER", "ASCENDING")))])
    assert out and '"__name__"' in out


def test_rt14_08_a_quote_in_a_valid_id_cannot_add_a_block():
    """A collection id with a quote, backslash and `${` is valid Firestore grammar: it renders as one escaped string,
    so the file still declares exactly one resource whose collection is exactly that id."""
    coll = 'or"ders\\${x}'
    out = te.generate_golden_indexes_tf([_req(coll)])
    doc = hcl2.loads(out)
    assert [list(r) for r in doc["resource"]] == [["google_firestore_index"]]
    body = next(iter(doc["resource"][0]["google_firestore_index"].values()))
    assert body["collection"] == 'or"ders\\$${x}'   # python-hcl2 shows the escaped template; tofu reads ${x} literally
    assert set(doc) == {"resource"}


def test_rt14_08_the_developer_stage_raises_the_typed_stage_error():
    """handler step 7 turns the renderer's refusal into DeveloperStageError(FIRESTORE_INDEX_ID_INVALID)."""
    from developer_agent.errors import ERROR_CLASSES, FIRESTORE_INDEX_ID_INVALID
    assert FIRESTORE_INDEX_ID_INVALID in ERROR_CLASSES
    tree = ast.parse(_read(HANDLER))
    handlers = [h for h in ast.walk(tree) if isinstance(h, ast.ExceptHandler)
                and isinstance(h.type, ast.Name) and h.type.id == "FirestoreIndexIdInvalid"]
    assert len(handlers) == 1
    raised = [n for n in ast.walk(handlers[0]) if isinstance(n, ast.Raise)]
    assert len(raised) == 1 and isinstance(raised[0].exc, ast.Call)
    assert raised[0].exc.func.id == "DeveloperStageError" and raised[0].exc.args[0].id == "FIRESTORE_INDEX_ID_INVALID"


# Values the engine may still write between quotes without hcl_quoted: block labels the engine sanitizes itself and
# module constants. Anything else must go through hcl_quoted (exact (function, expression) pairs).
RAW_QUOTED_ALLOWED = {
    ("render_cmek_module_block", "CMEK_MODULE_LABEL"), ("render_cmek_module_block", "CMEK_KEY_NAME"),
    ("render_cmek_module_block", "CMEK_ROTATION_PERIOD"),
    ("reconcile_multi_service_declarations", "s_label"),     # label: compute_<clean service name>
    ("generate_golden_indexes_tf", "resource_name"),         # label: [a-z0-9_] slug
    ("generate_golden_indexes_tf", "ord_val"),               # "ASCENDING" / "DESCENDING"
}


def _raw_quoted_interpolations(source):
    """(function, expression) of every f-string value that sits inside an open double-quoted HCL string of its
    f-string (structural: the f-string's own constant parts, quote parity with backslash escapes)."""
    tree = ast.parse(source)
    owner = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                owner[id(n)] = fn.name
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        inside = False
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                i, t = 0, v.value
                while i < len(t):
                    if t[i] == "\\":
                        i += 2
                        continue
                    if t[i] == '"':
                        inside = not inside
                    i += 1
            elif isinstance(v, ast.FormattedValue) and inside:
                found.add((owner.get(id(node), "<module>"), ast.unparse(v.value)))
    return found


def test_rt14_08_guard_no_raw_value_between_hcl_quotes_in_the_engine():
    raw = _raw_quoted_interpolations(_read(ENGINE))
    assert raw <= RAW_QUOTED_ALLOWED, f"render these through hcl_quoted: {sorted(raw - RAW_QUOTED_ALLOWED)}"


def test_rt14_08_guard_detects_a_new_instance():
    """The guard is not vacuous: the pre-RT14-08 renderer line is found."""
    src = 'def generate_golden_indexes_tf(coll):\n    return f"""  collection  = "{coll}"\n"""\n'
    assert _raw_quoted_interpolations(src) == {("generate_golden_indexes_tf", "coll")}


# RT14-F4: json.dumps writes a JSON string, which does not escape `${` / `%{` (an HCL template). The engine calls it
# only where it writes a JSON file, never HCL (exact function names).
JSON_DUMPS_ALLOWED = {"vendor_composite_bundle", "generate_firestore_indexes_json"}


def _json_dumps_owners(source):
    tree = ast.parse(source)
    found = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "dumps" \
                        and isinstance(n.func.value, ast.Name) and n.func.value.id == "json":
                    found.add(fn.name)
    return found


def test_rt14_f4_guard_no_json_dumps_in_an_hcl_render():
    owners = _json_dumps_owners(_read(ENGINE))
    assert owners <= JSON_DUMPS_ALLOWED, f"render HCL strings through hcl_quoted: {sorted(owners - JSON_DUMPS_ALLOWED)}"
    assert _json_dumps_owners("import json\ndef render_x(v):\n    return json.dumps(v)\n") == {"render_x"}


@pytest.mark.parametrize("values", [[], ["user:a@example.com"], ["user:a@example.com", "group:ops@example.com"],
                                    ["DATA_READ", "ADMIN_READ"], ["run.googleapis.com", "storage.googleapis.com"]])
def test_rt14_f4_hcl_quoted_list_is_byte_identical_to_json_for_plain_values(values):
    import json
    assert te.hcl_quoted_list(values) == json.dumps(values)


def test_rt14_f4_template_sequences_in_a_list_value_are_escaped():
    assert te.hcl_quoted_list(["user:${var.x}@example.com"]) == '["user:$${var.x}@example.com"]'
    with pytest.raises(TypeError):
        te.hcl_quoted_list([1])


def test_rt14_f4_invoker_members_cannot_add_a_template():
    member = 'user:${upper("x")}@example.com'
    text = te.generate_golden_variables_tf("shop", "acme/shop", allow_unauthenticated=False, enable_direct_iap=True,
                                           authorized_invoker_members=[member], region="us-central1")
    assert 'default     = ["user:$${upper(\\"x\\")}@example.com"]' in text
    body = next(v["authorized_invoker_members"] for v in hcl2.loads(text)["variable"]
                if "authorized_invoker_members" in v)
    assert len(body["default"]) == 1


# ================================================================================================ RT14-12
PERSON_RUN = ('resource "google_cloud_run_v2_service" "reports" {\n  name                = "reports"\n'
              '  location            = var.region\n  deletion_protection = false\n  template {\n    containers {\n'
              '      image = "us-docker.pkg.dev/cloudrun/container/hello"\n    }\n  }\n}\n')
AI_RUN = ('resource "google_cloud_run_v2_service" "api" {\n  name     = "api"\n  location = var.region\n'
          '  template {\n    containers {\n      image = var.container_image\n    }\n  }\n}\n')
BUCKET = 'resource "google_storage_bucket" "data" {\n  name     = "data"\n  location = var.region\n}\n'
MAIN = 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n  service_name = var.product_id\n}\n'


def _reconcile(custom, repository, *, targets=None, apps=()):
    files = {W + "main.tf": MAIN, CUSTOM_TF: custom}
    for a in apps:
        files[f"apps/{a}/main.py"] = "x = 1\n"
    rec = AssemblyRecord()
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text="", archetype="cloudrun",
                                            assembly_record=rec, llm_iac_paths=[CUSTOM_TF], target_services=targets,
                                            repository_keys=repository_custom_tf_keys({CUSTOM_TF: repository}))
    return files, rec


def test_rt14_12_a_repository_cloud_run_service_is_kept_byte_identical():
    """The report's negative: a repo custom.tf with a person's Cloud Run service comes out byte-identical."""
    custom = BUCKET + "\n" + PERSON_RUN
    files, rec = _reconcile(custom, custom)
    assert files[CUSTOM_TF] == custom
    assert rec.kept_repository == {"google_cloud_run_v2_service.reports": CUSTOM_TF} and not rec.replaced


def test_rt14_12_multi_service_keeps_it_and_never_synthesizes_a_module_for_it():
    custom = PERSON_RUN
    files, rec = _reconcile(custom, custom, targets=["api", "worker"], apps=("api", "worker"))
    assert files[CUSTOM_TF].startswith(PERSON_RUN)
    assert 'module "compute_reports"' not in files[CUSTOM_TF] and 'module "compute_worker"' in files[CUSTOM_TF]
    assert "google_cloud_run_v2_service.reports" not in rec.replaced


def test_rt14_12_this_runs_draft_is_still_replaced():
    """Do No Harm: an AI Cloud Run service (not in the repository's custom.tf) is replaced and recorded as before."""
    files, rec = _reconcile(BUCKET + "\n" + AI_RUN, "")
    assert "google_cloud_run_v2_service" not in files[CUSTOM_TF] and BUCKET in files[CUSTOM_TF]
    assert rec.replaced_reason == {"google_cloud_run_v2_service.api": "CLOUD_RUN_REPLACED_BY_MODULE"}
    assert rec.kept_repository == {}


def test_rt14_12_mixed_file_removes_only_the_drafted_service():
    repo = PERSON_RUN
    files, rec = _reconcile(PERSON_RUN + "\n" + AI_RUN, repo)
    assert PERSON_RUN in files[CUSTOM_TF] and '"api"' not in files[CUSTOM_TF]
    assert set(rec.replaced) == {"google_cloud_run_v2_service.api"}
    assert set(rec.kept_repository) == {"google_cloud_run_v2_service.reports"}


def test_rt14_12_no_repository_keys_is_todays_behaviour():
    """Direct callers that pass no repository keys get the pre-RT14-12 result (every Cloud Run block replaced)."""
    files = {W + "main.tf": MAIN, CUSTOM_TF: PERSON_RUN}
    rec = AssemblyRecord()
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text="", archetype="cloudrun",
                                            assembly_record=rec, llm_iac_paths=[CUSTOM_TF])
    assert "google_cloud_run_v2_service" not in files[CUSTOM_TF] and not rec.kept_repository


def _vt3(custom, rec):
    from developer_agent.validators.base import ValidationContext
    from developer_agent.validators.topology import LlmComputeValidator
    from shared.artifact_ownership import Ownership
    from shared.service_topology import validate_service_topology
    vt, diags = validate_service_topology({"services": [{"name": "shop", "kind": "cloudrun"}],
                                           "primary_service": "shop", "edges": [], "resources": []}, product_id="shop")
    assert vt is not None, diags
    ctx = ValidationContext.build({CUSTOM_TF: custom}, ownership=lambda p: Ownership.LLM_AUTHORED, assembly=rec,
                                  extras={"platform_addresses": ()})
    return sorted(d.block_address for d in LlmComputeValidator(vt).validate(ctx))


def test_rt14_f3_vt3_does_not_ask_to_delete_a_kept_repository_service():
    """Review F3: when this run's AI rewrites custom.tf and reproduces the person's service, the reconcile keeps it
    (RT14-12); V-T3 must not then ask the repair persona to delete it. Exact (path, key) pairs of kept_repository."""
    _, rec = _reconcile(PERSON_RUN + "\n" + AI_RUN, PERSON_RUN)
    assert _vt3(PERSON_RUN, rec) == []
    # Do No Harm: the AI's own Cloud Run service is still flagged, and so is the kept key in another file
    assert _vt3(PERSON_RUN + "\n" + AI_RUN, rec) == ["google_cloud_run_v2_service.api"]
    assert _vt3(PERSON_RUN, AssemblyRecord()) == ["google_cloud_run_v2_service.reports"]
    other = AssemblyRecord(kept_repository={"google_cloud_run_v2_service.reports": W + "other.tf"})
    assert _vt3(PERSON_RUN, other) == ["google_cloud_run_v2_service.reports"]


def test_rt14_12_repository_keys_helper():
    assert repository_custom_tf_keys({CUSTOM_TF: BUCKET + PERSON_RUN}) == frozenset(
        {"google_storage_bucket.data", "google_cloud_run_v2_service.reports"})
    assert repository_custom_tf_keys({}) == frozenset() and repository_custom_tf_keys(None) == frozenset()
    assert repository_custom_tf_keys({CUSTOM_TF: "resource {{{ not hcl"}) == frozenset()


def test_rt14_12_the_handler_passes_the_repository_keys():
    tree = ast.parse(_read(HANDLER))
    calls = [c for c in ast.walk(tree) if isinstance(c, ast.Call) and getattr(c.func, "id", "") ==
             "reconcile_multi_service_declarations"]
    assert len(calls) == 1
    kw = {k.arg: k.value for k in calls[0].keywords}
    assert ast.unparse(kw["repository_keys"]) == "repository_custom_tf_keys(existing_files)"


def test_rt14_12_readme_no_longer_says_custom_tf_is_preserved_verbatim():
    text = te.generate_infra_readme("shop")
    row = next(line for line in text.splitlines() if line.startswith("| **`custom.tf`**"))
    assert "PRESERVED VERBATIM" not in row and "Cloud Run services included, are kept" in row
