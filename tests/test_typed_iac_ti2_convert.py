"""Typed IaC intent TI-2: scripts/convert_custom_tf.py (HCL draft -> iac_intent/v1, typed CONVERT.* reasons) and the
inert / Do-No-Harm guarantees of the stage (no product caller, mode stays off). Pure (python-hcl2 only)."""
import hermetic_guard  # noqa: F401  (first import)

import importlib.util
import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: F401,E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing (gateway requirements / eval/.deps)", pytrace=False)

from shared import iac_intent as ii  # noqa: E402

_spec = importlib.util.spec_from_file_location("ti2_convert_custom_tf", os.path.join(REPO_ROOT, "scripts",
                                                                                     "convert_custom_tf.py"))
CONV = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = CONV
_spec.loader.exec_module(CONV)
ART = ii.load_artifacts()
# TI-3 RT F3: with the lane-11 facts (network / zone) a network-bound module such as database-cloudsql is usable
CTX = ii.IntentContext(services={"api": ("module.compute", "compute-cloudrun")},
                       facts=dict(ii.default_facts(), network="var.network_id", zone="var.zone"))
W = "infra/workload/custom.tf"
TOPIC_T = 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'   # literal "t" targets resolve to it (TI-2b F1/F2)


def conv(text, **kw):
    kw.setdefault("services", {"compute": ("api", "compute-cloudrun")})
    return CONV.convert_tree({W: text}, ART, **kw)


def res(r, addr):
    return next(e for e in r.intent["resources"] if f"{e['type']}.{e['name']}" == addr)


def entry(r, addr):
    return next(e for e in r.entries if e.address == addr)


def F(f):
    return {"$ref": {"kind": "fact", "fact": f}}


def test_literals_templates_and_facts():
    r = conv('''
variable "project_id" { type = string }
resource "google_pubsub_topic" "events" {
  name    = "${var.product_id}-events"
  project = var.project_id
  labels  = { team = "core", "k-2" = "v" }
  message_retention_duration = "86600s"
}''')
    t = res(r, "google_pubsub_topic.events")["arguments"]
    assert t["name"] == {"$fn": "format", "$args": ["%s-events", F("product_id")]}
    assert t["project"] == F("project_id") and t["labels"] == {"team": "core", "k-2": "v"}
    assert ii.validate_intent(r.intent, ART, CTX).ok


def test_escapes_and_percent_in_templates_are_exact():
    r = conv('resource "google_pubsub_topic" "t" {\n  name = "a\\"b %%{x} $${y} 50% ${var.region}"\n}\n')
    v = res(r, "google_pubsub_topic.t")["arguments"]["name"]
    # the format string escapes % as %% ("%{x}" -> "%%{x}"); the renderer then template-escapes "%{"
    assert v == {"$fn": "format", "$args": ['a"b %%{x} ${y} 50%% %s', F("region")]}


def test_template_directive_is_a_typed_reason():
    r = conv('resource "google_pubsub_topic" "t" {\n  name = "%{ if true }x%{ endif }"\n}\n')
    assert entry(r, "google_pubsub_topic.t").reasons == ["CONVERT.TEMPLATE_DIRECTIVE"]


@pytest.mark.parametrize("expr,value", [
    ("10 - 2 - 3", 5),          # left-associative (python-hcl2 parses the chain right-associatively)
    ("2 * 3 + 4", 10),          # precedence (python-hcl2 parses 2 * (3 + 4))
    ("2 + 3 * 4", 14),
    ("1 + 1 == 2 && !false ? 30 : 60", 30),
    ("var.workload_sa_email != \"\" ? 11 : 22", 11),     # a platform fact is a known non-empty string
    ("var.workload_sa_email == null ? 11 : 22", 22),
    ("var.unset != \"\" ? 11 : 22", 22),                 # AI input default decides the branch
    ("length(var.unset) > 0 ? 11 : 22", 22),
])
def test_partial_evaluation_restores_hcl_precedence(expr, value):
    r = conv(TOPIC_T + 'variable "unset" {\n  default = ""\n}\nresource "google_pubsub_subscription" "s" {\n'
             f'  name = "s"\n  topic = "t"\n  ack_deadline_seconds = {expr}\n}}\n')
    assert res(r, "google_pubsub_subscription.s")["arguments"]["ack_deadline_seconds"] == value


def test_undecidable_condition_and_unset_input_are_typed():
    r = conv('resource "google_pubsub_topic" "t" {\n  name = google_pubsub_topic.u.name != "" ? "a" : "b"\n}\n'
             'resource "google_pubsub_topic" "u" {\n  name = "u"\n}\n')
    assert entry(r, "google_pubsub_topic.t").reasons == ["CONVERT.UNSUPPORTED_EXPRESSION"]
    r = conv('variable "bucket" {\n  default = ""\n}\nresource "google_storage_bucket" "b" {\n'
             '  name = var.bucket\n  location = var.region\n}\n')
    assert entry(r, "google_storage_bucket.b").reasons == ["CONVERT.UNSET_VARIABLE"]
    r = conv('variable "env" {}\nresource "google_pubsub_topic" "t" {\n  name = var.env\n}\n')
    assert entry(r, "google_pubsub_topic.t").reasons == ["CONVERT.UNRESOLVED_VARIABLE"]


def test_count_and_for_each_expand_into_one_entry_per_instance():
    r = conv('''
locals {
  roles = toset(["roles/datastore.user", "roles/pubsub.publisher"])
}
resource "google_project_iam_member" "grants" {
  for_each = local.roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${module.foundation.workload_sa_email}"
}
resource "google_pubsub_topic" "t" {
  count = var.workload_sa_email != "" ? 1 : 0
  name  = "t-${count.index}"
}''')
    names = sorted(e["name"] for e in r.intent["resources"])
    assert names == ["grants_roles_datastore_user", "grants_roles_pubsub_publisher", "t_0"]
    g = res(r, "google_project_iam_member.grants_roles_pubsub_publisher")["arguments"]
    assert g["role"] == "roles/pubsub.publisher"
    assert g["member"] == {"$member": {"service_account": F("workload_sa_email")}}
    assert res(r, "google_pubsub_topic.t_0")["arguments"]["name"] == {"$fn": "format", "$args": ["t-%s", 0]}
    assert ii.validate_intent(r.intent, ART, CTX).ok


def test_non_literal_for_each_is_a_typed_reason():
    r = conv('resource "google_pubsub_topic" "t" {\n  for_each = toset([google_pubsub_topic.u.name])\n'
             '  name = each.key\n}\nresource "google_pubsub_topic" "u" {\n  name = "u"\n}\n')
    assert entry(r, "google_pubsub_topic.t").reasons == ["CONVERT.META_FOR_EACH"]


@pytest.mark.parametrize("member,want", [
    ('"serviceAccount:${google_service_account.w.email}"',
     {"$member": {"service_account": {"$ref": {"kind": "resource_attr", "type": "google_service_account",
                                                "name": "w", "attr": "email"}}}}),
    ("google_service_account.w.member",
     {"$member": {"service_account": {"$ref": {"kind": "resource_attr", "type": "google_service_account",
                                                "name": "w", "attr": "email"}}}}),
    ('"serviceAccount:service-${data.google_project.p.number}@gcp-sa-pubsub.iam.gserviceaccount.com"',
     {"$member": {"service_agent": "pubsub_service_agent"}}),
    ('"serviceAccount:${data.google_storage_project_service_account.g.email_address}"',
     {"$member": {"service_agent": "gcs_service_agent"}}),
])
def test_iam_members_convert_only_from_exact_shapes(member, want):
    r = conv(f'''
data "google_project" "p" {{}}
data "google_storage_project_service_account" "g" {{}}
resource "google_service_account" "w" {{
  account_id = "worker-sa"
}}
resource "google_pubsub_topic" "t" {{
  name = "t"
}}
resource "google_pubsub_topic_iam_member" "m" {{
  topic  = google_pubsub_topic.t.name
  role   = "roles/pubsub.publisher"
  member = {member}
}}''')
    assert res(r, "google_pubsub_topic_iam_member.m")["arguments"]["member"] == want
    assert ii.validate_intent(r.intent, ART, CTX).ok


@pytest.mark.parametrize("member", ['"allUsers"', '"serviceAccount:someone@x.iam.gserviceaccount.com"',
                                    '"user:${var.project_id}"'])
def test_untyped_members_do_not_convert(member):
    r = conv(TOPIC_T + f'resource "google_pubsub_topic_iam_member" "m" {{\n  topic = "t"\n  role = "roles/pubsub.viewer"\n'
             f'  member = {member}\n}}\n')
    assert entry(r, "google_pubsub_topic_iam_member.m").reasons == ["CONVERT.MEMBER_NOT_TYPED"]


def test_not_expressible_owners_are_excluded_and_their_exact_attributes_become_facts():
    r = conv('''
resource "google_project_service" "apis" {
  service = "run.googleapis.com"
}
resource "google_firestore_database" "db" {
  name        = "(default)"
  location_id = "nam5"
  type        = "FIRESTORE_NATIVE"
}
resource "google_cloud_run_v2_service" "svc" {
  name     = "x"
  location = var.region
  template {}
}
resource "google_service_account_iam_member" "wi" {
  service_account_id = "x"
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[ns/ksa]"
}
resource "google_pubsub_topic" "t" {
  name   = "t"
  labels = { db = google_firestore_database.db.name }
  depends_on = [google_project_service.apis]
}
resource "google_pubsub_subscription" "s" {
  name  = "s"
  topic = google_pubsub_topic.t.id
  push_config {
    push_endpoint = "${google_cloud_run_v2_service.svc.uri}/push"
  }
}''')
    status = {e.address: (e.status, e.category) for e in r.entries}
    assert status["google_project_service.apis"] == ("excluded", "platform_owned")
    assert status["google_firestore_database.db"] == ("excluded", "platform_owned")
    assert status["google_cloud_run_v2_service.svc"] == ("excluded", "topology_owned")
    assert status["google_service_account_iam_member.wi"] == ("excluded", "platform_owned")
    t = res(r, "google_pubsub_topic.t")
    assert t["arguments"]["labels"] == {"db": F("database_name")} and "depends_on" not in t
    ep = res(r, "google_pubsub_subscription.s")["arguments"]["push_config"]["push_endpoint"]
    assert ep == {"$fn": "format", "$args": ["%s/push", {"$ref": {"kind": "service", "service": "api",
                                                                    "output": "service_uri"}}]}
    assert r.expressibility == 1.0 and ii.validate_intent(r.intent, ART, CTX).ok


def test_references_to_unconvertible_entries_cascade():
    r = conv('''
resource "google_monitoring_notification_channel" "c" {
  type = "email"
}
resource "google_pubsub_topic" "t" {
  name = google_monitoring_notification_channel.c.name
}
resource "google_pubsub_subscription" "s" {
  name  = "s"
  topic = google_pubsub_topic.t.id
}''')
    assert entry(r, "google_monitoring_notification_channel.c").reasons == ["CONVERT.TYPE_NOT_ALLOWED"]
    assert entry(r, "google_pubsub_topic.t").reasons == ["CONVERT.UNCONVERTED_REFERENCE"]
    assert entry(r, "google_pubsub_subscription.s").reasons == ["CONVERT.DEPENDS_ON_UNCONVERTED"]
    assert r.intent["resources"] == [] and r.expressibility == 0.0


def test_cloud_sql_instance_maps_to_the_required_module():
    r = conv('''
resource "google_sql_database_instance" "pg" {
  name             = "pg"
  database_version = "POSTGRES_15"
  region           = var.region
  deletion_protection = false
  settings {
    tier = "db-g1-small"
  }
}
resource "google_sql_database" "d" {
  name     = "orders"
  instance = google_sql_database_instance.pg.name
}''')
    assert r.intent["modules"] == [{"module": "database-cloudsql", "name": "pg", "args": {
        "database_version": "POSTGRES_15", "deletion_protection": False, "tier": "db-g1-small"}}]
    assert res(r, "google_sql_database.d")["arguments"]["instance"] == {
        "$ref": {"kind": "module_output", "module": "pg", "output": "instance_name"}}
    assert entry(r, "google_sql_database_instance.pg").reasons == ["CONVERT.MAPPED_TO_MODULE"]
    assert ii.validate_intent(r.intent, ART, CTX).ok


def test_dynamic_block_with_a_decidable_collection_is_expanded():
    r = conv(TOPIC_T + '''
variable "sa" {
  default = ""
}
resource "google_pubsub_subscription" "s" {
  name  = "s"
  topic = "t"
  push_config {
    push_endpoint = "https://x"
    dynamic "oidc_token" {
      for_each = var.sa != "" ? [var.sa] : []
      content {
        service_account_email = oidc_token.value
      }
    }
  }
}''')
    assert "oidc_token" not in res(r, "google_pubsub_subscription.s")["arguments"]["push_config"]


def test_platform_outputs_and_ai_variables_are_not_entries():
    r = conv('variable "x" {\n  default = "a"\n}\nresource "google_pubsub_topic" "t" {\n  name = var.x\n}\n'
             'output "topic_id" {\n  value = google_pubsub_topic.t.id\n}\noutput "service_url" {\n'
             '  value = google_pubsub_topic.t.id\n}\noutput "lit" {\n  value = "x"\n}\n',
             platform_output_names=["service_url"])
    assert [o["name"] for o in r.intent["outputs"]] == ["topic_id"]
    assert res(r, "google_pubsub_topic.t")["arguments"]["name"] == "a"


def test_parse_error_is_a_typed_file_entry():
    r = conv('resource "google_pubsub_topic" "t" {\n  name = \n')
    assert [e.reasons for e in r.entries] == [["CONVERT.HCL_PARSE_ERROR"]]


# ------------------------------------------------------------------------------------------------ inert / DNH
def test_ti2_is_inert_no_product_code_imports_the_intent_module_or_the_converter():
    # TI-3 wired the intent into the developer stage behind iac_intent_mode (default "off"); the converter stays
    # owner-run tooling that no product code imports, and the intent is read only by the files TI-3 lists.
    out = subprocess.run(["git", "-C", REPO_ROOT, "grep", "-l", "-E", r"convert_custom_tf",
                          "--", "apps/*.py", "mcp-servers/*.py", "shared/*.py", "agents/*.py", "workflows",
                          "infra/*.tf"],
                         capture_output=True, text=True)
    assert sorted(set(out.stdout.split())) == [], out.stdout
    # TI-3h: the terraform server's byte-identical copy of shared/settings.py carries the platform setting
    # governance.iac_intent_generate (a bool the gateway reads); it does not read or import the intent.
    out = subprocess.run(["git", "-C", REPO_ROOT, "grep", "-l", "-E", r"iac_intent",
                          "--", "mcp-servers/*.py", "agents/*.py", "workflows", "infra/*.tf",
                          ":(exclude)mcp-servers/terraform/shared/settings.py"],
                         capture_output=True, text=True)
    # TI-5a (plan §4 TI-5): the terraform server's apply side recognises an intent workspace by the intent's JSON
    # (json.loads + exact path, no import of shared.iac_intent and no provider-schema slice): exactly these files
    assert sorted(set(out.stdout.split())) == ["mcp-servers/terraform/service.py",
                                               "mcp-servers/terraform/test_service.py"], (
        "the intent is gateway-only (plan §2.5) except the TI-5 apply side: " + out.stdout)
    service = open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py"), encoding="utf-8").read()
    assert "import iac_intent" not in service and "from shared.iac_intent" not in service
    tf_settings = open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "shared", "settings.py"),
                       encoding="utf-8").read()
    assert tf_settings.count("iac_intent") == tf_settings.count("iac_intent_generate") > 0   # only the TI-3h setting


def test_hallucination_stack_intent_mode_defaults_off():
    from shared import hallucination_stack as hs
    assert hs.HallucinationStackSettings().iac_intent_mode == "off"   # TI-3: flipped only on the paid gate
