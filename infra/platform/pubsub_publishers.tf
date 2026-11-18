# ==============================================================================
# FD-4AS-c (register row FD-4AS-c, owner 10-20): topic-level Pub/Sub publishers.
#
# Before: every agent persona SA held PROJECT-level roles/pubsub.publisher (main.tf agent_pubsub_publishers) and
# the main-orchestrator workflow SA held another one (modules/workflows orchestrator_pubsub_publisher), so any of
# them could publish a `google_docs` intake event straight to spec-intake-events and skip the Drive poller's
# authorized-submitter checks (FD-4AS RT F3). Both project-level grants are gone; each publisher now holds
# roles/pubsub.publisher on exactly the topic its code publishes to:
#
#   topic                       publisher (runtime identity)                      code that publishes
#   spec-intake-events          spec-ingestion-service runtime SA                 apps/spec-ingestion/poller.py
#                               Control Center SA (destructive_guard.tf)          apps/control-center/routes/workloads.py
#                               castor-sre-remediation workflow SA (row           workflows/sre_remediation.yaml
#                               FD-4AS-c-a, see below)
#   autonomous-refactor-events  github-refactor-scanner-job runtime SA            apps/refactor-scanner/scanner.py
#   castor-dlq                  castor-main-orchestrator workflow SA              workflows/main_orchestrator.yaml
#                               Pub/Sub service agent (main.tf, dead letters)
#   runtime-incident-events     SRE error log sink writer (main.tf)               Cloud Logging sink
#
# The runtime SAs are looked up from the same maps the services / jobs use (destructive_guard.tf
# service_runtime_sa / job_runtime_sa, default sa-castor-developer), so a later per-service SA (FD-4T) moves the
# grant with the service. Pinned by tests/test_fd4as_c_topic_publishers.py.
#
# Not covered here (FD-4CT inventory, docs/handoff/fd-4ct-inventory.md): identities outside this Terraform that
# can publish through a broad role on the host project (Owner / Editor, e.g. the default compute SA).
# ==============================================================================

locals {
  spec_ingestion_sa_email   = lookup(local.service_runtime_sa, "spec-ingestion-service", local.developer_sa_email)
  refactor_scanner_sa_email = lookup(local.job_runtime_sa, "github-refactor-scanner-job", local.developer_sa_email)
}

resource "google_pubsub_topic_iam_member" "spec_ingestion_spec_intake_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.spec_intake_events.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${local.spec_ingestion_sa_email}"
}

# Row FD-4AS-c-a (owner 10-24): the SRE remediation workflow publishes its remediation request to spec-intake-events
# (workflows/sre_remediation.yaml step publish_intake); without this grant SRE auto-remediation (a required component)
# fails at that step. Topic-level only.
resource "google_pubsub_topic_iam_member" "sre_remediation_spec_intake_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.spec_intake_events.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.agents["sa-castor-sre"].email}"
}

resource "google_pubsub_topic_iam_member" "refactor_scanner_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.autonomous_refactor_events.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${local.refactor_scanner_sa_email}"
}

# The main orchestrator workflow publishes a failed run to the dead-letter topic (step publish_dead_letter).
resource "google_pubsub_topic_iam_member" "orchestrator_dlq_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.castor_dlq.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.agents["sa-castor-architect"].email}"
}
