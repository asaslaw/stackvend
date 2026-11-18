# ==============================================================================
# StackVend: Human Architect & Custom Infrastructure Additions
# ==============================================================================
# This file is reserved for human architects, operators, and custom modules.
# Unlike main.tf, this file is NEVER overwritten by StackVend agents.
#
# Use this file to declare additive GCP resources such as:
# - google_storage_bucket
# - google_pubsub_topic / google_pubsub_subscription
# - google_secret_manager_secret
# - google_sql_database_instance
# - Bespoke IAM roles or custom module invocations
#
# Example:
# resource "google_storage_bucket" "workload_assets" {
#   name                        = "${var.product_id}-assets"
#   location                    = var.region
#   uniform_bucket_level_access = true
# }
# ==============================================================================
