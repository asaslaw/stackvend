# ==============================================================================
# StackVend: Human Architect Configuration Overrides
# ==============================================================================
# This file uses Terraform's native override mechanism (*_override.tf).
# Any block or attribute defined here merges over top of resources and modules
# declared in main.tf.
#
# Unlike main.tf, this file is NEVER overwritten by StackVend agents.
#
# Example 1: Override Cloud Run container scaling or timeouts in module "compute":
#
# module "compute" {
#   min_instance_count = 2
#   timeout_seconds    = 600
# }
#
# Example 2: Override environment variables on a Cloud Run service:
#
# resource "google_cloud_run_v2_service" "app" {
#   template {
#     containers {
#       env {
#         name  = "FEATURE_FLAG_ENABLED"
#         value = "true"
#       }
#     }
#   }
# }
# ==============================================================================
