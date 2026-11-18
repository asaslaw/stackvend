# HOST-INTERNAL-INGRESS / HOST-VPC-EGRESS: plan-level contract for infra/platform/host_network.tf and the main.tf
# ingress / vpc_access wiring, run by tests/test_internal_ingress_tf.py on a COPY of the repository tree. Every provider
# is MOCKED (no backend, no credentials, no network; providers come only from a local filesystem mirror).

mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      email  = "svcacct@mock-stackvend-project.iam.gserviceaccount.com"
      member = "serviceAccount:svcacct@mock-stackvend-project.iam.gserviceaccount.com"
      name   = "projects/mock-stackvend-project/serviceAccounts/svcacct@mock-stackvend-project.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_project_service_identity" {
    defaults = {
      email  = "agent@gcp-sa-x.iam.gserviceaccount.com"
      member = "serviceAccount:agent@gcp-sa-x.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_logging_project_sink" {
    defaults = {
      writer_identity = "serviceAccount:service-123456789012@gcp-sa-logging.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_project_iam_custom_role" {
    defaults = {
      id = "projects/mock-stackvend-project/roles/mockRole"
    }
  }
  mock_data "google_project" {
    defaults = {
      number = "123456789012"
    }
  }
}
mock_provider "google-beta" {
  mock_resource "google_service_account" {
    defaults = {
      email  = "svcacct@mock-stackvend-project.iam.gserviceaccount.com"
      member = "serviceAccount:svcacct@mock-stackvend-project.iam.gserviceaccount.com"
      name   = "projects/mock-stackvend-project/serviceAccounts/svcacct@mock-stackvend-project.iam.gserviceaccount.com"
    }
  }
}
mock_provider "google" {
  alias = "host_quota"
}
mock_provider "random" {}

variables {
  project_id                         = "mock-stackvend-project"
  allow_unauthenticated              = false
  authorized_invoker_members         = ["user:admin@example.com"]
  vcs_provider                       = "SERVERLESS_GIT"
  deploy_git_server                  = true
  organization_id                    = "organizations/123456789012"
  castor_managed_workloads_folder_id = "folders/4242"
  create_stackvend_managed_tag       = true
}

run "design_b_defaults_egress_on_ingress_all" {
  command = plan
  assert {
    condition     = length(google_compute_network.host) == 1 && length(google_compute_subnetwork.host_run_egress) == 1
    error_message = "the network and subnet are planned by default"
  }
  assert {
    condition = (length(google_compute_global_address.psc_google_apis) == 1 && length(google_compute_global_forwarding_rule.psc_google_apis) == 1
    && length(google_dns_managed_zone.host_run_app) == 1 && length(google_dns_record_set.host_run_app_wildcard) == 1)
    error_message = "Design B: PSC endpoint and run.app zone"
  }
  assert {
    condition     = length(google_compute_router.host) == 0 && length(google_compute_router_nat.host) == 0
    error_message = "Design B: no Cloud NAT"
  }
  assert {
    condition     = google_cloud_run_v2_service.services["mcp-terraform-server"].ingress == "INGRESS_TRAFFIC_ALL" && google_cloud_run_v2_service.git_server[0].ingress == "INGRESS_TRAFFIC_ALL"
    error_message = "ingress stays ALL by default"
  }
  assert {
    condition     = google_cloud_run_v2_service.services["mcp-terraform-server"].template[0].vpc_access[0].egress == "PRIVATE_RANGES_ONLY"
    error_message = "Design B egress mode"
  }
  assert {
    condition = (length(google_cloud_run_v2_job.jobs["sandbox-garbage-collector-job"].template[0].template[0].vpc_access) == 1
      && length(google_cloud_run_v2_job.tf_applier.template[0].template[0].vpc_access) == 1
    && length(google_cloud_run_v2_service.git_server[0].template[0].vpc_access) == 1)
    error_message = "jobs, tf-applier and the git server are on the network"
  }
  assert {
    condition     = length(google_cloud_run_v2_job.qa_sandbox.template[0].template[0].vpc_access) == 0
    error_message = "the QA job is never on the host network"
  }
  assert {
    condition     = google_compute_subnetwork.host_run_egress[0].ip_cidr_range == var.host_egress_subnet_cidr && google_compute_global_address.psc_google_apis[0].address == var.host_psc_endpoint_ip
    error_message = "ranges come from the variables"
  }
  assert {
    condition     = google_dns_managed_zone.host_run_app[0].dns_name == "run.app." && google_dns_record_set.host_run_app_wildcard[0].name == "*.run.app."
    error_message = "run.app zone and wildcard"
  }
  assert {
    condition     = length(google_compute_subnetwork_iam_member.host_run_egress_cloudbuild_trigger_user) == 0 && length(google_compute_subnetwork_iam_member.platform_upgrader_subnet_user) == 0
    error_message = "no deployer grants by default"
  }
}

run "ingress_internal" {
  command = plan
  variables {
    host_internal_ingress = true
  }
  assert {
    condition     = google_cloud_run_v2_service.services["mcp-terraform-server"].ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" && google_cloud_run_v2_service.git_server[0].ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY"
    error_message = "internal-only"
  }
  assert {
    condition     = google_cloud_run_v2_service.services["product-control-center-ui"].ingress == "INGRESS_TRAFFIC_ALL"
    error_message = "the Control Center keeps its own ingress"
  }
}

run "design_a_nat_all_traffic" {
  command = plan
  variables {
    host_egress_mode      = "NAT_ALL_TRAFFIC"
    host_internal_ingress = true
  }
  assert {
    condition     = length(google_compute_router.host) == 1 && length(google_compute_router_nat.host) == 1
    error_message = "Design A: Cloud Router + NAT"
  }
  assert {
    condition     = google_compute_router_nat.host[0].enable_dynamic_port_allocation == true && google_compute_router_nat.host[0].nat_ip_allocate_option == "AUTO_ONLY" && google_compute_router_nat.host[0].min_ports_per_vm == 1024
    error_message = "NAT shape"
  }
  assert {
    condition = (length(google_compute_global_address.psc_google_apis) == 0 && length(google_compute_global_forwarding_rule.psc_google_apis) == 0
    && length(google_dns_managed_zone.host_run_app) == 0 && length(google_dns_record_set.host_run_app_wildcard) == 0)
    error_message = "Design A: no PSC endpoint, no run.app zone"
  }
  assert {
    condition = (google_cloud_run_v2_service.services["orchestrator-gateway-service"].template[0].vpc_access[0].egress == "ALL_TRAFFIC"
    && google_cloud_run_v2_job.tf_applier.template[0].template[0].vpc_access[0].egress == "ALL_TRAFFIC")
    error_message = "Design A egress mode"
  }
  assert {
    condition     = google_compute_subnetwork.host_run_egress[0].private_ip_google_access == true
    error_message = "Design A reaches run.app and Google APIs over Private Google Access"
  }
}

run "design_a_ignores_the_psc_address" {
  command = plan
  variables {
    host_egress_mode     = "NAT_ALL_TRAFFIC"
    host_psc_endpoint_ip = "10.254.1.7"
  }
}

run "egress_off" {
  command = plan
  variables {
    host_vpc_egress = false
  }
  assert {
    condition     = length(google_compute_network.host) == 0 && length(google_cloud_run_v2_service.services["mcp-terraform-server"].template[0].vpc_access) == 0
    error_message = "no network, no vpc_access"
  }
}

run "ingress_without_egress_refused" {
  command = plan
  variables {
    host_vpc_egress       = false
    host_internal_ingress = true
  }
  expect_failures = [google_cloud_run_v2_service.services]
}

run "psc_inside_subnet_refused" {
  command = plan
  variables {
    host_psc_endpoint_ip = "10.254.1.7"
  }
  expect_failures = [google_compute_subnetwork.host_run_egress]
}

run "unknown_mode_refused" {
  command = plan
  variables {
    host_egress_mode = "ALL_TRAFFIC"
  }
  expect_failures = [var.host_egress_mode]
}

run "public_subnet_refused" {
  command = plan
  variables {
    host_egress_subnet_cidr = "100.64.0.0/24"
  }
  expect_failures = [var.host_egress_subnet_cidr]
}

run "noncanonical_subnet_refused" {
  command = plan
  variables {
    host_egress_subnet_cidr = "10.254.1.5/24"
  }
  expect_failures = [var.host_egress_subnet_cidr]
}

run "small_subnet_refused" {
  command = plan
  variables {
    host_egress_subnet_cidr = "10.254.1.0/28"
  }
  expect_failures = [var.host_egress_subnet_cidr]
}

run "public_psc_refused" {
  command = plan
  variables {
    host_psc_endpoint_ip = "8.8.8.8"
  }
  expect_failures = [var.host_psc_endpoint_ip]
}

run "psc_with_prefix_refused" {
  command = plan
  variables {
    host_psc_endpoint_ip = "10.254.2.10/32"
  }
  expect_failures = [var.host_psc_endpoint_ip]
}

run "other_rfc1918_ok" {
  command = plan
  variables {
    host_egress_subnet_cidr = "192.168.10.0/24"
    host_psc_endpoint_ip    = "172.16.0.5"
  }
}
