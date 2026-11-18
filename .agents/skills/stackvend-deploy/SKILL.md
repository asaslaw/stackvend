---
name: stackvend-deploy
description: >-
  Safe platform deployment, verification, and blast-radius governance for StackVend.
  Defines the decision tree between core host Terraform (apply.sh apply) and Cloud Run microservices (deploy-services.sh).
---

# StackVend Platform Deployment Runbook

You are the Release Engineer managing deployments of the StackVend control plane.

---

## 1. The Deployment Decision Matrix

| Change Type | Affected Files | Deployment Command |
| :--- | :--- | :--- |
| **Core Platform Infrastructure** | `infra/` root Terraform, host IAM bindings, Shared VPC, PSA database peering | `bash apply.sh apply` *(in platform host project)* |
| **Microservice / Tool Server** | `apps/*`, `mcp-servers/*` | `bash scripts/deploy-services.sh <service-name>` |
| **Documentation / Skills** | `docs/`, `.agents/skills/` | Pure `git commit && git push` *(Zero deployment needed)* |

---

## 2. Microservice Deployment & Image Synchronization

### A. Deploying `mcp-terraform-server`
When you deploy `mcp-terraform-server`:
```bash
bash scripts/deploy-services.sh mcp-terraform-server
```
`scripts/deploy-services.sh` automatically:
1. Compiles the container image via Cloud Buildpacks from `mcp-servers/terraform`.
2. Deploys the Cloud Run Service `mcp-terraform-server`.
3. **Synchronizes the compiled image to the `tf-applier` Cloud Run Job** with:
   `--command="/cnb/lifecycle/launcher" --args="python3,-m,applier"`.

### B. Deploying `orchestrator-gateway-service`
```bash
bash scripts/deploy-services.sh orchestrator-gateway-service
```

### B2. The `stage-runner` job (STAGE-JOB-RUNNER)
The architect, developer and QA stages run as executions of the `stage-runner` Cloud Run Job, which runs the gateway's
image. Every gateway deploy syncs the job's image. Two operator commands:
* `PROJECT_ID=<id> bash scripts/deploy-services.sh stage-runner`: builds nothing; points the job at the image the
  gateway SERVES (after a traffic rollback, after an apply). Without it, a stage refuses `STAGE_RUNNER_IMAGE_SKEW`.
* Rollback to the synchronous stages, no deploy and no apply: `PROJECT_ID=<id> bash scripts/stage-jobs-switch.sh off`
  (`on` / `status` too).

### C. Deploying All Services in Parallel
```bash
bash scripts/deploy-services.sh
```

---

## 3. Real-Time Forensic Log Streaming

When a deployment fails or a container boot loops, run these one-liners:

### Stream Live Cloud Buildpack Compilation
```bash
# Stream the most recent Cloud Buildpack compile log
gcloud builds log $(gcloud builds list --limit=1 --format="value(id)") --stream
```

### Tail Live Cloud Run Container Boot Errors
```bash
# Tail latest fatal container logs for a specific service
gcloud logging read 'resource.type="cloud_run_revision" AND severity>=ERROR' \
  --limit=25 \
  --project=$(gcloud config get-value project) \
  --format="table(timestamp, resource.labels.service_name, textPayload)"
```

---

## 4. Pre-Deployment Test Suite (Hard Gate)

Never deploy without running the automated test suites:
```bash
pytest tests/test_hcl_utils.py
pytest mcp-servers/terraform/test_service.py
```
Both suites must exit code 0 before initiating Cloud Run builds.
