## 🎯 Summary of Changes
A clear and concise description of what this PR accomplishes, including motivation, bug fixes, or new features.

## 🔗 Related Issues
Closes # (issue number, if applicable)

---

## 🛡️ Pre-Merge Quality & Safety Checklist

Please verify that your Pull Request adheres to the StackVend architectural invariants:

### 1. Verification & Tests
- [ ] Automated unit tests have been added or updated in `tests/`.
- [ ] All three suites pass locally with 0 failed (commands and environment variables in `AGENTS.md` "Setup & verification"):
  ```bash
  export TEST_MODE=true PROJECT_ID=mock-stackvend-project GCP_PROJECT=mock-stackvend-project GOOGLE_CLOUD_PROJECT=mock-stackvend-project DEFAULT_REGION=us-central1
  pytest tests/ -rf --tb=no
  pytest mcp-servers/terraform/test_service.py
  pytest mcp-servers/kubernetes/test_service.py
  ```
- [ ] Updated `CHANGELOG.md` (the newest, unreleased section) with a concise summary of user-visible changes.

### 2. Monorepo Replica Synchronization (Gate 5)
- [ ] If modifying `shared/builtin_prompts.py`, all replicas in `apps/control-center/shared/` and `apps/orchestrator-gateway/shared/` are synchronized in lockstep.
- [ ] If modifying `shared/providers/serverless_git_provider.py`, all 7 replicas across `apps/*` and `mcp-servers/*` are synchronized.
- [ ] If modifying `shared/settings.py`, all microservice replicas are synchronized.

### 3. Slim Container & Buildpack Invariants (Gate 4)
- [ ] No native CLI dependencies (`gcloud`, `kubectl`, `terraform`) are invoked inside Cloud Run microservices or `tf-applier`.
- [ ] No C-extension libraries added to `requirements.txt` that fail on Google Cloud Buildpacks (pure-Python packages preferred).

### 4. Privacy & Hygiene Scan
- [ ] Zero hardcoded tenant GCP project IDs, personal emails, or private infrastructure hashes.
- [ ] All secrets and tokens are resolved dynamically via Google Secret Manager or IAM.

### 5. Architectural Review
- [ ] For non-trivial features, an architectural review was conducted using the **`/stackvend-red-team-review`** skill.
