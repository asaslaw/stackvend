---
name: "🐛 Bug Report"
about: Create a report to help us improve StackVend
title: "[BUG]: "
labels: ["bug", "triage"]
assignees: []
---

## 🐛 Bug Description
A clear and concise description of what the bug is.

## ⚙️ Environment Details
- **Google Cloud Region**: (e.g. `us-central1`)
- **Python Version**: (e.g. `3.12.x`)
- **IaC Engine used to install the platform**: OpenTofu version (`tofu version`; the installer needs 1.10 or later)
- **StackVend version**: (the `VERSION` file at the repository root, e.g. `0.9.0-preview`)
- **Commit SHA / Branch**: (e.g. `main` at `65d6ac1`)

## 🔍 Affected Subsystem / Component
- [ ] Control Center Portal (`apps/control-center`)
- [ ] Orchestrator Gateway (`apps/orchestrator-gateway`)
- [ ] Project & Repo Vending (`apps/project-vending`)
- [ ] Serverless Git (`apps/git-server`)
- [ ] MCP Tool Servers (`mcp-servers/*`)
- [ ] OpenTofu Golden Modules (`infra/modules/*`)
- [ ] FinOps Spend Sync / Enforcer

## 🔁 Steps to Reproduce
1. In Cloud Shell or Terminal, run '...'
2. Submit spec or invoke endpoint '...'
3. See error traceback in Cloud Logging or console.

## 📋 Expected Behavior
A clear and concise description of what you expected to happen.

## 🪵 Relevant Logs & Tracebacks
```text
Paste sanitized Cloud Logging / terminal logs here (ensure no credentials, tokens, or private project IDs are included).
```

## 💡 Additional Context
Add any other context about the problem here (e.g. Assured Workloads folder, VPC Service Controls, corporate organization policies).
