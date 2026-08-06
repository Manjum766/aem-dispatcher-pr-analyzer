# Tekton PR Review Agent

This directory contains all Tekton manifests for the **PR Review Agent** pipeline.
On every pull request, it runs three parallel security/quality scans and posts a
single consolidated comment to the GitHub PR.

## Pipeline Overview

```
[git-clone] → [sonarqube-scan, snyk-scan, dispatcher-lint] → [post-pr-comment]
```

| Pillar | Tool | What it checks |
|---|---|---|
| SAST + Code Quality | SonarQube | Java (`core/`), TypeScript (`ui.frontend.*`) — bugs, vulnerabilities, code smells |
| Secrets + Dependency CVEs | Snyk | Hardcoded secrets; CVEs in Maven (`pom.xml`) and npm/yarn deps |
| Dispatcher Rules | Custom script | Allow-all patterns, missing deny-first rules, open `/crx`/`/system` paths, missing CSP/X-Frame-Options |
| PR Comment | GitHub REST API | Single upserted comment with summary table, severity badges, pass/fail per pillar |

---

## Required Kubernetes Secrets

All Tasks consume credentials from Kubernetes Secrets. Create them once per cluster
namespace before applying the pipeline manifests.

### `github-token`

GitHub Personal Access Token with `repo` scope (read + write PR comments).

```bash
kubectl create secret generic github-token \
  --from-literal=token=<YOUR_GITHUB_PAT>
```

### `sonarqube-token`

SonarQube user token (generated in SonarQube → My Account → Security).

```bash
kubectl create secret generic sonarqube-token \
  --from-literal=token=<YOUR_SONARQUBE_USER_TOKEN>
```

### `sonarqube-url`

Base URL of the SonarQube server (no trailing slash).

```bash
kubectl create secret generic sonarqube-url \
  --from-literal=url=https://sonarqube.example.com
```

### `snyk-token`

Snyk API token (generated in Snyk → Account Settings → API Token).

```bash
kubectl create secret generic snyk-token \
  --from-literal=token=<YOUR_SNYK_API_TOKEN>
```

---

## Applying the Manifests

Apply in this order (or use `kubectl apply -f` on each file):

```bash
# 1. Tasks
kubectl apply -f tekton/tasks/sonarqube-scan.yaml
kubectl apply -f tekton/tasks/snyk-scan.yaml
kubectl apply -f tekton/tasks/dispatcher-lint.yaml
kubectl apply -f tekton/tasks/post-pr-comment.yaml

# 2. Pipeline
kubectl apply -f tekton/pipelines/pr-review-pipeline.yaml

# 3. Triggers
kubectl apply -f tekton/triggers/trigger-binding.yaml
kubectl apply -f tekton/triggers/trigger-template.yaml
kubectl apply -f tekton/triggers/event-listener.yaml
```

Or apply all at once:

```bash
kubectl apply -f tekton/tasks/ -f tekton/pipelines/ -f tekton/triggers/
```

---

## GitHub Webhook Setup

1. In your GitHub repository go to **Settings → Webhooks → Add webhook**.
2. Set **Payload URL** to your EventListener service URL:
   ```
   http://<eventlistener-service-ip>:8080
   ```
3. Set **Content type** to `application/json`.
4. Set **Secret** to the value in your `github-webhook-secret` Kubernetes Secret
   (if you configure HMAC validation on the EventListener).
5. Select **Let me select individual events** and tick **Pull requests**.
6. Click **Add webhook**.

The EventListener fires on `pull_request` events with actions:
`opened`, `synchronize`, `reopened`.

---

## Pipeline Parameters Reference

| Parameter | Source | Description |
|---|---|---|
| `REPO_URL` | `repository.clone_url` in webhook payload | Git clone URL |
| `REVISION` | `pull_request.head.sha` | Commit SHA to check out |
| `PR_NUMBER` | `pull_request.number` | PR number for comment upsert |
| `REPO_OWNER` | `repository.owner.login` | GitHub org/user name |
| `REPO_NAME` | `repository.name` | GitHub repository name |
| `SONAR_PROJECT_KEY` | TriggerTemplate default or per-repo override | SonarQube project key |
| `SNYK_ORG` | TriggerTemplate default (empty = Snyk default org) | Snyk organisation slug |

---

## Workspace

All Tasks share a single ephemeral `PersistentVolumeClaim` workspace named `output`
(provisioned as a `volumeClaimTemplate` per `PipelineRun`). Scan Tasks write JSON
result files there; the comment Task reads them.

| File | Written by |
|---|---|
| `sonar-result.json` | `sonarqube-scan` Task |
| `snyk-result.json` | `snyk-scan` Task |
| `dispatcher-result.json` | `dispatcher-lint` Task |

---

## Directory Structure

```
tekton/
  tasks/
    sonarqube-scan.yaml      # SonarQube SAST Task
    snyk-scan.yaml           # Snyk secrets + CVE Task
    dispatcher-lint.yaml     # Dispatcher rules lint Task
    post-pr-comment.yaml     # GitHub PR comment Task
  pipelines/
    pr-review-pipeline.yaml  # Fan-out / fan-in Pipeline
  triggers/
    trigger-binding.yaml     # GitHub webhook → Pipeline params
    trigger-template.yaml    # PipelineRun template
    event-listener.yaml      # Tekton EventListener
  scripts/
    dispatcher-lint.sh       # Dispatcher rule checks (bash)
    post-comment.sh          # GitHub comment upsert (bash + curl + jq)
```

## Java Security & Quality Demo

This repository also contains a small Maven-based Java module with intentionally vulnerable and low-quality code used to demonstrate:

- SonarQube bugs
- SonarQube code smells
- Security hotspots
- Snyk dependency vulnerabilities
- PR review workflows
