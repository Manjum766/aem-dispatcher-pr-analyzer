# PR Review Agent — Implementation Plan

## Top-Level Overview

Build a **One PR Review Agent** that runs on Tekton, triggered on every pull request
against this AEM repository. It executes three parallel security/quality checks and
then consolidates all findings into a single GitHub PR comment (created on first run,
updated on re-run).

### Scope
| Pillar | Tool | What it checks |
|---|---|---|
| SAST + Code Quality | SonarQube | Java (core/), TypeScript (ui.frontend.*) — bugs, vulnerabilities, code smells |
| Secrets + Dependency CVEs | Snyk | Hardcoded secrets across all files; CVEs in Maven (pom.xml) and npm/yarn deps |
| Dispatcher Rules | Custom script | Allow-all patterns, missing deny-first rules, open /crx /system paths, overly-broad cache, missing CSP/X-Frame-Options headers |
| PR Comment | GitHub REST API | Single comment (upsert) with summary table, severity badges, pass/fail per pillar |

### Out of scope
- Deployment risk scoring (CloudManager handles deployment gates)
- GitHub Actions (no workflow runner enabled on this repo)
- Full AEM HTL / Sling Model analysis (dispatcher security only)

### Tekton layout
All Tekton manifests live under a new top-level `tekton/` directory:
```
tekton/
  tasks/
    sonarqube-scan.yaml
    snyk-scan.yaml
    dispatcher-lint.yaml
    post-pr-comment.yaml
  pipelines/
    pr-review-pipeline.yaml
  triggers/
    trigger-template.yaml
    trigger-binding.yaml
    event-listener.yaml
  scripts/
    dispatcher-lint.sh
    post-comment.sh
```

---

## Sub-Tasks

---

### Sub-Task 1 — Repository Scaffolding & Shared Secrets Contract

**Intent**
Create the `tekton/` directory tree and document the Kubernetes Secrets that all
Tasks will consume. This establishes the structural foundation before any YAML is
written and aligns the team on secret names before cluster setup.

**Expected Outcomes**
- `tekton/` directory exists with all subdirectories
- `tekton/README.md` documents every required Kubernetes Secret and how to create them
- No functional Tekton YAML yet — just the skeleton and documentation

**Todo List**
1. Create directory tree: `tekton/tasks/`, `tekton/pipelines/`, `tekton/triggers/`, `tekton/scripts/`
2. Write `tekton/README.md` covering:
   - Required Kubernetes Secrets:
     - `github-token` → key `token` — GitHub PAT with `repo` scope (read + write PR comments)
     - `sonarqube-token` → key `token` — SonarQube user token
     - `sonarqube-url` → key `url` — SonarQube host URL
     - `snyk-token` → key `token` — Snyk API token
   - `kubectl` commands to create each secret
   - Trigger setup: how the existing EventListener maps to this Pipeline
3. Add a `sonar-project.properties` file at repo root (required by SonarQube scanner)
   covering both `core/` (Java) and `ui.frontend.idl/`, `ui.frontend.widgets/` (TypeScript)

**Relevant Context**
- No `.github/workflows/` — Tekton is the only CI layer
- Secrets consumed via `env.valueFrom.secretKeyRef` in Tekton Task steps
- SonarQube scanner auto-discovers `sonar-project.properties` at repo root

**Status** — `[ ] pending`

---

### Sub-Task 2 — SonarQube Scan Task

**Intent**
Write the Tekton Task that runs SonarQube analysis against the PR branch and
reports results back to SonarQube server. Produces a JSON artifact consumed by
the comment step.

**Expected Outcomes**
- `tekton/tasks/sonarqube-scan.yaml` — valid Tekton Task
- Task runs `sonar-scanner` CLI against the workspace
- Task writes a structured JSON result file to a shared Tekton workspace:
  `$(workspaces.output.path)/sonar-result.json`
  containing: `{ status: "passed"|"failed", bugs, vulnerabilities, code_smells, hotspots, quality_gate_status, dashboard_url }`
- Task passes on `qualityGate=OK`, fails (but does not block the pipeline) on `qualityGate=ERROR`

**Todo List**
1. Define Task with params: `SONAR_PROJECT_KEY`, `SONAR_BRANCH`
2. Define workspaces: `source` (cloned repo), `output` (shared results)
3. Add step using image `sonarsource/sonar-scanner-cli:latest`:
   - Runs `sonar-scanner` with params sourced from `sonar-project.properties` + env vars
   - Passes PR metadata: `sonar.pullrequest.key`, `sonar.pullrequest.branch`, `sonar.pullrequest.base`
4. Add a second step (bash + curl) that polls the SonarQube API for the Quality Gate
   status (`/api/qualitygates/project_status?projectKey=...`) and writes `sonar-result.json`
5. Set `onError: continue` on the Task so a SonarQube failure does not abort the
   parallel fan-out — the comment step will report it

**Relevant Context**
- Java sources: `core/src/main/java/`
- TypeScript sources: `ui.frontend.idl/js/`, `ui.frontend.widgets/src/`
- SonarQube token/URL consumed from K8s Secrets `sonarqube-token` and `sonarqube-url`
- `sonar-project.properties` created in Sub-Task 1

**Status** — `[ ] pending`

---

### Sub-Task 3 — Snyk Scan Task

**Intent**
Write the Tekton Task that runs Snyk to detect hardcoded secrets and known CVEs
across Java (Maven) and JavaScript (npm / Yarn) dependency trees.

**Expected Outcomes**
- `tekton/tasks/snyk-scan.yaml` — valid Tekton Task
- Runs three Snyk scans: `snyk code test` (secrets/SAST), `snyk test` against root
  `pom.xml` (Maven CVEs), `snyk test` against `ui.frontend.widgets/package.json` (Yarn CVEs)
- Writes `$(workspaces.output.path)/snyk-result.json`:
  `{ status, secrets_found, critical_vulns, high_vulns, medium_vulns, low_vulns, issues: [...] }`
- Task uses `onError: continue` — a Snyk finding is reported, not a pipeline abort

**Todo List**
1. Define Task with param `SNYK_ORG` (optional, falls back to Snyk default org)
2. Define workspaces: `source`, `output`
3. Add step using image `snyk/snyk:linux`:
   - Authenticate: `snyk auth $(SNYK_TOKEN)`
   - Run `snyk code test --json` → capture to temp file (secrets + SAST)
   - Run `snyk test --file=pom.xml --all-projects --json` → Maven deps
   - Run `snyk test --file=ui.frontend.widgets/package.json --json` → Yarn deps
   - Run `snyk test --file=ui.frontend.idl/package.json --json` → npm deps
4. Add a bash step that merges all four JSON outputs into `snyk-result.json`,
   aggregating severity counts
5. Set `onError: continue` on all Snyk steps

**Relevant Context**
- `ui.frontend.widgets/` uses Yarn 3 Berry (`yarnrc.yml`) — Snyk handles this natively
- `ui.frontend.idl/` uses npm (has `package-lock.json`)
- Root `pom.xml` is the Maven multi-module entry point
- Snyk token consumed from K8s Secret `snyk-token`

**Status** — `[ ] pending`

---

### Sub-Task 4 — Dispatcher Lint Task & Script

**Intent**
Write a shell script and Tekton Task that statically analyses all dispatcher
configuration files changed in the PR for known security anti-patterns.

**Expected Outcomes**
- `tekton/scripts/dispatcher-lint.sh` — self-contained bash script, exits 0 always,
  writes findings to stdout as JSON
- `tekton/tasks/dispatcher-lint.yaml` — Tekton Task wrapping the script
- Script detects the following and writes `$(workspaces.output.path)/dispatcher-result.json`:
  `{ status, findings: [{ file, line, severity, rule, message }] }`

**Checks implemented in `dispatcher-lint.sh`**

| Rule ID | Description | Severity |
|---|---|---|
| DISP-001 | `/type "allow"` with `/glob "*"` — allow-all pattern | CRITICAL |
| DISP-002 | First rule in a filter file is not `/type "deny"` | HIGH |
| DISP-003 | `/url "/crx/*"` or `/url "/system/*"` is `allow`ed | CRITICAL |
| DISP-004 | `/url "/bin/*"` allowed without a more specific deny below | HIGH |
| DISP-005 | Cache rules file has `/glob "*" /type "allow"` as only rule (no deny overrides) | MEDIUM |
| DISP-006 | VHost file missing `Header always set Content-Security-Policy` | MEDIUM |
| DISP-007 | VHost file missing `X-Frame-Options` header directive | MEDIUM |
| DISP-008 | `/allowAuthorized "1"` in farm config — caches authenticated content | HIGH |

**Todo List**
1. Write `tekton/scripts/dispatcher-lint.sh`:
   - Accept `DISPATCHER_DIR` env var (default: `dispatcher/src`)
   - For each `.any` file under `conf.dispatcher.d/filters/`: check DISP-001, DISP-002, DISP-003, DISP-004
   - For each `.any` file under `conf.dispatcher.d/cache/`: check DISP-005
   - For each `.vhost` file under `conf.d/available_vhosts/`: check DISP-006, DISP-007
   - For each `.farm` file: check DISP-008
   - Emit JSON to `$OUTPUT_FILE` env var path
2. Write `tekton/tasks/dispatcher-lint.yaml`:
   - Step uses `bash:latest` (or `alpine/git`) image
   - Copies and executes `dispatcher-lint.sh` from workspace
   - `onError: continue`

**Relevant Context**
- Current dispatcher layout: `dispatcher/src/conf.d/` and `dispatcher/src/conf.dispatcher.d/`
- `default_filters.any` starts correctly with `/0001 { /type "deny" /url "*" }` — DISP-002 should check the custom `filters.any` / `ibm_cloud_default_filters.any` too
- `ibm_cloud_default.vhost` already has CSP + X-Frame-Options — the script verifies they are present, flagging if a new vhost file lacks them
- `ibm_cloud_default.farm` has `/allowAuthorized "0"` — DISP-008 should fire only when value is `"1"`

**Status** — `[ ] pending`

---

### Sub-Task 5 — Post PR Comment Task & Script

**Intent**
Write the Task that reads the three result JSON files from the shared workspace,
builds a single Markdown comment, and upserts it on the GitHub PR via the REST API.
"Upsert" means: find an existing comment from this bot (by a known marker string)
and update it, or create a new one if none exists.

**Expected Outcomes**
- `tekton/scripts/post-comment.sh` — bash script that reads result JSONs, builds Markdown, posts/updates GitHub comment
- `tekton/tasks/post-pr-comment.yaml` — Tekton Task wrapping the script
- Comment format:
  ```
  ## 🤖 PR Review Agent

  | Check | Status | Details |
  |---|---|---|
  | 🔍 SonarQube | ✅ Passed / ❌ Failed | X bugs, Y vulns, Z smells — [Dashboard](...) |
  | 🔒 Snyk | ✅ Passed / ⚠️ Issues | X critical, Y high CVEs; Z secrets found |
  | ⚙️ Dispatcher Rules | ✅ Clean / ⚠️ Warnings | N findings |

  <details><summary>Snyk Findings</summary>...</details>
  <details><summary>Dispatcher Findings</summary>...</details>

  <!-- pr-review-agent-marker -->
  ```
- The HTML comment `<!-- pr-review-agent-marker -->` is used to find and update
  the existing comment on re-runs

**Todo List**
1. Write `tekton/scripts/post-comment.sh`:
   - Params via env vars: `GITHUB_TOKEN`, `REPO_OWNER`, `REPO_NAME`, `PR_NUMBER`
   - Read `sonar-result.json`, `snyk-result.json`, `dispatcher-result.json` from `$RESULTS_DIR`
   - Use `jq` to parse JSON and build Markdown string
   - `GET /repos/{owner}/{repo}/issues/{pr}/comments` → search for comment body containing marker
   - If found: `PATCH /repos/{owner}/{repo}/issues/comments/{id}` (update)
   - If not found: `POST /repos/{owner}/{repo}/issues/{pr}/comments` (create)
2. Write `tekton/tasks/post-pr-comment.yaml`:
   - Image: `alpine/jq` or `bitnami/jq` (has both `curl` and `jq`)
   - Params: `REPO_OWNER`, `REPO_NAME`, `PR_NUMBER`
   - Consumes K8s Secret `github-token`
   - Workspace: `output` (reads result JSONs written by earlier Tasks)
3. Handle missing result files gracefully — if a scan Task was skipped or failed to
   write its JSON, show `⚠️ Scan did not complete` for that row

**Relevant Context**
- GitHub REST API endpoint: `POST /repos/{owner}/{repo}/issues/{number}/comments`
- The `<!-- pr-review-agent-marker -->` HTML comment must be in the body so the
  search-and-update logic can locate it reliably
- `REPO_OWNER` and `REPO_NAME` are extracted from `git remote get-url origin` in the
  binding or passed explicitly via TriggerBinding params

**Status** — `[ ] pending`

---

### Sub-Task 6 — Pipeline & Trigger Wiring

**Intent**
Compose the four Tasks into a Pipeline with a fan-out / fan-in pattern: clone repo,
run the three scan Tasks in parallel, then run the comment Task once all three finish
(regardless of individual Task outcome).

**Expected Outcomes**
- `tekton/pipelines/pr-review-pipeline.yaml` — valid Tekton Pipeline
- `tekton/triggers/trigger-binding.yaml` — maps GitHub webhook payload to Pipeline params
- `tekton/triggers/trigger-template.yaml` — creates a PipelineRun from the binding
- `tekton/triggers/event-listener.yaml` — EventListener referencing the binding + template
- Pipeline DAG:
  ```
  [git-clone] → [sonarqube-scan, snyk-scan, dispatcher-lint] → [post-pr-comment]
  ```
- All three scan Tasks have `runAfter: [git-clone]`
- `post-pr-comment` has `runAfter: [sonarqube-scan, snyk-scan, dispatcher-lint]`
  with `taskRef` condition that runs even when upstream tasks fail

**Todo List**
1. Write `tekton/pipelines/pr-review-pipeline.yaml`:
   - Use `git-clone` from Tekton Catalog (`tekton.dev/v1beta1 ClusterTask`)
   - Declare a shared `PersistentVolumeClaim` workspace (`output`) passed to all Tasks
   - Pipeline params: `REPO_URL`, `REVISION`, `PR_NUMBER`, `REPO_OWNER`, `REPO_NAME`,
     `SONAR_PROJECT_KEY`, `SNYK_ORG` (optional)
   - Set `finally` block containing `post-pr-comment` so it always runs
2. Write `tekton/triggers/trigger-binding.yaml`:
   - Extract from GitHub `pull_request` webhook: `repository.clone_url`, `pull_request.head.sha`,
     `pull_request.number`, `repository.owner.login`, `repository.name`
3. Write `tekton/triggers/trigger-template.yaml`:
   - Creates a `PipelineRun` with a generated name
   - Mounts a `VolumeClaimTemplate` for the `output` workspace
4. Write `tekton/triggers/event-listener.yaml`:
   - References the existing cluster ServiceAccount
   - Binds `trigger-binding` + `trigger-template`
   - Filter on `pull_request` event type (opened, synchronize, reopened)
5. Add `tekton/README.md` section: how to apply all manifests with `kubectl apply -k tekton/`
   or individual `kubectl apply -f`

**Relevant Context**
- Tekton Pipelines and Triggers infrastructure already exists in the cluster
- The `git-clone` ClusterTask is part of standard Tekton Catalog and is assumed present
- `post-pr-comment` is placed in `finally` to guarantee it runs even when a scan fails
- `PipelineRun` workspace uses `volumeClaimTemplate` (ephemeral PVC per run)

**Status** — `[ ] pending`

---

## Implementation Order

```
Sub-Task 1 (Scaffolding)
    ↓
Sub-Task 2 (SonarQube Task) ─┐
Sub-Task 3 (Snyk Task)       ├─ can be done in parallel
Sub-Task 4 (Dispatcher Task) ─┘
    ↓
Sub-Task 5 (Post Comment Task)
    ↓
Sub-Task 6 (Pipeline + Triggers)
```

Sub-Tasks 2, 3, and 4 are independent and can be implemented in parallel.
Sub-Task 5 depends on the JSON output contracts established in 2–4.
Sub-Task 6 wires everything together and is last.
