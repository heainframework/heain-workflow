# heain-workflow

Business processes with people in them, for a heain deployment (Step 4.6c, 2026-10-07). A process is a versioned definition (YAML or JSON); each run of it is an instance that moves through steps:

- tasks for people (an inbox through heain-gateway, notices through heain-notify);
- decisions by core's Approver (P5);
- calls to apps that open a capability to workflows (`*.step`);
- core jobs;
- signed webhooks, heain-notify messages, timers and switches.

Tasks may have deadlines, and a definition may start itself on a schedule.

Built on [heain-sdk](https://github.com/heainframework/heain-sdk) v1. It needs heain-core with Step 4.6a (public endpoints and `gateway.exposures`); people reach it through [heain-gateway](https://github.com/heainframework/heain-gateway) and are told through [heain-notify](https://github.com/heainframework/heain-notify). It passes the heain conformance suite. Run it however you like: a plain process, a service unit, or a container (Docker is not required).

## Author decisions (2026-10-07)

1. **Definitions** are YAML or JSON state machines. A new version becomes active only after core's Approver approves it (P5 type `workflow.activate`, category `KNOWLEDGE_UPDATE`). A running instance keeps the version it started with.
2. **People and approvals.** Ordinary work is a workflow task (an inbox, claim, complete). Where the definition says so, a `p5` step asks core's Approver instead (category `ALLOWLIST_BASED`, the action type the definition names), so the decision is in core's audit chain.
3. **Automatic steps in v1:** apps' `*.step` capabilities (a direct call), core jobs (`*.step` or `job.orchestrate` job capabilities), signed webhooks, and heain-notify messages.
4. **Time:** task deadlines (remind, or take another path), timers, and schedules (5-field cron).

## Definitions

```yaml
id: purchase
title: Purchase request
start: {roles: [staff]}          # people with one of these roles (through heain-gateway) may start it; or apps: [...]
first: review
steps:
  - {id: review, type: task, title: Review the purchase, assign: {role: manager}, outcomes: [approve, reject],
     fields: [comment], deadline: 2d, notify: ["group:managers"], on: {approve: size, reject: rejected}}
  - {id: size, type: switch, cases: [{var: amount, op: ">", value: 1000, goto: finance}], default: issue}
  - {id: finance, type: p5, action_type: purchase.approve, on: {approved: issue, denied: rejected}}
  - {id: issue, type: app, app: erp-docs, capability: docs.issue.step, path: /v1/issue, next: render, error: rejected}
  - {id: render, type: job, capability: docs.render.step, payload: review, next: erp}
  - {id: erp, type: webhook, url: "https://erp.example/hooks/purchase", next: wait}
  - {id: wait, type: timer, wait: 1h, next: tell}
  - {id: tell, type: notify, to: [starter], kind: purchase.done, next: done}
  - {id: done, type: end, status: completed}
  - {id: rejected, type: end, status: rejected}
```

| Step type | What it does | Fields |
|---|---|---|
| `task` | A task for a person: by role, by account, or by an account named in a variable. Its outcome picks the next step; its fields are kept under `vars.<step>`. | `assign: {role \| user \| var}`, `outcomes`, `fields`, `deadline`, `on_deadline`, `notify` |
| `p5` | Core's Approver decides. | `action_type`, `on: {approved, denied}` |
| `app` | `POST` to an app's `*.step` capability with `{workflow, version, instance, step, vars}`. The app answers `{outcome, vars}`. A 4xx is final; other errors are retried. | `app`, `capability`, `path` |
| `job` | A core job on a `*.step` (or `job.orchestrate`) job capability. Its payload is `vars.<payload>`; its output is kept under `vars.<step>.output`. | `capability`, `payload` |
| `webhook` | `POST {workflow, version, instance, step, vars}`, signed: `X-Heain-Signature` is an RSA/ECDSA signature over the SHA-256 of the body, by the app key whose certificate is in `X-Heain-Cert`. | `url` |
| `notify` | A heain-notify message with a reference only (the instance id). It never blocks the process. | `to` (`group:`, `contact:`, `gateway_user:`, `starter`, `var:<key>`), `kind`, `severity` |
| `timer` | Waits. | `wait` (`30s`, `5m`, `2h`, `7d`) |
| `switch` | The first matching case wins. | `cases: [{var, op (== != > >= < <= in), value, goto}]`, `default` |
| `end` | Ends the instance with a status. | `status` |

Every step may name `next`, `on: {<outcome>: <step>}` and `error` (where to go when it fails, instead of failing the instance). Automatic steps are retried with growing waits before they fail.

A task's deadline either takes `on_deadline`, or marks the task overdue and tells the same people again. `schedule: "0 8 * * 1-5"` with `schedule_vars` starts an instance on that schedule (time zone `-timezone`), with starter `schedule`.

## The API

All endpoints are declared `public`, so an operator may expose them to people through heain-gateway (`gateway.exposures`, approved through P5).

| Endpoint | Who |
|---|---|
| `PUT /v1/definitions/{id}` (YAML, JSON, or `{"source": "..."}`) → a new version, proposed to P5 | `workflow-admin` role, or an app in `-admin-callers` |
| `GET /v1/definitions`, `GET /v1/definitions/{id}` | the same |
| `GET /v1/workflows` | anyone: the active workflows they may start |
| `POST /v1/workflows/{id}/instances {vars}` | people with a `start.roles` role, or apps in `start.apps` |
| `GET /v1/instances`, `GET /v1/instances/{id}` | a person sees the instances they started or worked on, or whose open task they can see; an admin sees all |
| `POST /v1/instances/{id}/cancel` | admin |
| `GET /v1/tasks` (my inbox), `POST /v1/tasks/{id}/claim`, `POST /v1/tasks/{id}/complete {outcome, data}` | people only (through heain-gateway); `data` may hold only the task's fields |

Each request is audited in core by heain-sdk, with the person's signed assertion. Instances started and ended, steps, and definition versions activated or denied are audited too. Instance data never goes into the audit.

## Opening a capability to workflows

An app offers a step by declaring a capability named `<something>.step`:

- **direct:** heain-workflow calls it;
- **job:** a core job runs it.

The app should check that the caller is `heain-workflow.*`. `examples/wf-demo` shows both (`docs.issue.step`, `docs.render.step`).

## At rest

Definitions and tasks are sealed under the app's inside key from heain-core's KMS, and indexed by HMAC. Each instance (its variables and history) is sealed under its own key. Removing an instance destroys its key (crypto-shred). Only the status and wake time of an instance are readable without its key.

## Setting it up

```sh
go build -o heain-workflow ./cmd/heain-workflow
./heain-workflow -timezone Asia/Bangkok          # listens on :19530 (HEAIN_LISTEN)
```

Flags:

- `-admin-callers` (apps that may manage definitions);
- `-notify-app` (default `heain-notify`);
- `-timezone`;
- `-poll` (how often P5 decisions and jobs are checked, default 3 s).

The usual heain-sdk environment applies (`HEAIN_CORE_URL`, `HEAIN_ENROLL_TOKEN`, ...). Then:

1. Through P5, set `gateway.exposures` for the routes people use.
2. Give people the `workflow-admin` role (heain-gateway), plus the roles the definitions name.
3. Add contacts in heain-notify with `gateway_user`, so task notices reach them.

## Tests

```sh
go test ./...
bash scripts/live_4_6c.sh     # needs ~/heain-core, ~/heain-sdk, ~/heain-database, ~/heain-gateway, ~/heain-notify; ~3 min
```

The live test runs a real core node with heain-database, heain-gateway, heain-notify (with TEST ONLY sinks) and wf-demo. It covers:

- a purchase from start to end (task, P5, app step, job, signed webhook, timer, notice);
- a deadline, a denial and a cancel;
- versions;
- a schedule;
- who sees what;
- nothing plaintext at rest;
- the audit chain.
