# Panopticon

**Endpoint telemetry, detection, and controlled response — end to end.**

Panopticon is a security-focused, multi-repository EDR/XDR capstone and research
platform. It collects real endpoint telemetry (process, network, and related
events) from Windows and Linux hosts, evaluates it against a rule- and
behavior-based detection engine, and — where a detection engine recommendation
warrants it — authorizes and dispatches a narrow, closed set of typed response
actions back to the originating endpoint, with full lifecycle tracking and audit.

This is a capstone/research project, not a commercial product. It is under
active development; maturity varies by repository (see the table below), and
known limitations are documented in each repository's README rather than
hidden.

## Architecture

```
Endpoint Agents (Windows / Linux)
        │  telemetry (process, network, ...)
        ▼
 Detection Engine  ──── rules, correlation, behavioral (UEBA) analysis
        │  alert + response recommendation
        ▼
 Response Engine   ──── translates a recommendation onto a CLOSED set
        │               of 7 typed commands (never arbitrary execution)
        ▼
    Manager         ──── authorization, dispatch, lifecycle, audit
        │  typed command
        ▼
 Endpoint Agent     ──── executes the command, returns a typed result
        │
        ▼
      Audit  ──────────────────────────────────────────────►  Console
```

The closed response-action set is: `KILL_PROCESS`, `COLLECT_PROCESS_INFO`,
`COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`,
`ISOLATE_HOST`, `RELEASE_HOST_ISOLATION`. There is no 8th action and no path
to arbitrary remote execution — this is a deliberate, security-reviewed
architectural boundary, not a current-phase limitation.

`KILL_PROCESS` and related identity-sensitive actions carry a
`target_start_time_ticks` value alongside the target PID specifically to
prevent PID-reuse attacks (terminating the wrong process after the OS recycles
a PID). This is enforced end-to-end and covered by tests in the Manager repo.

## Repositories

| Repository | Role |
|---|---|
| [panopticon-agent](https://github.com/Panopticon-Co/panopticon-agent) | Windows endpoint agent ("Officer") — C++20, ETW/Sysmon telemetry collection, response-command execution |
| [panopticon-linux-agent](https://github.com/Panopticon-Co/panopticon-linux-agent) | Linux endpoint agent — C++20, procfs-based telemetry, privileged isolation helper |
| [panopticon-detection-engine](https://github.com/Panopticon-Co/panopticon-detection-engine) | Rule-based detection, multi-stage correlation, and behavioral (UEBA) engine ("eyedetect") |
| [panopticon-response-engine](https://github.com/Panopticon-Co/panopticon-response-engine) | Translates detection recommendations onto the closed 7-action command vocabulary; policy, authorization tiers, lifecycle |
| [panopticon-manager](https://github.com/Panopticon-Co/panopticon-manager) | FastAPI control plane — ingestion, orchestration, authorization/dispatch, audit |
| [panopticon-console](https://github.com/Panopticon-Co/panopticon-console) | Read-only alert and investigation dashboard |
| [panopticon-contracts](https://github.com/Panopticon-Co/panopticon-contracts) | Canonical wire-level JSON Schemas and golden fixtures for the response command/result contract — not a runtime service |
| [panopticon-diagrams](https://github.com/Panopticon-Co/panopticon-diagrams) | Canonical architecture, UML, and sequence diagrams, validated in CI against the sibling repositories |

## Platform support

- **Windows**: endpoint agent with live ETW and Sysmon telemetry collection.
- **Linux**: endpoint agent with procfs-based telemetry and a privileged
  isolation helper for host-isolation response actions.
- **Backend/Console**: platform-independent (Python/FastAPI backend, a
  dependency-free Python-served console).

macOS and mobile endpoints are not supported and are not currently planned.

## Security-oriented design

- A **closed, security-reviewed response-action set** — the platform will
  never execute an arbitrary command on an endpoint; only one of the seven
  named actions above.
- **PID-reuse protection** on process-identity-sensitive actions via an
  opaque, pass-through-only `start_time_ticks` token that is never guessed or
  defaulted.
- **Explicit separation of detection from execution**: the Detection Engine
  and Response Engine only ever produce recommendations/typed commands — they
  never call `subprocess`, `os.kill`, or any OS API directly. Only the
  endpoint agents execute anything, and only after Manager authorization.
- **Canonical, versioned wire contracts** (panopticon-contracts) that every
  producer and consumer repository is validated against.
- **Full command lifecycle and audit trail** — created → authorized →
  dispatched → accepted → result → audited — for every response action.

## Development status

This project follows a vertical-slice-first roadmap: a working
telemetry → detection → alert path was built and validated before response
execution, and response execution was built and tested end to end against the
real, unmodified detection and response engines before broader
telemetry/response expansion. Reachability from a real ingested event varies
by rule: `QUARANTINE_FILE` (via production rule `DET-PERS-007`) is proven
reachable through a real `POST /api/v1/ingest` call with no internal bypass;
`KILL_PROCESS`'s dispatch/execution/audit machinery is proven correct once an
alert exists, but its only previously-cited trigger rule (`DET-INJ-001`)
requires process-injection telemetry no current endpoint collector produces,
so that specific path is not reachable from a real endpoint today. Some
response actions (`COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS`) are
implemented and tested at the Manager/Response Engine boundary but are not
yet triggered automatically by every production detection rule — see each
repository's README and, for the Manager, `docs/RESPONSE_ENGINE_STATE.md` for
the current, honest status.

## Documentation

Each repository's README is the entry point for that component: build/test
instructions, architecture role, security considerations, and known
limitations. `panopticon-diagrams` holds the canonical, CI-validated
architecture and sequence diagrams referenced across the platform.

## Contributing

Each repository has its own `CONTRIBUTING.md` tailored to its toolchain
(CMake/vcpkg for the C++ agents, pytest for the Python services). In general:
fork or branch, keep changes focused, add or update tests, and note any
cross-repository contract impact in your pull request.

## Reporting a security issue

Panopticon is a security product, so please **do not open a public issue**
for a suspected vulnerability. Each repository's `SECURITY.md` explains how
to report privately via
[GitHub Security Advisories](https://github.com/Panopticon-Co). This is a
capstone/research project maintained on a best-effort basis; there is no
formal SLA on response time.

## License

All Panopticon-Co repositories are licensed under the [MIT License](https://github.com/Panopticon-Co/panopticon-manager/blob/main/LICENSE) unless a repository's own `LICENSE` file states otherwise.

## Disclaimer

Panopticon is a capstone and research project. It is not a certified,
audited, or commercially supported security product, and no claims of
production-readiness, compliance, or formal security certification are made.
