# BYO Architecture

Status: approved v0.1 foundation; analyzers are not implemented yet.

## Purpose

BYO — Before You Open is a privacy-first preflight inspector for files, links,
and QR codes. Its job is to report what can be observed and explain which
properties may deserve attention before a person decides whether to trust or
open the input.

BYO is not an antivirus product, a malware sandbox, or a guarantee of safety.
The architecture must preserve that distinction in code and in every user
interface.

## Architectural invariants

The following rules are mandatory:

1. Inspected content is data. BYO must never execute, open, launch, import, or
   hand it to another application as part of analysis.
2. `byo-core` is platform-neutral and has no dependency on a user interface,
   operating-system integration, Tauri, a shell, an opener, a sidecar, or a
   network client.
3. v0.1 is fully offline. Neither the core nor its current callers perform
   network activity.
4. Observations and interpretations are different domain concepts and must not
   be collapsed into a single verdict.
5. Finding severity uses only `Info`, `Attention`, and `Warning`.
6. BYO does not calculate or display a numeric risk score.
7. Unknown, unsupported, partial, and failed analysis states must be reported
   explicitly. They must not be converted into reassuring results.

## Layers and dependency direction

### `byo-core`

`byo-core` will contain the reusable analysis domain and, after later approved
milestones, the offline analyzers. It must remain usable by the CLI and future
user interfaces without knowing which caller invoked it.

The core may eventually accept bounded byte buffers, readers, and explicit
input metadata. It should not discover files through platform APIs or perform
user-interface work. Callers are responsible for resolving user-selected paths
and opening read-only handles. This keeps operating-system behavior outside the
analysis layer and makes the core deterministic and testable.

The core must not:

- depend on `byo-cli` or any future UI crate;
- depend on Tauri or a webview API;
- invoke operating-system integration APIs;
- spawn processes or execute shell commands;
- open files or URLs with their registered applications;
- include HTTP, DNS, socket, upload, telemetry, or reputation clients;
- silently convert incomplete analysis into a positive conclusion.

### `byo-cli`

`byo-cli` is a thin adapter around `byo-core`. It owns command-line argument
handling, terminal presentation, exit behavior, and future path selection. It
must not duplicate analyzer rules.

The foundation CLI currently provides only help and version output. File, URL,
and QR commands are intentionally deferred. The CLI depends on `byo-core`; the
core never depends on the CLI.

### Future UI layers

Desktop and mobile interfaces are outside this foundation. A future UI will be
another adapter that calls `byo-core` and presents the same structured reports.
UI framework types must not leak into the core.

Future native integrations—such as file pickers, share sheets, Explorer or
file-manager entries, and signature APIs—belong in narrow platform adapters.
They may supply input to the core, but they may not change core findings or
create alternative analyzer implementations.

### Future network functionality

Network functionality is outside v0.1 and outside the current trust boundary.
If approved later, it must be a separate, explicit layer with its own threat
model, consent flow, timeouts, destination policy, privacy disclosure, and
tests. It must not be added to `byo-core` merely as an optional code path.

No `byo-net` crate is created by this milestone.

## Planned report model

The exact Rust types are deferred until the next approved milestone. The model
will preserve these concepts:

- **Observation** — a factual property obtained from the supplied input, such
  as a byte signature, filename component, parsed URL field, or decoded QR
  payload.
- **Finding** — a rule-based interpretation that references one or more
  observations and explains why they may matter.
- **Severity** — exactly `Info`, `Attention`, or `Warning`.
- **Limitation** — something BYO could not inspect, did not attempt, or cannot
  establish.
- **Report metadata** — analyzer/schema version plus whether the analysis was
  local and whether network activity occurred.

In v0.1, the network-activity value must always be false. A successful analysis
means that configured checks completed; it does not mean the input is safe.

## Input flow

The intended flow is:

1. A caller receives a user-selected input without launching it.
2. The caller applies path and top-level size policy and opens data read-only.
3. The caller passes bounded data and explicit context to `byo-core`.
4. The core produces observations, findings, errors, and limitations.
5. The caller renders untrusted values strictly as data, never as markup or a
   command.

Analysis should stream large inputs where possible. Parsers must receive only
the bytes they need, and every allocation derived from hostile input must have
an explicit upper bound.

## Dependency policy

Dependencies are part of BYO's attack surface. Each dependency must have a
specific need, a compatible license, active maintenance, and a reviewed feature
set.

Foundation policy:

- `byo-core` has no third-party dependencies.
- `byo-cli` depends only on the local `byo-core` crate.
- no async runtime is present;
- no HTTP or other network-capable crate is present;
- unsafe Rust is forbidden in BYO workspace code;
- generated binaries and `target/` artifacts are not committed.

Later parser dependencies require a separate reviewed change. Default features
must not be accepted without inspecting what they enable.

## Workspace layout

```text
byo/
├── crates/
│   ├── byo-core/
│   └── byo-cli/
├── docs/
│   ├── architecture.md
│   └── threat-model.md
├── fixtures/
└── Cargo.toml
```

Additional crates are created only when an actual isolation boundary requires
them. `byo-types` and `byo-net` are deliberately absent.

## Intentionally deferred

- file, filename, URL, and QR analyzers;
- report and finding Rust types;
- parser dependencies and fuzz targets;
- Tauri and all other graphical user interfaces;
- platform-specific integrations;
- archive, document, metadata, and signature parsing;
- HTTP requests, redirect resolution, reputation services, and uploads;
- packaging, installers, releases, and mobile work.

