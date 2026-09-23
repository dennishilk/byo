# BYO Architecture

Status: M1 offline inspection pipeline implemented; PRE-ALPHA.

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

`byo-core` contains the reusable report domain plus the M1 filename, bounded
file-header, streaming hash, and URL analyzers. It remains usable by the CLI
and future user interfaces without knowing which caller invoked it.

The file analyzer accepts a `Read` implementation plus explicit filename and
size context. It never discovers a path. The URL analyzer accepts text and uses
a 64 KiB input ceiling. Callers remain responsible for user-selected paths and
read-only handles. This keeps operating-system behavior outside the analysis
layer and makes the core deterministic and testable.

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

The CLI provides help/version plus `file` and `url` commands. It rejects
directories and unsupported special files, opens regular files read-only,
checks metadata around analysis, safely renders terminal text, and optionally
serializes the structured report as JSON. The CLI depends on `byo-core`; the
core never depends on the CLI. QR remains deferred.

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

## Report model

M1 implements durable Rust types for these concepts:

- **Observation** — a factual property obtained from the supplied input, such
  as a byte signature, filename component or parsed URL field; a future QR
  milestone can use the same concept for decoded payload data.
- **Finding** — a rule-based interpretation that references one or more
  observations and explains why they may matter.
- **Severity** — exactly `Info`, `Attention`, or `Warning`.
- **Limitation** — something BYO could not inspect, did not attempt, or cannot
  establish.
- **Report metadata** — schema/analyzer version, explicit
  `Complete`/`Partial`/`Failed` state, input kind, local status and network
  activity.

`network_activity` is constructed as `false` in every M1 report. A complete
analysis means that configured M1 checks completed; it does not mean the input
is safe. Findings reference the observation IDs that support them. The
machine-readable schema is PRE-ALPHA and not compatibility-stable yet.

## Input flow

The intended flow is:

1. The CLI receives a selected path or URL text without launching it.
2. For a file, the CLI checks metadata, rejects unsupported types and opens a
   read-only handle.
3. The core streams SHA-256 with a fixed 64 KiB buffer and retains at most the
   first 64 KiB for signature checks. Filename rules consume filename data only.
4. For a URL, the core enforces its input ceiling and calls the `url` parser;
   it never performs resolution or navigation.
5. The core produces observations, findings and limitations in one report.
6. The CLI escapes every untrusted terminal value or serializes the typed
   structure with `serde_json`.

Analysis should stream large inputs where possible. Parsers must receive only
the bytes they need, and every allocation derived from hostile input must have
an explicit upper bound.

## Dependency policy

Dependencies are part of BYO's attack surface. Each dependency must have a
specific need, a compatible license, active maintenance, and a reviewed feature
set.

M1 dependency policy:

- `sha2` 0.10 performs reviewed streaming SHA-256; default features are off;
- `url` 2.5.0 provides WHATWG parsing;
- `idna` 0.5.0 provides UTS-46/Punycode Unicode display conversion;
- `serde` derives serialization for the report model;
- `serde_json` exists only in `byo-cli` for JSON output;
- no async runtime is present;
- no HTTP or other network-capable crate is present;
- unsafe Rust is forbidden in BYO workspace code;
- generated binaries and `target/` artifacts are not committed.

The `url`/`idna` versions are intentionally pinned to a standards-oriented,
Rust-1.77-compatible combination without the newer ICU dependency expansion.
Later parser dependencies require a separate reviewed change.

## Workspace layout

```text
byo/
├── crates/
│   ├── byo-core/
│   └── byo-cli/
├── docs/
│   ├── architecture.md
│   ├── m1-offline-inspection.md
│   └── threat-model.md
├── fixtures/
└── Cargo.toml
```

Additional crates are created only when an actual isolation boundary requires
them. `byo-types` and `byo-net` are deliberately absent.

## Intentionally deferred

- QR analysis, image decoders and fuzz targets;
- Tauri and all other graphical user interfaces;
- platform-specific integrations;
- archive/document content parsing, metadata extraction and cryptographic
  signature verification;
- HTTP requests, redirect resolution, reputation services, and uploads;
- packaging, installers, releases, and mobile work.
