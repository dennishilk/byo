# BYO — Before You Open

> **Inspect links, QR codes and files before trusting them.**

BYO is a privacy-first, open-source preflight inspector for files and URLs, with
QR-code inspection planned for a later milestone. It helps people understand
what something appears to be and which observable properties deserve attention
**before** they decide whether to open or trust it.

## Project status

```text
Project status: PRE-ALPHA

An initial working offline CLI is available for development and testing.
No production release is available yet.
```

Nothing in this repository should be treated as a finished security product.
The current implementation is PRE-ALPHA and cannot determine whether an input
is safe.

## The problem

Links can hide their final destination, QR codes are often opened before their contents are shown, and filenames do not always describe what a file really contains. Existing security tools may give a verdict without clearly explaining the underlying facts.

BYO aims to provide a calm, transparent inspection step:

- identify what was supplied;
- show relevant technical facts and warning signs;
- explain findings in understandable language;
- let the user make the final decision.

BYO is not intended to become a traditional antivirus product or malware sandbox.

## Core principles

- **Never execute an inspected file.**
- **Never automatically open an inspected link or QR-code destination.**
- Perform as much analysis as possible locally and offline.
- Do not upload files or hashes without an explicit, informed choice.
- Keep network activity visible and controllable.
- Clearly separate observed facts from interpretation.
- Avoid absolute labels such as “SAFE” or “100% secure.”
- Provide a simple view without hiding useful technical detail.

BYO can identify properties and warning signs, but it cannot guarantee that a file, link or QR code is safe.

## What currently works

The PRE-ALPHA CLI currently performs these deterministic offline checks:

- read-only regular-file inspection with a 64 KiB header window;
- fixed-buffer streaming SHA-256 hashing;
- common file-header recognition for PE, ELF, Mach-O, PDF, ZIP, PNG, JPEG,
  GIF, gzip, 7z, RAR, WebP and script shebangs;
- filename extension structure, executable-style double extensions and
  Unicode/control-character visibility;
- explainable extension-versus-header comparisons, including ZIP-container
  exceptions for formats such as DOCX;
- standards-based URL parsing without navigation or network access;
- credential-presence reporting with password redaction;
- ASCII/Punycode and Unicode hostname visibility;
- active/local/custom scheme visibility and conservative tracking-parameter
  detection;
- human-readable reports and structured PRE-ALPHA JSON.

Observations, findings and limitations are separate report concepts. Findings
use only `Info`, `Attention` and `Warning`; BYO produces no numeric risk score
and no absolute verdict.

## Try the development CLI

```bash
cargo run -p byo-cli -- file ./something.pdf
cargo run -p byo-cli -- url 'https://example.com/path?utm_source=test'
cargo run -p byo-cli -- --json url 'https://xn--bcher-kva.example/'
```

`byo file` opens only a selected regular file, read-only. `byo url` parses the
provided text locally. Neither command launches its input.

## Current limitations

M1 does not perform full format validation, archive extraction, Office/PDF
content parsing, signature verification, QR decoding, redirect resolution,
reachability checks or reputation lookup. Header signatures are evidence of a
possible type, not proof that an entire file is valid. Robust mixed-script and
visual-confusable hostname detection is also deferred.

QR decoding, graphical interfaces and online functionality remain design goals,
not completed features. More advanced formats, signature validation, archive
inspection, metadata extraction and any optional reputation service require
separate milestones and threat-model updates.

## Architecture

The current implementation uses:

- a platform-neutral `byo-core` Rust library;
- a thin `byo-cli` caller for paths, terminal output and JSON.

Tauri, desktop/mobile code and platform integrations are not present in M1.
Tauri 2 and narrow native adapters remain possible future directions, subject
to separate review.
See [the architecture](docs/architecture.md), [threat model](docs/threat-model.md)
and [M1 scope](docs/m1-offline-inspection.md) for the exact boundaries.

## Long-term platform direction

Planned platforms are:

- Windows
- Linux
- macOS
- Android
- iOS
- CLI

Initial releases will deliberately target a smaller subset. A platform will only be listed as supported after it has been built and tested there.

## Security posture

BYO itself will process potentially hostile input. Defensive parsing, resource limits, recursion limits, archive-bomb protections, strict network timeouts, malformed-input tests and future fuzzing therefore belong to the architecture from the beginning.

The project will document both what an inspection establishes and what remains unknown.

## License

BYO is released under the [MIT License](LICENSE).

*Also acceptable: Bring Your Own Beer.*
