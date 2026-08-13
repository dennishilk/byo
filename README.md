# BYO — Before You Open

> **Inspect links, QR codes and files before trusting them.**

BYO is a planned privacy-first, open-source preflight inspector for files, links and QR codes. It is intended to help people understand what something is, where it leads and which properties deserve attention **before** they decide whether to open or trust it.

## Project status

```text
Project status: PRE-ALPHA

Architecture and MVP scope are currently being designed.
No production release is available yet.
```

Nothing in this repository should currently be treated as a finished or tested security product.

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

## Planned inspection areas

The following are design goals, not completed features:

- file type and extension comparison;
- SHA-256 hashing and basic executable detection;
- suspicious or double filename extensions;
- URL parsing, normalization and tracking-parameter review;
- Punycode and internationalized-domain visibility;
- redirect inspection through an explicit online action;
- QR-code decoding without opening its contents;
- a shared, explainable finding model.

More advanced formats, signature validation, archive inspection, metadata extraction and optional reputation services will be evaluated separately and will not be presented as implemented before they are built and tested.

## Architecture under evaluation

The current preferred direction is:

- a reusable analysis core written in Rust;
- a first-class CLI using the same core;
- a desktop interface evaluated with Tauri 2;
- narrow native adapters only where operating-system integration requires them.

The architecture and the exact v0.1 scope are still being assessed. No structure or framework choice is considered final until that plan is reviewed.

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
