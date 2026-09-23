# M1 Offline Inspection Pipeline

Status: implemented on the M1 development branch; PRE-ALPHA.

M1 is BYO's first useful end-to-end pipeline. It turns a user-selected regular
file or supplied URL string into a deterministic report while keeping the
subject inert and local.

## Implemented scope

`byo file <PATH>`:

- rejects directories and unsupported special file types;
- opens the selected regular file read-only;
- records filename extension structure and relevant Unicode/control characters;
- identifies deceptive document/media-plus-executable extension patterns;
- computes SHA-256 with a fixed 64 KiB streaming buffer;
- retains no more than the first 64 KiB for common header signatures;
- compares recognized signatures with compatible filename extensions;
- treats ZIP-backed formats such as DOCX, XLSX, PPTX, JAR and APK as containers
  rather than blindly declaring a mismatch;
- reports metadata changes detected around the read.

`byo url <URL>`:

- uses the WHATWG-oriented `url` parser and performs no navigation;
- reports scheme, credential presence, host, port, path, query and fragment
  presence;
- redacts authority passwords from human and JSON reports;
- shows ASCII/Punycode and Unicode hostname forms;
- identifies IP-literal hosts and active/local/non-web schemes;
- recognizes a conservative list of common tracking parameters;
- may show a separate derived URL suggestion without those parameters while
  preserving the original input internally.

Both commands emit observations, referenced findings, limitations and report
metadata. `--json` serializes the PRE-ALPHA structured model. The schema version
is explicit but is not compatibility-stable yet.

## Limits

| Input or operation | M1 limit |
|---|---:|
| Filename analysis | 4096 bytes |
| Individually reported filename controls/invisibles | 64 |
| Header/signature window | 64 KiB |
| Non-streaming file inspection | 1 GiB |
| URL input | 64 KiB |
| URL path shown in a field | 512 Unicode scalars |
| URL query pairs inspected | 256 |
| Distinct query names retained | 64 |
| URL controls/invisibles individually reported | 32 |

SHA-256 remains streaming and does not require a whole-file allocation. When a
limit prevents a configured check, the report becomes `Partial` or `Failed`
and records a limitation.

## Dependencies and rationale

- `sha2` 0.10.9: RustCrypto SHA-256 implementation, used incrementally with
  unnecessary default features disabled.
- `url` 2.5.0: standards-based URL parsing instead of hand-written splitting.
- `idna` 0.5.0: UTS-46/Punycode display conversion. This version pairs with the
  declared Rust 1.77.2 minimum and avoids a much larger newer ICU graph.
- `serde`: serialization derives for the typed report model.
- `serde_json`: CLI-only JSON serialization.

None is an HTTP, DNS, async-runtime, process-launch, browser or telemetry
dependency.

## Explicit non-goals and known limitations

M1 does not validate complete PDF, PE, ELF, Mach-O, image or archive structures.
It does not extract containers, inspect Office contents, verify signatures,
decode QR images, evaluate domain confusables, resolve redirects, test
reachability or query reputation services. A recognized magic value is evidence
of a likely format, not proof that the full file is valid or benign.

M1 performs no HTTP request, DNS request, upload, hash submission, shell
execution, opener invocation, sidecar execution or automatic navigation. It
cannot determine whether a file or URL is safe.
