# M2 Bounded Offline QR Inspection

Status: implemented; PRE-ALPHA.

M2 adds a local QR inspection path without changing the M1 trust model. A user
can inspect a regular PNG or JPEG file with `byo qr <PATH>` and receive the same
typed observations, findings, limitations and offline metadata used by the file
and URL analyzers. BYO never launches the image or a decoded payload.

## Commands

```bash
cargo run -p byo-cli -- qr ./qr.png
cargo run -p byo-cli -- qr ./photo.jpg
cargo run -p byo-cli -- --json qr ./qr.png
```

The CLI opens the selected regular file read-only. Directories and special files
are rejected. There are no temporary conversion files, subprocesses, viewer or
opener calls, uploads, HTTP requests or DNS lookups.

## Dependency decision

M2 separates raster decoding from QR extraction:

- `image` 0.25.6, with default features disabled and only `png` and `jpeg`
  enabled, supplies in-process raster decoding and a resource-limit API. This
  pinned release declares an MSRV below the workspace's Rust 1.77.2, while
  newer `image` releases raise their compiler requirement. Its license is
  `MIT OR Apache-2.0`.
- `quircs` 0.10.3 supplies in-process QR detection, multiple-code iteration and
  raw `Vec<u8>` payloads. It does not force QR data through UTF-8. It declares
  Rust 1.68 and uses the MIT license.

`rqrr` was evaluated but its current release requires a compiler newer than the
workspace MSRV and has a larger dependency graph. Older releases were not
chosen because `quircs` more directly satisfies the raw-payload requirement.
Using individual PNG/JPEG crates directly was also considered, but would
duplicate format dispatch and limit plumbing without improving the QR boundary.
No selected production dependency adds HTTP, DNS, an async runtime, browser,
process helper or telemetry.

## Input and allocation limits

| Resource | M2 ceiling |
|---|---:|
| Encoded source image | 32 MiB |
| Width | 8,192 pixels |
| Height | 8,192 pixels |
| Width × height | 32,000,000 pixels |
| Image decoder allocation | 256 MiB |
| Accepted payload per QR | 8 KiB |
| QR candidates processed | 7 |
| Text display | 2,048 Unicode scalar values |
| Binary hexadecimal preview | 256 bytes |

The CLI rejects an oversized declared file before reading and also reads through
a 32 MiB plus one-byte ceiling to detect growth. The core repeats the size
check. It identifies PNG/JPEG from magic bytes, reads dimensions under the image
decoder's allocation limit, uses checked multiplication, applies dimension and
pixel ceilings before full decode, then decodes under both allocation and
dimension limits. A limit hit is a failed or partial analysis with an explicit
limitation; it is never reported as a truncated success.

The QR library's internal candidate inventory is limited to eight grids. BYO's
application bound is seven. If the decoder yields eight, BYO processes seven and
marks the report partial. If an image plausibly contains more than eight, the
decoder may not expose the exact total, which remains an explicit implementation
limitation rather than an exhaustive count claim.

## Payload model

Every processed candidate has a stable one-based index and an independent
result. A detected candidate that cannot be decoded remains present with a
decode limitation. Zero detected codes is a normal factual observation.

A successful payload records its byte length and UTF-8 validity. Valid text is
classified only into obvious forms:

- ordinary text;
- URL-like data;
- `mailto:` email URI;
- `tel:` telephone URI;
- `sms:` or `smsto:` URI;
- conventional `WIFI:` configuration;
- another syntactically obvious custom scheme.

Non-UTF-8 payloads remain binary and receive only a bounded hexadecimal preview.
All human output goes through the centralized terminal escaping function. JSON
serialization additionally escapes invisible and directional control
characters.

## URL reuse and secret handling

Every syntactically obvious scheme is passed to the existing M1 URL analyzer.
The nested typed report therefore preserves its parse result, Punycode/Unicode
host display, tracking-parameter observations, active/local/custom-scheme
findings, limitations and `network_activity=false`. M2 does not contain a
second URL parser or QR-specific URL rules.

The QR display value is taken from the nested URL report's redacted display.
An authority password is never copied into a QR observation, human output or
JSON. The original decoded URL exists only transiently and in the nested
report's non-serialized private original field.

For `WIFI:` data, M2 parses only the authentication type, SSID, password-key
presence and hidden flag within the 8 KiB payload bound and with conventional escaping.
The `P:` value is deliberately skipped and never stored. Reports say only that
a password was present. BYO does not connect to a network or invoke a network
management API.

## Test corpus

`fixtures/qr/` contains small deterministic fixtures for text, PNG/JPEG URLs,
tracking and credential URLs, Punycode, active content, Wi-Fi, controls, binary
data, a practical high-capacity payload, multiple/bounded-multiple codes, no
code, a damaged QR and truncated PNG/JPEG inputs. Dimension and 32 MiB source
limits are generated or patched in tests so large files are not committed.

Regression tests cover secret absence in both renderers, terminal escaping,
raw binary handling, URL-analyzer reuse, malformed inputs, failed candidate
decode, zero/multiple/bounded codes, checked pixel multiplication, dimension and
pixel ceilings, payload rejection and encoded-size preflight.

## Explicit limitations

M2 cannot determine whether a QR payload or destination is safe. Detection can
miss small, distorted, obscured or low-contrast codes, and error correction can
produce no result. Candidate order is decoder order, not visual reading order.
The implementation does not support camera capture, live scanning, QR
generation, automatic copying, structured append, ECI/Shift-JIS conversion,
contact-card parsing, animation semantics or formats other than PNG and JPEG.
It does not isolate codecs in a separate process and cannot prevent every CPU
denial-of-service or third-party parser defect. Fuzzing remains future work.
