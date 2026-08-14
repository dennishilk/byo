# BYO v0.1 Threat Model

Status: foundation security requirements. No analyzers are implemented yet.

## Security objective

BYO processes potentially hostile names, bytes, URLs, and images to help a user
inspect them without trusting them. The primary objective is that inspection
does not execute or open the subject and does not turn hostile input into a
command, navigation, uncontrolled allocation, or misleading safety verdict.

BYO can identify properties and warning signs. It cannot guarantee that an
input is safe, benign, complete, or correctly classified.

## Trust boundaries

### User and local environment

The user chooses an input and controls whether BYO is invoked. The selected
input, its filename, its path, its metadata, and every byte read from it are
untrusted. Clipboard and drag-and-drop text will also be untrusted when those
interfaces are added.

The operating system and the BYO executable itself are assumed not to be
already compromised. BYO is not a sandbox for the operating system, kernel,
filesystem driver, or image codec outside its process.

### Caller boundary

The CLI and future UI/platform adapters receive paths or text, apply top-level
limits, open read-only handles, and pass bounded input to `byo-core`. They must
not invoke a default application, shell, interpreter, preview handler, or
platform thumbnailer as part of inspection.

### Core boundary

`byo-core` treats all supplied data as hostile. It returns structured
observations, interpretations, limitations, and errors. It has no authority to
perform operating-system integration or network access.

### Future network boundary

A future network module is explicitly outside the v0.1 trust boundary. It will
require separate approval and a dedicated threat model covering SSRF, DNS
rebinding, redirects, private address ranges, proxy behavior, cookies,
credentials, response limits, TLS, and privacy disclosure.

## Non-negotiable v0.1 exclusions

v0.1 performs no:

- HTTP requests;
- redirect resolution;
- reputation lookup;
- uploads;
- hash submission;
- shell execution;
- opener invocation;
- sidecars.

It also performs no automatic navigation and never launches inspected files,
decoded QR destinations, or URL targets.

## Threats and required controls

The controls below are requirements for later analyzer milestones. Their
presence in this document does not claim that the analyzers already exist.

### Hostile filenames

Filenames may contain terminal control sequences, bidirectional text controls,
newlines, device-like names, separators, reserved names, or bytes that are not
valid Unicode on the current platform.

Required controls:

- treat a filename as data, never a format string, command, or path fragment;
- preserve enough original representation for accurate reporting;
- create a separate escaped display representation;
- never use a display-normalized filename to reopen a file;
- do not place raw hostile names into logs or terminal output without escaping.

### Unicode control and invisible characters

Bidirectional overrides, isolates, zero-width characters, variation selectors,
non-breaking spaces, and confusable characters can make displayed content
differ from its logical sequence.

Required controls:

- detect relevant control and invisible code points;
- show their code points and positions;
- distinguish a factual presence observation from a warning interpretation;
- do not rewrite the actual filename or URL silently;
- avoid claiming that every non-ASCII character is malicious.

### Malformed and polyglot files

A file may be truncated, internally inconsistent, valid under multiple format
interpretations, or designed to trigger parser edge cases. A magic signature is
evidence, not proof that the full file is valid.

Required controls:

- parsers return explicit errors rather than positive classifications;
- record multiple compatible observations when appropriate;
- keep format detection separate from full-format validation;
- use bounded reads and checked arithmetic;
- test truncated, contradictory, and deliberately malformed fixtures;
- never pass the file to an external viewer to confirm its type.

### Misleading extensions

Extensions may disagree with content or use deceptive compounds such as a
document-looking component followed by an executable extension. Legitimate
compound extensions also exist.

Required controls:

- report the claimed extension and content-derived observations separately;
- use explicit rules for dangerous trailing extensions;
- do not flag every multi-dot filename as malicious;
- explain mismatches without converting them into a malware verdict.

### Oversized inputs

Very large files can exhaust time, memory, disk cache, or user patience even if
parsing is otherwise correct.

Initial limit policy for implementation and testing:

- inspect metadata before allocating from a declared length;
- read at most 64 KiB for initial signature/header detection;
- stream hashes with a fixed-size buffer rather than loading whole files;
- default to refusing non-streaming inspection above 1 GiB;
- make cancellation and progress reporting caller concerns when introduced;
- use checked conversions between file sizes and allocation sizes.

These values are upper bounds, not promises that every input below them can be
fully analyzed.

### Decompression and decoder-style resource exhaustion

Compressed containers, recursive archives, and crafted decoders can cause high
expansion ratios, deep nesting, excessive allocations, or CPU exhaustion.

Required controls:

- archive extraction and recursive decompression are outside v0.1;
- no archive member is written to disk during inspection;
- future archive work requires limits for nesting, entry count, declared and
  actual size, total expanded bytes, compression ratio, and processing time;
- parser allocation limits must be enforced independently of container claims.

### Malformed URLs

URLs may be syntactically invalid, use unexpected schemes, contain ambiguous
authority syntax, unusual ports, encoded delimiters, or parser differentials.

Required controls:

- retain the original input separately from any parser serialization;
- treat parse failure as an explicit result;
- use one reviewed standards-based parser rather than ad hoc splitting;
- never navigate to a parsed URL as part of analysis;
- do not infer reachability, ownership, or safety from successful parsing.

### Punycode and Unicode hostnames

Internationalized hostnames can be legitimate while still containing visually
confusable or mixed-script labels.

Required controls:

- show both the ASCII/Punycode and Unicode representations when available;
- identify mixed-script or confusable properties as explainable findings;
- preserve parser errors and conversion limitations;
- avoid blanket warnings for all internationalized domains;
- never claim that visual similarity proves impersonation.

### Credentials embedded in URLs

URLs may contain usernames and passwords in their authority component. Showing,
copying, logging, or later transmitting them can disclose secrets.

Required controls:

- report the presence of embedded credentials;
- redact password material in ordinary presentation and logs;
- do not submit credential-bearing URLs to any external service;
- require an explicit action before copying an unredacted original;
- never use embedded credentials for a network request in v0.1.

### Malicious QR images and payloads

QR source images can exploit decoder bugs or declare extreme dimensions. A
decoded payload can contain control characters, a dangerous URL, shell-looking
text, or arbitrary binary data.

Initial limit policy for implementation and testing:

- encoded QR image input: at most 32 MiB;
- maximum width: 8,192 pixels;
- maximum height: 8,192 pixels;
- maximum decoded pixel count: 32 megapixels;
- maximum accepted decoded QR payload: 8 KiB;
- dimensions and pixel multiplication use checked arithmetic;
- decoder buffers are bounded independently of encoded file size.

Required controls:

- inspect image metadata and dimensions before full decode where supported;
- configure strict decoder limits and reject unsupported limit enforcement;
- render decoded payloads as escaped data;
- never open, execute, or automatically copy a decoded payload;
- pass URL-like payloads only to the offline URL analyzer after that analyzer is
  implemented;
- report undecodable, multiple, truncated, and binary payloads explicitly.

### Parser panics

Malformed input may reach assumptions that produce a panic in BYO or a parser
dependency.

Required controls:

- analysis APIs return `Result`-style errors;
- avoid `unwrap`, `expect`, unchecked indexing, and unchecked arithmetic on
  hostile-input paths;
- add regression fixtures for every discovered panic;
- review parser dependencies and their enabled features;
- add fuzzing in a later approved milestone before expanding complex formats;
- never interpret a crashed or aborted parser as a clean result.

Rust memory safety reduces some bug classes but does not prevent logic errors,
panics, denial of service, or unsafe code inside dependencies.

### Memory exhaustion

Hostile lengths, dimensions, counts, or recursive structures may cause large
allocations without requiring a conventional parser bug.

Required controls:

- every allocation derived from input has an explicit upper bound;
- prefer streaming and fixed-size buffers;
- use checked arithmetic before allocating;
- avoid collecting unbounded iterator results;
- cap the number and total size of observations and findings;
- return a limitation when a limit prevents complete inspection.

### Path handling

Paths may reference symlinks, network filesystems, special files, devices,
changing files, or names with platform-specific semantics. Metadata can change
between checks and reads.

Required controls:

- open only user-selected inputs and use read-only access;
- reject directories and unsupported special-file types by default;
- never concatenate an untrusted path into a shell command;
- do not treat canonicalization as proof of safety;
- report when metadata changes during inspection where detectable;
- do not create adjacent temporary files or extract content beside the input;
- keep path resolution in the caller/platform layer, outside `byo-core`.

### Accidental execution or opening

The most direct failure would be invoking the subject while attempting to
inspect it.

Required controls:

- no shell, process, opener, preview-handler, or sidecar dependency;
- no “open anyway” action in v0.1;
- no automatic URL navigation;
- no use of the operating system's registered file handlers for analysis;
- UI and CLI language must distinguish copying from opening;
- integration tests must assert that analysis paths have no launch behavior
  once analyzers exist.

## Findings and communication risks

A technically correct observation can still harm users if presented as a
guarantee. The report model must therefore:

- keep observations separate from rule-based findings;
- use only `Info`, `Attention`, and `Warning` severity;
- include limitations and unsupported checks;
- avoid numeric risk scores;
- never output an absolute `SAFE` verdict;
- distinguish “no obvious warning signs found” from “safe.”

## Deferred security work

The following work is intentionally deferred with the associated analyzers:

- concrete report and error types;
- parser selection and dependency review;
- malformed-input fixture corpus;
- property tests and fuzz targets;
- platform-specific signature APIs;
- archive and document parsing;
- UI capability configuration;
- a separate network threat model.

