# Fixtures

M1 tests construct small deterministic byte fixtures in memory or in isolated
temporary directories. The synthetic inputs cover common header signatures,
truncation, mismatches and CLI file handling without storing executable
programs or live malware.

Future checked-in fixtures must be safe to store publicly, must not contain live
malware or secrets, and must document whether they are valid, malformed,
truncated or synthetic.

Large generated files, archives, build outputs, and third-party samples do not
belong in the repository.
