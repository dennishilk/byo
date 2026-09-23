# QR fixtures

These files are deterministic, synthetic and harmless. They were generated
locally by a temporary Rust helper using `qrcode` 0.14.1 and `image` 0.25.6.
Each QR uses error-correction level L, a four-module quiet zone, five grayscale
pixels per module, black modules and a white background. PNG is lossless; the
JPEG case uses `image`'s default JPEG encoder. The generator performed no
network access.

| File | Construction or payload |
|---|---|
| `text.png` | `Hello from BYO` |
| `url.png` | `https://example.com/path` |
| `url.jpg` | `https://example.com/jpeg` |
| `tracking.png` | `https://example.com/path?utm_source=qr&id=1` |
| `credentials.png` | example.com URL with the fake sentinel password `BYO_SECRET_SENTINEL` |
| `punycode.png` | `xn--bcher-kva.example` URL with a tracking parameter |
| `active-scheme.png` | `javascript:alert(1)` stored as inert QR data |
| `wifi.png` | conventional Wi-Fi payload with fake sentinel password `BYO_WIFI_SECRET_SENTINEL` |
| `controls.png` | text containing a newline and terminal ESC sequence |
| `binary.png` | five raw bytes including invalid UTF-8 and ESC |
| `near-limit.png` | 2,900 ASCII `A` bytes, near the practical capacity of one standard QR |
| `multiple.png` | two separately rendered QR symbols composed on one white raster |
| `over-limit-multiple.png` | nine QR symbols composed on one white raster; the decoder exposes its internal maximum of eight |
| `no-code.png` | uniform gray 128 × 96 PNG |
| `corrupt-qr.png` | a valid generated symbol with a large data region erased |
| `truncated.png` | first 465 bytes of `text.png` |
| `truncated.jpg` | first 32 bytes of `url.jpg` |

The two sentinel strings are test-only non-secrets. Tests prove they do not
appear in human or JSON reports. Oversized encoded input is represented by a
temporary sparse file, while width and pixel-limit tests modify the IHDR
dimensions and recompute its CRC in memory. No large fixture is committed.
