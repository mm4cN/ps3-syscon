# PS3 SYSCON Diagnostic

An early, MIT-licensed desktop utility for safely inspecting a PlayStation 3
SYSCON serial connection. The MVP provides:

- serial-port enumeration with FTDI/FT232 identification;
- profile-selected 8-N-1 serial connection and a scrollable, nonblocking terminal;
- raw transmit controls that are **disabled by default** and require explicit opt-in;
- an offline mock connection for development without hardware;
- one-click CXR, CXRF, and SW authentication with configurable retry;
- an authenticated, read-only error-history action;
- a profile-aware motherboard guide linking to sourced UART test-pad photographs;
- conservative decoding of documented error-code suffixes;
- timestamped, sortable error cards and readable TXT export;
- unit tests for parsing, decoding, export, and port classification.

## Important safety and scope notes

Connecting to a port starts a passive reader and sends no bytes. `Auth` runs the
selected profile's documented challenge-response, with bounded retry. `Get
errors` is enabled only after authentication and exposes no clear/write
operation. This implementation is covered by protocol fixtures and a NIST AES
known-answer test, but must still be validated against each supported hardware
variant before being described as universally compatible. Raw terminal
transmission remains available only after explicit opt-in. While manual mode is
enabled, the automatic `Auth` and `Get errors` controls are paused to avoid
mixing manual traffic with protocol operations.

Do not connect RS-232 voltage levels directly to a PS3 UART. Use a 3.3 V TTL
adapter, cross TX/RX, connect GND, and **do not connect adapter VCC to the PS3**.
Verify the board-specific pads before soldering.

The decoder is a reference aid, not a parts-replacement verdict. Meanings are
limited to entries explicitly listed by the PS3 Developer Wiki. Unknown codes
remain unknown. Context, board revision, power-on step, and corroborating
measurements still matter.

## Build and run

Install a current stable Rust toolchain, then run:

```sh
cargo run -p syscon-gui
```

Run all tests:

```sh
cargo test --workspace
```

The repository's `CI` GitHub Actions workflow runs formatting, tests, Clippy,
and a hardware-only build on Linux, macOS, and Windows for every push and pull
request. It can also be started manually. Each job uploads its hardware-only
release executable as a build artifact retained for 14 days; the mock feature
is intentionally omitted from those release binaries.

On Linux, serial-device access may require membership in the distribution's
serial-port group (often `dialout`).

## Workspace layout

- `syscon-core`: port discovery and threaded serial/mock terminal transport.
- `syscon-diagnostics`: strict error-code parsing, sourced lookup data, and TXT report formatting.
- `syscon-gui`: the `egui`/`eframe` desktop application.

## Serial defaults

The UI starts at 57,600 baud, 8 data bits, no parity, one stop bit, and no flow
control. Selecting CXR or SW chooses 57,600 baud; CXRF chooses 115,200 baud.
Opening a connection does not transmit an initialization command.

Profile guidance follows the motherboard/SYSCON family: COK, SEM, and DIA
boards use Mullion (start with CXR; CXRF is the advanced internal/DIAG mode),
while VER, DYN, SUR, JTP, JSD, KTE, and later Super Slim boards use Sherwood
(SW). The motherboard marking takes precedence over the console shell model.

## UI overview

The upper part of the window is split into two always-visible panels. `Connection`
contains the SYSCON profile, suggested motherboard families, serial-port picker,
retry settings, and the `Auth`/`Get errors` actions. `Board connection guide`
contains a motherboard picker, profile guidance, a sourced test-pad link, and
the 3.3 V TTL wiring warning.

The terminal and decoded-error list have fixed-height, scrollable views, so
incoming data does not continuously enlarge the window. The terminal state
indicator uses gray for disconnected, light red for offline mock, yellow for
idle, green for an operation in progress, orange for manual mode, and light blue
for an authenticated connection. A separate orange `Manual mode` indicator sits
beside the raw-transmit checkbox.

## Authentication and read-only history

- `CXR`: framed external-mode `AUTH1`/`AUTH2`, then `ERRLOG GET 00` through
  `ERRLOG GET 1F`.
- `CXRF`: `scopen`, challenge-response, then `errlog`.
- `SW`: checksummed plaintext framing, challenge-response, then `errlog`.

All transmitted frames and received responses are appended to the terminal.
The retry count and delay are configurable. The mock mode deliberately fails
its first authentication attempt and succeeds on the second, exercising the
retry and UI state without hardware.

Error-history records retain the raw SYSCON clock value and display its
converted date and time. `FFFFFFFF` is shown as unavailable; dates around
`2005-12-31` can indicate that the console clock was not configured rather
than the true failure date. The decoded-error list defaults to newest-first;
the UI can switch back to the original SYSCON order. Entries without a valid
timestamp stay at the end in their device-provided order.

`Export` writes the list in the currently selected display order to
`syscon-diagnostics.txt` by default. The path field is editable. Each line uses
this format:

```text
<index> <YYYY-MM-DD HH:MM:SS or N/A> <code> <title or unknown>
```

For example:

```text
01 2025-02-17 04:23:52 A0801001 Power CELL
```

The mock transport is a Cargo feature enabled by default for development. A
final hardware-only build can omit the mock worker and its UI button entirely:

```bash
cargo build --release -p syscon-gui --no-default-features
```

Commands that mutate EEPROM, clear logs, control power/fans, or change voltage
are not present in the typed protocol API.

## Connection diagrams

The right-hand `Board connection guide` panel links to board photographs from
the public reference collection. Archival copies of all eight photographs live
under `assets/connection-guides/images`, with pinned source URLs and SHA-256
digests in `assets/connection-guides/manifest.json`.

The photographs are third-party material and are **not covered by this
project's MIT licence**. Their individual reuse licence was not stated in the
upstream repository when archived; see `assets/connection-guides/README.md`
before redistributing them.

## Sources

Decoder entries and format notes cite:

- [PS3 Developer Wiki: Syscon Error Codes](https://www.psdevwiki.com/ps3/Syscon_Error_Codes)
- [PS3 Developer Wiki: Error Codes](https://www.psdevwiki.com/ps3/Error_Codes)
- [db260179/ps3syscon reference implementation](https://github.com/db260179/ps3syscon/blob/81cc667de930d489aa6ea9b4e87d0197d119511c/Linux/ps3_syscon_uart_script.py)
- [Board connection-point collection](https://github.com/db260179/ps3syscon/tree/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points)

These are community-maintained sources. The UI links every known decoded entry
to its source. Contributions should preserve provenance and avoid turning
unconfirmed repair anecdotes into definitive diagnoses.

## Roadmap

- Capture and document serial settings against known hardware.
- Validate CXR, CXRF, and SW flows on a documented hardware matrix.
- Add captured, anonymized UART transcripts as regression fixtures.
- Add model/board-aware diagnostic context.

## License

MIT. See [LICENSE](LICENSE).

