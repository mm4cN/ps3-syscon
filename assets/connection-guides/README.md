# PS3 UART connection-guide assets

This directory contains archival copies of the eight upstream board
photographs used by the connection guide. They are stored locally so the
reference material remains available if the upstream GitHub repository moves
or disappears.

The photographs are third-party material and are **not covered by this
project's MIT licence**. The upstream repository did not state a separate
licence for the photographs when they were archived. Do not reuse or
redistribute them under the assumption that they are MIT-licensed.

`manifest.json` records the pinned upstream commit, original URL, local path,
and SHA-256 digest for every file. The images themselves live under `images/`.

Source collection:

- <https://github.com/db260179/ps3syscon/tree/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points>
- <https://www.psdevwiki.com/ps3/Syscon_Hardware>

Safety: use a 3.3 V TTL adapter, cross TX/RX, connect GND, and do not connect
the adapter VCC pin to the PS3. Verify the exact motherboard marking before
soldering. DIAG handling differs by board and mode.

