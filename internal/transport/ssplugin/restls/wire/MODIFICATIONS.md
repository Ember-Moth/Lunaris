# Polaris modifications to sing-restls

sing-restls is a Polaris port of the RESTLS server transport from
MetaCubeX/Restls-Client-Go, reworked into the sing-* module interface. It is
not a SagerNet project: the `github.com/sagernet/sing-restls` module path only
follows the sing-* convention of this directory, and no SagerNet upstream
exists. This file records what Polaris changed and when.

- Original project: https://github.com/MetaCubeX/Restls-Client-Go (RESTLS by 3andne)
- Original license: BSD-3-Clause (Copyright The Go Authors) and BSD-3-Clause for RESTLS (Copyright 3andne)
- Ported from: v0.1.8 (`a8fa52c83df7e4feec0d94998fb2729f91b2a34a`), now tracking v0.1.9 (`6566c5f8a24420fbaeb27bc74deea2597a30f4a7`)
- Ported into Polaris: 2026-07-16
- Modified by: Polaris contributors

The handshake engine stays in the external module
`github.com/metacubex/restls-client-go`, which is linked rather than copied;
its license texts ship in the release notices bundle under
`LICENSES/modules/github.com/metacubex/restls-client-go/` and in
`LICENSES/BSD-3-Clause/RESTLS.txt`. The code in this directory is the sing
adapter, under the BSD-3-Clause license in `LICENSE`.

## Changes

Entries are oldest first. Each entry reads `YYYY-MM-DD: summary; files`, with
paths relative to this directory. Append new entries at the end of this list.

- 2026-07-16: Added the RESTLS server adapter with sing extended stream I/O and TLS record tracking, with tests; `conn.go`, `record.go`, `server.go`.
- 2026-07-16: Required sing from the local workspace module; `go.mod`, `go.sum`.
- 2026-07-24: Renamed the copyright holder from Star Node contributors to Polaris contributors; `LICENSE`, `README.md`.
- 2026-08-22: Moved to Restls-Client-Go v0.1.9 and updated the other module requirements for Go 1.27; `go.mod`, `go.sum`.

- 2026-11-01: Moved the adapter into Lunaris as an internal package, with no local module replacement. Preserved the external Restls-Client-Go v0.1.9 handshake engine; added SPDX headers and retained the BSD license. Carrier factories own handshake deadlines, target lifetime and secret references.
