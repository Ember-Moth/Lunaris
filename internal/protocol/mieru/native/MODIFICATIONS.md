# Polaris modifications to sing-mieru

sing-mieru is a Polaris port of enfein/mieru, reworked into the sing-* module
interface. It is not a SagerNet project; the sing-* name follows the
convention of this directory. This file records what Polaris changed and when,
as section 5(a) of the GNU GPL version 3 requires for modified copies.

- Original project: https://github.com/enfein/mieru (Copyright mieru authors)
- Original license: GPL-3.0-or-later (full text in `LICENSE`)
- Ported from: v3.34.0 (`1532c85cc8ca08dff469326f35a3f027697c6950`)
- Ported into Polaris: 2026-07-16
- Modified by: Polaris contributors

On 2026-08-28 the adapted mieru engine was replaced by a native
implementation of the Mieru v3 wire protocol; a line comparison finds no code
copied from mieru in the current files. Wire compatibility is tested against
the official mieru v3 client in the root module.

## Changes

Entries are oldest first. Each entry reads `YYYY-MM-DD: summary; files`, with
paths relative to this directory. Append new entries at the end of this list.

- 2026-07-16: Imported as a trimmed adaptation of enfein/mieru v3.34.0: kept the wire engine under `internal/core` with its upstream headers, removed the CLI, RPC control plane, SOCKS server, protobuf metrics and application configuration, and added a sing handler adapter; `handler.go`, `packet.go`, `server.go`, `types.go`, `users.go`, `internal/core/`.
- 2026-07-16: Required sing from the local workspace module; `go.mod`, `go.sum`.
- 2026-07-17: Marshalled session metadata into reused buffers and added a payload slab for segments, with tests; `internal/core/protocol/metadata.go`, `internal/core/protocol/payload_slab.go`, `internal/core/protocol/segment.go`, `internal/core/protocol/session.go`, `internal/core/protocol/underlay_packet.go`, `internal/core/protocol/underlay_stream.go`.
- 2026-08-22: Updated module requirements for Go 1.27; `go.mod`, `go.sum`.
- 2026-08-23: Added a stateless packet decryptor, a source-local user cache and admission limits for high user counts, with tests; `internal/core/cipher/`, `internal/core/protocol/`, `server.go`, `types.go`, `users.go`.
- 2026-08-28: Replaced the adapted upstream engine with a native implementation and removed all enfein/mieru code; `mieru.go`, `native/`, `README.md`, `go.mod`, `go.sum`.
- 2026-10-29: Moved the module path from `github.com/Anti-EntropyTech/sing-mieru` to `github.com/perfect-panel/sing-mieru` and updated the imports of its own packages; `go.mod`, `mieru.go`.

- 2026-11-01: Ported into Lunaris from Polaris `56d52fb44958ef3cc2a7fb841cd240f8206234b2`. Removed module-level binding from the runtime path; added managed socket entry points, per-session contexts, carrier/handshake admission, bounded payload accounting, receive-window backpressure, dynamic read deadlines and cleanup tests. Source lives in `internal/protocol/mieru/native`; no enfein/mieru application runtime is linked. Modified by Lunaris contributors.
