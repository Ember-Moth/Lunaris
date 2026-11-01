# Polaris modifications to sing-shadowsocksr

sing-shadowsocksr is a Polaris port of ShadowsocksR, reworked into the sing-*
module interface. It is not a SagerNet project; the sing-* name follows the
convention of this directory. This file records what Polaris changed and
when, as section 5(a) of the GNU GPL version 3 and section 4(b) of the Apache
License 2.0 require for modified files.

- Original projects:
  - https://github.com/shadowsocksr-backup/shadowsocksr (Python; Copyright 2015-2015 breakwa11), Apache-2.0 (`LICENSE-Apache-2.0`)
  - https://github.com/ShadowsocksR-Live/shadowsocksr-native (C; Copyright 2015-2016 Break Wa11 and ShadowsocksR contributors), GPL-3.0-only (`LICENSE`)
  - https://github.com/wyx2685/VNet-SSR (Go), GPL-3.0, used until 2026-08-28; no VNet-SSR code remains
- Ported from: shadowsocksr-backup `db6629a1307ed38eb507bd926ad1503e90bc4eb1`, `a440a726f6d3a25fe2eeac94786580f462a314a7` and `1fe6e89c0752458b18acc343899323a88c44015d`; shadowsocksr-native 0.9.4 (`227127c4bc5a6555e0556693d084c96860e75b5e`); VNet-SSR `d00ae73b45defec5703d449962680cdc006755b7`
- Ported into Polaris: 2026-07-16 (in `sing-shadowsocks/shadowsocksr`), moved to this module 2026-08-28
- Modified by: Polaris contributors

Four files remain Apache-2.0 and one GPL-3.0-only (see `NOTICE`); the rest is
GPL-3.0-or-later, so the module as a whole is distributed under GPL-3.0-only.

## Changes

Entries are oldest first. Each entry reads `YYYY-MM-DD: summary; files`, with
paths relative to this directory. Append new entries at the end of this list.

- 2026-07-16: Imported the VNet-SSR Go port behind a Polaris sing adapter as `sing-shadowsocks/shadowsocksr` (its later changes are listed in `pkg/sagernet/sing-shadowsocks/MODIFICATIONS.md`).
- 2026-07-31: Translated verify_simple, verify_sha1, auth_simple, auth_sha1, auth_sha1_v2, auth_sha1_v4 and tls1.0_session_auth from shadowsocksr-backup, and the auth_chain_c-f tables and padding from shadowsocksr-native, into the earlier adapter at `sing-shadowsocks/shadowsocksr/upstream/obfs` (`verify.go`, `obfs_tls10.go`, `auth_chain.go`).
- 2026-08-24: Optimised authentication and UDP paths of that adapter.
- 2026-08-28: Rewrote SSR natively as this module; the derived code above was carried into `protocol/verify.go`, `protocol/legacy_auth.go`, `protocol/legacy_helpers.go`, `obfs/tls10.go` and `protocol/auth_chain.go`, and the VNet-SSR code was dropped; all files.
- 2026-08-28: Added SIP004 AEAD ciphers and a fixed-memory salt replay window, with tests; `cipher/`, `config.go`, `conn.go`, `packet.go`, `protocol/auth_aes.go`, `protocol/auth_chain.go`, `replay/`, `README.md`.
- 2026-08-28: Reused authentication working state and HMAC digests across frames, with tests; `protocol/auth_aes.go`, `protocol/auth_chain.go`, `protocol/legacy_mac.go`.
- 2026-08-28: Optimised the obfs hot paths, with tests; `obfs/http.go`, `obfs/obfs.go`, `obfs/sha1.go`, `obfs/tls10.go`, `obfs/tls_ticket.go`.
- 2026-09-11: Pinned the sing requirement to the workspace version; `go.mod`.
- 2026-10-29: Restored the upstream copyright and license headers of the derived files, marked `protocol/auth_chain.go` GPL-3.0-only, and added the license texts and attribution; `LICENSE`, `LICENSE-Apache-2.0`, `NOTICE`, `README.md`, `obfs/tls10.go`, `protocol/auth_chain.go`, `protocol/legacy_auth.go`, `protocol/legacy_helpers.go`, `protocol/verify.go`.
- 2026-10-29: Moved the module path from `github.com/Anti-EntropyTech/sing-shadowsocksr` to `github.com/perfect-panel/sing-shadowsocksr` and updated the imports of its own packages, with tests; `config.go`, `conn.go`, `go.mod`, `obfs/obfs.go`, `protocol/auth_aes.go`, `protocol/auth_chain.go`, `protocol/legacy_auth.go`, `protocol/protocol.go`.

- 2026-11-01: Ported into Lunaris from Polaris `56d52fb44958ef3cc2a7fb841cd240f8206234b2`; rewrote internal import paths, adapted the TCP salt replay window to the ported bounded replay cache, retained borrowed input before buffer release, serialized shared protocol/obfs state independently from network I/O, and accepted bounded 16-bit TLS ticket application records. Added ownership and large-record regressions. Source lives in `internal/protocol/shadowsocksr/wire`. Modified by Lunaris contributors.
