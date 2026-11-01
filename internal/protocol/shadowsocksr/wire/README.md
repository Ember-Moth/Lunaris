# sing-shadowsocksr

> Origin: a Polaris port of ShadowsocksR ([shadowsocksr-backup](https://github.com/shadowsocksr-backup/shadowsocksr), Apache-2.0, and [shadowsocksr-native](https://github.com/ShadowsocksR-Live/shadowsocksr-native), GPL-3.0-only), reworked into the sing-* module interface. It is not a SagerNet project; see `MODIFICATIONS.md` and `NOTICE`.

Native, server-focused ShadowsocksR implementation for Polaris.

This module implements the SSR wire protocol directly on top of Go's standard
cryptography packages and `sing` buffers/connections. It does not embed an
upstream application or use global protocol registries.

Supported classic stream ciphers:

- none
- AES-128/192/256-CTR
- AES-128/192/256-CFB
- RC4-MD5
- ChaCha20 and ChaCha20-IETF

Supported SIP004 AEAD ciphers:

- AES-128/192/256-GCM
- ChaCha20-IETF-Poly1305 (`chacha20-poly1305` is accepted as an alias)
- XChaCha20-IETF-Poly1305

SIP004 is implemented as the cipher layer of the existing SSR pipeline:
`protocol/auth -> cipher -> obfs`. TCP uses incremental authenticated length
and payload records with automatic 0x3fff-byte chunking; UDP uses one random
salt and one independent AEAD payload per datagram. Authenticated TCP salts are
checked against a fixed-memory replay window. Shadowsocks 2022 methods are not
SIP004 and remain unsupported by this SSR module.

Supported protocols:

- origin
- verify_simple, verify_sha1
- auth_simple, auth_sha1, auth_sha1_v2, auth_sha1_v4
- auth_aes128_md5, auth_aes128_sha1
- auth_chain_a through auth_chain_f

Supported obfuscation modes:

- plain
- http_simple, http_post
- tls1.0_session_auth
- tls1.2_ticket_auth, tls1.2_ticket_fastauth

The implementation keeps replay and authenticated client state per server and
applies client limits per user. Fixed classic wire vectors, independent SIP004
reference vectors, arbitrary-fragment and tamper tests, race tests, allocation
benchmarks, and classic-cipher Mihomo interoperability are used to guard
compatibility and performance. A client must support the selected SIP004 method
inside its SSR implementation; classic-only SSR clients cannot use these new
method combinations.

## License

Most files are GPL-3.0-or-later. Files derived from upstream ShadowsocksR
code keep the upstream copyright and license in their headers:

- `protocol/verify.go`, `protocol/legacy_auth.go`, `protocol/legacy_helpers.go`
  and `obfs/tls10.go` are Apache-2.0 (Copyright 2015-2015 breakwa11;
  `LICENSE-Apache-2.0`).
- `protocol/auth_chain.go` is GPL-3.0-only (Copyright 2015-2016 Break Wa11 and
  ShadowsocksR contributors).

The module as a whole can therefore only be distributed under GPL-3.0-only.
The GPL-3.0 text is in `LICENSE`; sources and per-file attribution are in
`NOTICE`, and dated Polaris changes in `MODIFICATIONS.md`.
