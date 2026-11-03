# Third-party notices

Lunaris original source is licensed under GPL-3.0-only. Dependencies and imported third-party source retain their own licenses.

## shadcn/ui components

The files in `web/src/components/ui` were generated from the shadcn/ui registry using shadcn 4.23.0. Source: https://github.com/shadcn-ui/ui. The following license applies to these components:

MIT License

Copyright (c) 2023 shadcn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


## Polaris XHTTP / Xray SplitHTTP

`internal/transport/xhttp` was ported from [HyperPteLtd/Polaris](https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/transport/xhttp), commit `56d52fb44958ef3cc2a7fb841cd240f8206234b2`.

Copyright (C) 2026 Polaris contributors

Original Polaris files are GPL-3.0-or-later unless their file-level notices state otherwise. The applicable GPL version 3 text is retained in [LICENSE](LICENSE).

The files marked as derived from XTLS/Xray-core retain MPL-2.0 and the original source reference `b17a88f9b46d` (`transport/internet/splithttp`, `infra/conf/transport_method.go`, and related configuration helpers). The complete license is in [LICENSES/MPL-2.0/MPL-2.0.txt](LICENSES/MPL-2.0/MPL-2.0.txt). These file-level licenses are not replaced by Lunaris's main license.

Lunaris changes adapt the host listener and context integration, use released SagerNet module APIs and Go crypto randomness, bound and validate node-facing configuration, and harden request cancellation, write interruption, cleanup joins, range parsing, and power-of-two random alphabets. Client utilities remain available internally for regression testing; the node runtime registers only the server transport. New Lunaris wrapper and test files carry their own SPDX headers.


## Snell

The node directly links [SagerNet/sing-snell](https://github.com/SagerNet/sing-snell/tree/bc5a12ac736f), version `v0.0.0-20260904135315-bc5a12ac736f` (GPL-3.0-or-later). The v5 server files in `internal/protocol/snell/native5` are adapted from this pinned source, retaining [LICENSE](internal/protocol/snell/native5/LICENSE) and [MODIFICATIONS](internal/protocol/snell/native5/MODIFICATIONS.md). The adapter shares one credential-separated replay filter across users. Crypto, obfuscation and v6 services remain external module APIs.

`internal/protocol/snell/probe` contains the v6 profile/salt recognition subset from Polaris `56d52fb44958ef3cc2a7fb841cd240f8206234b2` (GPL-3.0-or-later, Copyright (C) 2026 Polaris contributors); record encoding stays upstream.

## Polaris authentication scan protection

The cache, guard and their source tests in `internal/authscan` are adapted from `pkg/sagernet/sing/common/authscan` at Polaris `56d52fb44958ef3cc2a7fb841cd240f8206234b2` (GPL-3.0-or-later, Copyright (C) 2026 Polaris contributors). Lunaris adds tentative matches, full-authentication cache commits, cached-candidate work accounting and I/O-free CPU permit lifetimes. The GPL text is retained in [LICENSE](LICENSE); new adapters carry GPL-3.0-only headers.

## Polaris native Mieru and ShadowsocksR

The sources in `internal/protocol/mieru/native` and `internal/protocol/shadowsocksr/wire` were ported from [HyperPteLtd/Polaris](https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/pkg/sagernet), commit `56d52fb44958ef3cc2a7fb841cd240f8206234b2`.

Copyright (C) 2026 Polaris contributors

Mieru's source history and GPL-3.0-or-later notice are retained in [its README](internal/protocol/mieru/native/README.md), [LICENSE](internal/protocol/mieru/native/LICENSE) and [MODIFICATIONS](internal/protocol/mieru/native/MODIFICATIONS.md). The native implementation originates from Polaris's replacement of an earlier enfein/mieru v3.34.0 port.

SSR retains [NOTICE](internal/protocol/shadowsocksr/wire/NOTICE), [GPL-3.0 text](internal/protocol/shadowsocksr/wire/LICENSE), [Apache-2.0 text](internal/protocol/shadowsocksr/wire/LICENSE-Apache-2.0), and [MODIFICATIONS](internal/protocol/shadowsocksr/wire/MODIFICATIONS.md). The Apache-2.0 files preserve breakwa11's upstream notices; `protocol/auth_chain.go` preserves the GPL-3.0-only notices of Break Wa11 and ShadowsocksR contributors. Other imported original Polaris files remain GPL-3.0-or-later. File-level declarations take precedence.

Lunaris changes integrate host-owned sockets and immutable credentials, bound and cancel sessions/buffers, adapt deadline and replay APIs, and repair receive-buffer ownership, codec concurrency and TLS ticket record bounds. New Lunaris adapters carry their own SPDX headers. The independent clients under `test/clients` are test-only modules and are not linked into the node binary.


## Polaris VLESS Encryption and XTLS Vision

`internal/protocol/vless/wire` is adapted from [HyperPteLtd/Polaris](https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/pkg/sagernet/sing-vmess) at commit `56d52fb44958ef3cc2a7fb841cd240f8206234b2`. The VLESS and mux codecs originate from [SagerNet/sing-vmess](https://github.com/SagerNet/sing-vmess), vendored by Polaris from `3aed155119a174c9290a4099841049f0cb275e02`, and retain GPL-3.0-or-later. Copyright (C) SagerNet contributors and 2026 Polaris contributors. The complete GPL text is retained in [LICENSE](LICENSE).

`wire/encryption` derives from XTLS/Xray-core `proxy/vless/encryption`, `infra/conf/vless.go` and related crypto helpers at `b17a88f9b46dabbdc2f3dff232dc91d6e13758fe`. Its MPL-2.0 notices remain in each implementation file; the full license is in [LICENSES/MPL-2.0/MPL-2.0.txt](LICENSES/MPL-2.0/MPL-2.0.txt).

Lunaris modifications (2026-11-01): isolated VLESS integration with released sing/vmess dependencies; standard-library cryptographic randomness; carrier-owned authentication deadlines; explicit TLS record exposure, including pointer-based REALITY record buffers; cancellable server padding/I/O; bounded ticket/replay caches and overflow checks; deadline-capable XUDP pipes, joined mux cleanup and serialized frame writes. New factory and regression files carry their own SPDX headers. Client codecs remain internal for regression testing. No local Go module replacement or sing-box runtime dependency is introduced.


## Shadowsocks plugins

`internal/transport/ssplugin` was adapted from [HyperPteLtd/Polaris](https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/shadowsocks/plugin), commit `56d52fb44958ef3cc2a7fb841cd240f8206234b2`.

Copyright (C) 2026 Polaris contributors. Original Polaris adapter files retain GPL-3.0-or-later unless a file-level notice states otherwise. The GPL version 3 text is in [LICENSE](LICENSE).

- `ssplugin/obfs` retains GPL-3.0-only and its MetaCubeX/mihomo simple-obfs source notice.
- `ssplugin/v2ray/mux.go`, `mux_write.go` and `session.go` derive from XTLS/Xray-core common/mux at `b17a88f9b46d` and retain MPL-2.0. The license is in [LICENSES/MPL-2.0/MPL-2.0.txt](LICENSES/MPL-2.0/MPL-2.0.txt).
- `ssplugin/kcptun/common.go` and `server.go` derive from MetaCubeX/mihomo transport/kcptun and retain MIT. The applicable notice is in [LICENSES/MIT/mihomo-kcptun.txt](LICENSES/MIT/mihomo-kcptun.txt).
- The Restls adapter at `ssplugin/restls/wire` was ported from Polaris's `pkg/sagernet/sing-restls`, with its [BSD-3-Clause license](internal/transport/ssplugin/restls/wire/LICENSE) and [modification history](internal/transport/ssplugin/restls/wire/MODIFICATIONS.md). It links the external `github.com/metacubex/restls-client-go` v0.1.9 engine.
- ShadowTLS links the released `github.com/sagernet/sing-shadowtls` v0.2.1 (GPL-3.0-or-later). KCP uses `github.com/metacubex/kcp-go` at `550693377604`; smux and snappy remain external modules.

Lunaris modifications (2026-11-01): independent transport-factory integration; secret references; strict options and resource bounds; WebSocket early-data validation; logical and physical authentication budgets; cancellable target ownership with Restls deadline promotion; KCP unauthenticated session limits; serialization and record-size bounds around released ShadowTLS I/O; released smux API adaptation. New wrappers and regression tests have their own SPDX headers. The independent Mihomo test client is a separate module and is not part of the node's production dependency graph.

VLESS mux follow-up (2026-11-02): flush each serialized write batch before releasing its writer lock; arrival counters cannot identify the final lock owner under concurrent scheduling. The imported GPL-3.0-or-later notices remain intact.

## Ingress address propagation and PROXY protocol

`internal/ingress/proxy_protocol*.go` and the Linux/macOS UDP ancillary helpers in `internal/ingress/udp_linux.go` and `udp_darwin.go` are adapted from Polaris commit `56d52fb44958ef3cc2a7fb841cd240f8206234b2`, `internal/runtime/proxy_protocol*.go` and the single-datagram helpers in `internal/runtime/udp_origin_{linux,darwin}.go`. Copyright (C) 2026 Polaris contributors; GPL-3.0-or-later. Source: <https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/runtime>.

Lunaris adaptations: per-connection preparation before TLS/camouflage; bounded shared UDP endpoint dispatch; immutable flow-origin propagation across multiplexing and QUIC streams; source-bound TCP and dual-family UDP egress; lifecycle and address-isolation tests. The direct-source policy also follows the principles in Polaris `internal/route/inbound.go` and `resolver.go`, without its panel or routing product layers.

## Routing and DNS

`internal/route` and `internal/dns` are adapted from Polaris commit `56d52fb44958ef3cc2a7fb841cd240f8206234b2`, with the original matching/index algorithms, GeoData protobuf parsing, DNS wire/transports/cache code and applicable regression fixtures. Copyright (C) 2026 Polaris contributors; GPL-3.0-or-later. Sources: <https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/route> and <https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/dns>.

Lunaris adaptations: application-owned direct/block actions; no panel or proxy-outbound dependency; immutable SQLite GeoData instead of environment/path discovery; configuration-generation ownership and resolver shutdown; bounded coalescing and cancellation isolation; per-datagram policy checks; source-preserving DNS transport with independent bootstrap resolution; stricter asset validation and failure handling.
