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

The node directly links [SagerNet/sing-snell](https://github.com/SagerNet/sing-snell/tree/bc5a12ac736f), version `v0.0.0-20260904135315-bc5a12ac736f` (GPL-3.0-or-later). It does not copy Polaris's modified sing-snell module.

## Polaris native Mieru and ShadowsocksR

The sources in `internal/protocol/mieru/native` and `internal/protocol/shadowsocksr/wire` were ported from [HyperPteLtd/Polaris](https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/pkg/sagernet), commit `56d52fb44958ef3cc2a7fb841cd240f8206234b2`.

Copyright (C) 2026 Polaris contributors

Mieru's source history and GPL-3.0-or-later notice are retained in [its README](internal/protocol/mieru/native/README.md), [LICENSE](internal/protocol/mieru/native/LICENSE) and [MODIFICATIONS](internal/protocol/mieru/native/MODIFICATIONS.md). The native implementation originates from Polaris's replacement of an earlier enfein/mieru v3.34.0 port.

SSR retains [NOTICE](internal/protocol/shadowsocksr/wire/NOTICE), [GPL-3.0 text](internal/protocol/shadowsocksr/wire/LICENSE), [Apache-2.0 text](internal/protocol/shadowsocksr/wire/LICENSE-Apache-2.0), and [MODIFICATIONS](internal/protocol/shadowsocksr/wire/MODIFICATIONS.md). The Apache-2.0 files preserve breakwa11's upstream notices; `protocol/auth_chain.go` preserves the GPL-3.0-only notices of Break Wa11 and ShadowsocksR contributors. Other imported original Polaris files remain GPL-3.0-or-later. File-level declarations take precedence.

Lunaris changes integrate host-owned sockets and immutable credentials, bound and cancel sessions/buffers, adapt deadline and replay APIs, and repair receive-buffer ownership, codec concurrency and TLS ticket record bounds. New Lunaris adapters carry their own SPDX headers. The independent clients under `test/clients` are test-only modules and are not linked into the node binary.
