# Independent interoperability clients

These Go modules are separate from the Lunaris node module. They pin external
client implementations and do not import Lunaris server codecs or use local
module replacements.

- `mieru`: official enfein/mieru v3.34.0 API, TCP/UDP underlays and multiplexed
  CONNECT/UDP ASSOCIATE.
- `shadowsocksr`: unmodified Mihomo v1.19.33 SSR wire codecs, TCP and UDP.

Build and run them through [the loopback script](../../scripts/test-snell-mieru-ssr.py).
Configuration files contain disposable loopback test credentials and should be
kept private. No client sets system proxy or routing configuration.

The SSR client config accepts `ConcurrentStartup: true` for diagnostics. With
`go build -race`, this reproduces Mihomo v1.19.33 TLS ticket handshake races in
`transport/ssr/obfs/tls1.2_ticket_auth.go` (`sendBuf` and handshake state). The
normal interop mode writes before starting the initial read, keeping the wire
codec unchanged. The diagnostic race is not a passing server test.

The server runners require `make build-web`. They provision temporary credentials and configuration through the JSON management API, stop the management process, then launch `managed` from the committed SQLite state. Client configuration files remain private and disposable; no Lunaris node YAML is used.
