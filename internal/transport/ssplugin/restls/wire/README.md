# sing-restls

> Origin: a Polaris port of the RESTLS server transport from [MetaCubeX/Restls-Client-Go](https://github.com/MetaCubeX/Restls-Client-Go) (BSD-3-Clause), reworked into the sing-* module interface. Despite the `github.com/sagernet/sing-restls` module path, it is not a SagerNet project; see `MODIFICATIONS.md`.

`sing-restls` is the server-side RESTLS transport boundary used by
Polaris. It exposes sing address and dialer contracts and implements
sing pooled extended stream I/O while preserving RESTLS wire compatibility.

The current handshake engine is `MetaCubeX/Restls-Client-Go` v0.1.9. Keeping
that engine private behind this module avoids coupling product protocol code to
the uTLS fork and allows the wire implementation to be replaced incrementally.

The connection adapter tracks TLS record boundaries and treats a
post-authentication `bad record MAC` as a peer close only after observing a TLS
1.3 close-notify record. This handles the RESTLS client mismatch without a
blocking EOF probe and preserves other integrity errors.

This copy is an internal Lunaris adapter, not a standalone Go module. The host transport owns the lifetime of the returned connection and its camouflage target, and promotes their deadlines after authentication without cancelling RESTLS cover traffic.
