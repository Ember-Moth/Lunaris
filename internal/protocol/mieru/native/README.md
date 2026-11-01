# sing-mieru

> Origin: a Polaris port of [enfein/mieru](https://github.com/enfein/mieru) v3.34.0 (GPL-3.0-or-later), reworked into the sing-* module interface and since rewritten natively. It is not a SagerNet project; see `MODIFICATIONS.md`.

Native, server-focused Mieru v3 implementation for Polaris.

The module implements Mieru's wire protocol directly on Go and `sing`
network primitives. It is a library by construction: there is no embedded
client, CLI, RPC control plane, application configuration graph, global
logger, socket-option layer, or persistent metrics registry.

Implemented protocol features include:

- TCP underlays with multiple multiplexed sessions;
- reliable UDP with fragmentation, ordered delivery, cumulative ACKs,
  receive windows, adaptive retransmission, congestion control, heartbeats,
  and idle cleanup;
- XChaCha20-Poly1305, Mieru time-derived keys, implicit stream nonces,
  stateless packet nonces, and user hints;
- immutable pre-derived users, atomic updates, source-local authentication
  caching, mandatory hints, and per-server replay protection;
- the Mieru traffic-pattern protobuf wire format, including nonce rewriting,
  padding, and TCP fragmentation;
- TCP CONNECT and UDP ASSOCIATE delivery through `sing` handler contracts.

Compatibility is tested against the official `enfein/mieru` v3 client over
TCP, multiplexed TCP, UDP, concurrent sessions, user updates, and injected UDP
loss. Hot paths have allocation and high-user authentication benchmarks.

License: GPL-3.0-or-later. See `LICENSE` and the repository's
`THIRD_PARTY_NOTICES` file.
