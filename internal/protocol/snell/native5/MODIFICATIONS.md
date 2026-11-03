# Snell v5 server adapter

Source: `github.com/sagernet/sing-snell` at `bc5a12ac736f` (GPL-3.0-or-later).

Only the v5 server, record, packet and connection-reuse implementation is included.
The upstream package does not expose its record codec or a shared replay-filter option.
The adapter adds an injectable, listener-wide salt filter and hashes PSK plus salt
before insertion, so replay memory is bounded independently of the user count.
The internal reuse dependency is reduced to the server record interfaces/constants.
Crypto, obfuscation, addresses, requests and the v6 server remain upstream dependencies.
Authentication selection and budgets belong to the enclosing Lunaris adapter.
