# Hysteria Realm Server

A rendezvous server for **Hysteria Realms**, the P2P feature of [Hysteria 2](https://github.com/apernet/hysteria).

It coordinates UDP hole punching between Hysteria servers and clients so users can host Hysteria servers from behind NAT or firewalls. No port forwarding, no public IP required.

## How it works

1. A Hysteria server registers a realm with the rendezvous server, advertising its STUN-discovered UDP address(es).
2. A Hysteria client looks up the realm. The rendezvous pushes the client's address(es), punch nonce, and punch obfuscation key to the server over its SSE stream, and waits.
3. The Hysteria server runs a fresh STUN, posts the just-discovered addresses, and the rendezvous returns those to the client. If the server doesn't post within a few seconds, the rendezvous falls back to the addresses cached at registration time.
4. Both sides simultaneously send UDP packets toward each other, punching holes in their respective NATs.
5. Once a hole is open, Hysteria's regular QUIC handshake proceeds over the direct connection.

The rendezvous server only mediates introductions. **No traffic is relayed.** Once peers are connected, the rendezvous is out of the loop.

## Build

```bash
go build -o hysteria-realm-server
```

## Run

```bash
HYSTERIA_REALM_TOKEN=your-secret-token \
HYSTERIA_REALM_LISTEN=:8443 \
HYSTERIA_REALM_CERT=/path/to/cert.pem \
HYSTERIA_REALM_KEY=/path/to/key.pem \
./hysteria-realm-server
```

Equivalent CLI flags are also supported:

```bash
./hysteria-realm-server \
  --token your-secret-token \
  --listen :8443 \
  --cert /path/to/cert.pem \
  --key /path/to/key.pem
```

If `HYSTERIA_REALM_CERT` and `HYSTERIA_REALM_KEY` are both unset, the server runs over plain HTTP. Setting only one of them is an error, so a typo can't silently turn TLS off.

To keep the token out of the process list and shell history, put it in a file and use `HYSTERIA_REALM_TOKEN_FILE` (or `--token-file`) instead of `HYSTERIA_REALM_TOKEN`.

## Configuration

| Variable                              | Default                            | Description                                                                                                                                                            |
| ------------------------------------- | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `HYSTERIA_REALM_LISTEN`               | `:8443`                            | Address to listen on                                                                                                                                                   |
| `HYSTERIA_REALM_TOKEN`                | _REQUIRED_                         | Shared bearer token for realm registration and connection. Required unless `HYSTERIA_REALM_TOKEN_FILE` is set.                                                         |
| `HYSTERIA_REALM_TOKEN_FILE`           | _(none)_                           | File to read the token from (surrounding whitespace is trimmed). Use instead of `HYSTERIA_REALM_TOKEN`, not together with it.                                          |
| `HYSTERIA_REALM_CERT`                 | _(none)_                           | Path to TLS certificate. Must be set together with `HYSTERIA_REALM_KEY`.                                                                                               |
| `HYSTERIA_REALM_KEY`                  | _(none)_                           | Path to TLS private key. Must be set together with `HYSTERIA_REALM_CERT`.                                                                                              |
| `HYSTERIA_REALM_DEBUG`                | `false`                            | Enable debug logs for registration, sessions, and punches                                                                                                              |
| `HYSTERIA_REALM_MAX_REALMS`           | `65536`                            | Maximum total number of registered realms. `0` disables the limit.                                                                                                     |
| `HYSTERIA_REALM_MAX_REALMS_PER_IP`    | `4`                                | Maximum realms per client IP. `0` disables the limit.                                                                                                                  |
| `HYSTERIA_REALM_CONNECT_RATE_PER_IP`  | `60`                               | Maximum `connect` requests per minute from one client IP, with short bursts of up to 20 allowed. `0` disables the limit.                                               |
| `HYSTERIA_REALM_TRUSTED_PROXY_HEADER` | _(none)_                           | Header to read the real client IP from when behind a reverse proxy or CDN (e.g. `X-Forwarded-For`, `CF-Connecting-IP`). Empty means use the connecting socket address. |
| `HYSTERIA_REALM_TRUSTED_PROXIES`      | _(none)_                           | Comma-separated IPs and CIDRs of your proxies (e.g. `10.0.0.0/8,192.0.2.1`). When set, the proxy header is only trusted on requests from these addresses.              |
| `HYSTERIA_REALM_NAME_PATTERN`         | `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` | Regex realm names must match. It always has to match the whole name, even without `^` and `$`.                                                                         |
| `HYSTERIA_REALM_METRICS_LISTEN`       | _(none)_                           | Address to expose Prometheus metrics on (e.g. `:9090`). Empty disables metrics.                                                                                        |

CLI flags with the same meaning are available: `--listen`, `--token`, `--token-file`, `--cert`, `--key`, `--debug`, `--max-realms`, `--max-realms-per-ip`, `--connect-rate-per-ip`, `--trusted-proxy-header`, `--trusted-proxies`, `--realm-name-pattern`, and `--metrics-listen`. Flags override environment variables. Invalid values (for example a non-numeric limit) stop the server at startup instead of being ignored.

When `HYSTERIA_REALM_TRUSTED_PROXY_HEADER` is set, the server reads the client IP from that header, falling back to the socket address if the header is missing or unparseable. Proxies add the address they saw to the **end** of headers like `X-Forwarded-For`, so the server uses the rightmost entry; anything to its left was sent by the client and could be made up. If requests pass through more than one proxy, list all of them in `HYSTERIA_REALM_TRUSTED_PROXIES`: the server then skips those addresses from the right and uses the first one that isn't a proxy. Setting `HYSTERIA_REALM_TRUSTED_PROXIES` also makes the server ignore the header on requests that don't come from a listed proxy. Without it, anyone who can reach the server directly can send the header and pick their own IP, bypassing the per-IP limits.

## Limitations

- **In-memory only.** All state is lost on restart. Active realms must re-register.
- **Single shared token.** Every realm uses the same token. Only suitable for self-hosted, trusted-group deployments. More sophisticated third-party implementations are welcome.

## API

All endpoints use `Authorization: Bearer ...`. Realm names in `{id}` must match `HYSTERIA_REALM_NAME_PATTERN`; an invalid name returns `400 bad_request`.

Addresses must be `ip:port` pairs that a peer on another network could send packets to. Port `0`, unspecified (`0.0.0.0`, `::`), loopback, link-local, multicast and broadcast addresses are rejected with `400 bad_request`. Private ranges such as `10.0.0.0/8` are allowed.

Errors are returned as JSON: `{"error": "<code>", "message": "<human-readable>"}`. Notable codes:

| Status | Code                  | Cause                                                                           |
| ------ | --------------------- | ------------------------------------------------------------------------------- |
| 400    | `bad_request`         | Invalid JSON, invalid addresses/nonce/obfs, bad name                            |
| 401    | `invalid_token`       | Missing or wrong bearer token                                                   |
| 404    | `realm_not_found`     | `connect` to a realm that is not registered                                     |
| 404    | `attempt_not_found`   | `connects/{nonce}` post for an unknown / expired nonce                          |
| 409    | `realm_taken`         | Registering a realm name that is already in use                                 |
| 409    | `attempt_exists`      | `connect` with a nonce that another in-flight `connect` already uses            |
| 429    | `realm_limit_reached` | Global realm limit reached                                                      |
| 429    | `ip_limit_reached`    | Per-IP realm limit reached                                                      |
| 429    | `rate_limited`        | Too many `connect` requests from this IP (`HYSTERIA_REALM_CONNECT_RATE_PER_IP`) |
| 503    | `rate_limited`        | Server's punch event buffer or pending-attempts cap is full                     |

### `POST /v1/{id}`

Register a Realm. Uses `HYSTERIA_REALM_TOKEN`.

Request:

```json
{
  "addresses": ["203.0.113.10:4433"]
}
```

Response:

```json
{
  "session_id": "session-token",
  "ttl": 60
}
```

### `GET /v1/{id}/events`

Open the Realm server's SSE stream. Uses `session_id`.

Events:

```text
event: punch
data: {"addresses":["198.51.100.20:4433"],"nonce":"...","obfs":"..."}
```

```text
event: heartbeat_ack
data: {"ttl":60}
```

`punch` is emitted on every `connect` request for this realm. `heartbeat_ack` is emitted after a successful `heartbeat` and lets clients confirm the SSE stream is still healthy. Acks are coalesced: while one is waiting to be sent, more heartbeats don't queue more acks, so they never crowd out `punch` events.

Only one stream per session receives events. Opening a new stream closes the previous one, because a client only reconnects after giving up on its old connection, which may be dead without the server knowing. `punch` events that waited in the queue for more than 20 seconds (for example while no stream was open) are dropped instead of delivered, since the client has stopped waiting for them by then.

### `POST /v1/{id}/heartbeat`

Refresh the session TTL. Uses `session_id`. It may also include replacement Realm addresses:

```json
{
  "addresses": ["203.0.113.11:4433"]
}
```

If `addresses` is omitted, only the TTL is refreshed. If present, the Hysteria Realm Server validates and replaces the stored addresses for that Realm.

Response:

```json
{
  "ttl": 60
}
```

### `DELETE /v1/{id}`

Deregister a Realm immediately. Uses `session_id`.

Response: `204 No Content`.

### `POST /v1/{id}/connect`

Request a connection to a Realm. Uses `HYSTERIA_REALM_TOKEN`.

```json
{
  "addresses": ["198.51.100.20:4433"],
  "nonce": "00112233445566778899aabbccddeeff",
  "obfs": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
}
```

- `nonce` is 16 random bytes encoded as 32 lowercase or uppercase hex characters.
- `obfs` is a 32-byte random key encoded as 64 lowercase or uppercase hex characters, used by peers to obfuscate UDP punch packets.

The Hysteria Realm Server forwards `addresses`, `nonce`, and `obfs` unchanged in the Realm server's `punch` SSE event, then **blocks the request for up to 10 seconds** waiting for the Realm server to post fresh addresses via `/v1/{id}/connects/{nonce}`. If the post arrives, those fresh addresses are returned to the client; if it doesn't (legacy server, STUN failure, etc.), the registered cached addresses are returned instead. The response always echoes `nonce` and `obfs`:

```json
{
  "addresses": ["203.0.113.10:4433"],
  "nonce": "00112233445566778899aabbccddeeff",
  "obfs": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
}
```

### `POST /v1/{id}/connects/{nonce}`

Posted by the Realm server in response to a `punch` SSE event, with the addresses it just discovered via a fresh STUN. Uses `session_id`. The `{nonce}` path segment must match the `nonce` from the SSE event.

```json
{
  "addresses": ["203.0.113.10:4433"]
}
```

Response: `204 No Content`. Returns `404 attempt_not_found` if the rendezvous has no in-flight `connect` for this nonce.
