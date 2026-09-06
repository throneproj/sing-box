---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

```json
{
  "type": "trusttunnel",
  "tag": "trusttunnel-out",

  "server": "127.0.0.1",
  "server_port": 443,
  "username": "trust",
  "password": "tunnel",
  "health_check": true,
  "quic": false,
  "quic_congestion_control": "bbr",
  "client_random": "a0b0/f0f0",
  "tls": {},

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### username

==Required==

Authentication username.

#### password

Authentication password.

#### health_check

Enable periodic health check.

#### quic

Use QUIC transport.

- `false`: Use HTTP/2 over TCP.
- `true`: Use HTTP/3 over UDP.

#### quic_congestion_control

QUIC congestion control algorithm.

| Algorithm | Description |
|-----------|-------------|
| `bbr` | BBR |
| `bbr_standard` | BBR (Standard version) |
| `bbr2` | BBRv2 |
| `bbr_variant` | BBRv2 (An experimental variant) |
| `cubic` | CUBIC |
| `reno` | New Reno |

`bbr` is used by default.

#### client_random

TLS ClientHello random to use, in the `prefix[/mask]` format of the TrustTunnel client, for servers restricted by `client_random_prefix` rules.

Both parts are hex encoded and cover the leading bytes of the 32 byte random only. The mask defaults to all bits set; bits it leaves out, and the rest of the random, remain random.

Supported by both HTTP/2 and QUIC transports.

#### tls

==Required==

Outbound TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
