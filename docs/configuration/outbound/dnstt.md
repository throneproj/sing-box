---
icon: material/new-box
---

!!! question "Since sing-box 1.15.0"

### Structure

```json
{
  "type": "dnstt",
  "tag": "dnstt-out",

  "mode": "dnstt",
  "dnstt_compat": false,
  "domain": "t.example.com",
  "public_key": "",
  "record_type": "txt",
  "client_id_size": 2,
  "max_qname_len": 101,
  "rps": 0,
  "idle_timeout": "2m",
  "keepalive_interval": "10s",
  "handshake_timeout": "15s",
  "resolvers": [
    {
      "type": "udp",
      "server": "8.8.8.8",
      "server_port": 53,
      "path": "/dns-query",
      "tls": {},
      "tcp_fallback": false
    }
  ],
  "resolver_strategy": "round_robin",
  "socks": {
    "username": "",
    "password": "",
    "udp_over_tcp": false | {}
  },
  "shadowsocks": {
    "method": "2022-blake3-aes-128-gcm",
    "password": "",
    "udp_over_tcp": false | {}
  },
  "ssh": {
    "user": "root",
    "password": "",
    "private_key": "",
    "private_key_path": "$HOME/.ssh/id_rsa",
    "private_key_passphrase": "",
    "host_key": [],
    "host_key_algorithms": [],
    "client_version": ""
  },

  ... // Dial Fields
}
```

!!! info ""

    Only one of `socks`, `shadowsocks` and `ssh` can be set.

    Without any of them, every connection is a raw stream to the upstream of the server and the destination is ignored,
    so use the outbound as the `detour` of another outbound.

### Fields

#### mode

Tunnel protocol.

| Mode     | Server                                           |
|----------|--------------------------------------------------|
| `dnstt`  | `dnstt-server`, or `vaydns-server -dnstt-compat` |
| `vaydns` | `vaydns-server`                                  |

`dnstt` is used by default.

#### dnstt_compat

Only for `vaydns` mode.

Use the dnstt wire format (8-byte client ID and padding), as `vaydns-client -dnstt-compat` does.

#### domain

==Required==

The tunnel domain delegated to the server.

#### public_key

==Required==

The public key of the server, 64 hex digits.

#### record_type

The record type that carries downstream data, one of `txt`, `null`, `cname`, `a`, `aaaa`, `mx`, `ns`, `srv` and `caa`.

Only `txt` is available in `dnstt` mode and with `dnstt_compat`; the server must use the same type.

`txt` is used by default.

#### client_id_size

Only for `vaydns` mode without `dnstt_compat`.

Client ID size in bytes, must match `-clientid-size` of the server.

`2` is used by default.

#### max_qname_len

Only for `vaydns` mode.

Maximum length of query names, at most `253`. Longer names carry more data, but some resolvers drop them.

`101` is used by default, `253` with `dnstt_compat`.

#### rps

Maximum queries per second. Unlimited if empty.

#### idle_timeout

The session is closed when nothing is received within this period; keep it in line with the server.

`2m` is used by default in `dnstt` mode and with `dnstt_compat`, `10s` in `vaydns` mode.

#### keepalive_interval

Keepalive interval, must be less than `idle_timeout`.

`10s` is used by default in `dnstt` mode and with `dnstt_compat`, `2s` in `vaydns` mode.

#### handshake_timeout

Session handshake timeout.

`15s` is used by default.

#### resolvers

==Required==

The resolvers that carry the queries.

After a failure, the session is rebuilt with a new client ID, waiting from 1s up to 30s between failed attempts.

#### resolvers.type

| Type     | Resolver                                                        |
|----------|-----------------------------------------------------------------|
| `udp`    | DNS over UDP                                                    |
| `tcp`    | DNS over TCP                                                    |
| `tls`    | DNS over TLS                                                    |
| `https`  | DNS over HTTPS                                                  |
| `system` | DNS servers of the system, or of the default network on Android |

`system` servers are read again when the network changes, and servers inside the address of a Tun inbound are skipped.

`udp` is used by default.

UDP resolvers use a new socket for every query in `vaydns` mode, and one shared socket in `dnstt` mode or when `detour` is set.

#### resolvers.server

==Required== except for `system`.

Resolver address.

#### resolvers.server_port

Resolver port.

`53` is used by default for `udp` and `tcp`, `853` for `tls` and `443` for `https`.

#### resolvers.path

Only for `https`.

HTTP request path.

`/dns-query` is used by default.

#### resolvers.tls

Only for `tls` and `https`.

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

#### resolvers.tcp_fallback

Only for `udp` and `system`.

Repeat truncated responses over TCP.

#### resolver_strategy

| Strategy      | Queries go to                      |
|---------------|------------------------------------|
| `round_robin` | each resolver in turn              |
| `failover`    | the first available resolver       |
| `fanout`      | every available resolver           |

A resolver that leaves 8 queries unanswered for 2s is skipped for 1s, doubling up to 30s.

`round_robin` is used by default.

#### socks

Reach destinations through a SOCKS5 server behind the tunnel.

#### socks.username

SOCKS username.

#### socks.password

SOCKS password.

#### socks.udp_over_tcp

UDP over TCP protocol settings, required for UDP.

See [UDP Over TCP](/configuration/shared/udp-over-tcp/) for details.

#### shadowsocks

Reach destinations through a Shadowsocks server behind the tunnel.

#### shadowsocks.method

==Required==

Encryption method, see [Shadowsocks](/configuration/outbound/shadowsocks/#method).

#### shadowsocks.password

==Required==

Shadowsocks password.

#### shadowsocks.udp_over_tcp

UDP over TCP protocol settings, required for UDP.

See [UDP Over TCP](/configuration/shared/udp-over-tcp/) for details.

#### ssh

Reach destinations through an SSH server behind the tunnel.

The fields are the same as in [SSH](/configuration/outbound/ssh/).

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
