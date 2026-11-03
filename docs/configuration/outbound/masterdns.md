---
icon: material/new-box
---

!!! question "Since sing-box 1.15.0"

### Structure

```json
{
  "type": "masterdns",
  "tag": "masterdns-out",

  "domain": [
    "t.example.com"
  ],
  "resolvers": [
    "8.8.8.8",
    "1.1.1.1:53",
    "185.51.200.0/24",
    "system"
  ],
  "mode": "socks5",
  "encryption_method": "xor",
  "encryption_key": "",
  "base64_response": false,
  "upload_compression": "off",
  "download_compression": "off",
  "balancing_strategy": "least_loss",
  "packet_duplication": 3,
  "setup_packet_duplication": 4,
  "mtu": {
    "min_upload": 38,
    "max_upload": 150,
    "min_download": 200,
    "max_download": 4000,
    "test_retries": 2,
    "test_timeout": "2s",
    "test_parallelism": 32,
    "auto_remove_low": true
  },

  ... // Dial Fields
}
```

!!! info ""

    For MasterDnsVPN and StormDNS servers. Only TCP is supported.

    The session starts with the first connection, after the MTU tests of the resolvers.

!!! warning ""

    Only queries are encrypted: replies of the server are never encrypted or authenticated,
    `xor` only obfuscates and `chacha20` is not authenticated, so use an encrypted protocol inside the tunnel.

### Fields

#### domain

==Required==

The tunnel domains delegated to the server, the `DOMAIN` of the server.

All of them must lead to the same server. Queries are spread over every pair of domain and resolver.

#### resolvers

==Required==

The resolvers that carry the queries, as DNS over UDP.

| Format           | Example                                                         |
|------------------|-----------------------------------------------------------------|
| Address          | `8.8.8.8`, `2001:4860:4860::8888`                               |
| Address and port | `1.1.1.1:53`, `[2001:4860:4860::8888]:53`                       |
| Prefix           | `185.51.200.0/24`, `185.51.200.0/24:53`                         |
| `system`         | DNS servers of the system, or of the default network on Android |

Port `53` is used by default. A prefix adds each of its host addresses, at most 65536, and an address listed
twice keeps its first port. Empty entries and entries starting with `#` are skipped.

`system` servers are read again when the network changes, and servers inside the address of a Tun inbound are skipped.

Resolvers that fail the MTU tests are tested again in the background, and resolvers that keep timing out are disabled
until they pass again.

When no resolver passes, the tests are repeated every 5s. After a failure, the session is rebuilt, waiting from 1s up
to 60s between failed attempts.

#### mode

| Mode     | Destination                                                               |
|----------|---------------------------------------------------------------------------|
| `socks5` | sent to the server, which connects to it or passes it to its SOCKS5 proxy |
| `tcp`    | ignored, the server connects to its `FORWARD_IP` and `FORWARD_PORT`       |

Must match the `PROTOCOL_TYPE` of the server.

In `socks5` mode, the server refuses `localhost` and IP addresses that are not public.

In `tcp` mode, every connection is a raw stream to the forward target of the server,
so use the outbound as the `detour` of another outbound.

`socks5` is used by default.

#### encryption_method

| Method        | `DATA_ENCRYPTION_METHOD` of the server |
|---------------|----------------------------------------|
| `none`        | `0`                                    |
| `xor`         | `1`                                    |
| `chacha20`    | `2`                                    |
| `aes-128-gcm` | `3`                                    |
| `aes-192-gcm` | `4`                                    |
| `aes-256-gcm` | `5`                                    |

`xor` is used by default.

#### encryption_key

==Required== unless `encryption_method` is `none`.

The key of the server, the text in its `ENCRYPTION_KEY_FILE`.

#### base64_response

Ask the server for base64 replies instead of raw bytes, for resolvers that damage binary TXT records.

Base64 replies carry a quarter less data.

#### upload_compression

Compression of uploaded data, one of `off`, `zstd`, `lz4` and `zlib`.

The server may refuse it. Only payloads larger than the minimum size of the server, `120` bytes by default,
are compressed, and compression is turned off when the upload MTU is not larger.

`off` is used by default.

#### download_compression

Compression of downloaded data, one of `off`, `zstd`, `lz4` and `zlib`.

The server may refuse it. Only payloads larger than the minimum size of the server, `120` bytes by default,
are compressed, and compression is turned off when the download MTU is not larger.

`off` is used by default.

#### balancing_strategy

| Strategy                     | Queries go to                                                            |
|------------------------------|--------------------------------------------------------------------------|
| `round_robin`                | each resolver in turn                                                    |
| `random`                     | a random resolver                                                        |
| `least_loss`                 | the resolver with the least loss                                         |
| `lowest_latency`             | the resolver with the lowest latency                                     |
| `hybrid`                     | the resolver with the best score of loss and latency                     |
| `loss_then_latency`          | the lowest latency among the least loss resolvers, rotating near the top |
| `least_loss_top_random`      | a random resolver among the best 10% by loss                             |
| `least_loss_top_round_robin` | each resolver among the best 10% by loss in turn                         |

A stream whose packets keep being resent moves to another resolver, at most once every 2.5s.

`least_loss` is used by default.

#### packet_duplication

Number of copies of each packet, each sent through a different pair of resolver and domain, at most `10`.
The server may lower it.

`3` is used by default.

#### setup_packet_duplication

Number of copies of stream setup packets, from `packet_duplication` up to `12`. The server may lower it.

`4` is used by default.

#### mtu

MTU tests, run on every pair of domain and resolver before the session starts.

The upload MTU is the data carried by one query and the download MTU the data carried by one reply.
The session uses the lowest MTUs of the resolvers that pass.

#### mtu.min_upload

Minimum upload MTU in bytes, resolvers below it are left out.

`38` is used by default.

#### mtu.max_upload

Maximum upload MTU in bytes, also limited by the length of the query names and by the server.

`150` is used by default.

#### mtu.min_download

Minimum download MTU in bytes, resolvers below it are left out.

`200` is used by default.

#### mtu.max_download

Maximum download MTU in bytes, also limited by the server.

`4000` is used by default.

#### mtu.test_retries

Attempts for each tested size.

`2` is used by default.

#### mtu.test_timeout

Timeout of each attempt.

`2s` is used by default.

#### mtu.test_parallelism

Number of resolvers tested at the same time.

`32` is used by default.

#### mtu.auto_remove_low

With at least 5 resolvers passing, leave out the few whose low MTUs hold down the MTUs of the session.

Enabled by default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
