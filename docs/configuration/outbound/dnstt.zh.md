---
icon: material/new-box
---

!!! question "自 sing-box 1.15.0 起"

### 结构

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

  ... // 拨号字段
}
```

!!! info ""

    `socks`、`shadowsocks` 与 `ssh` 只能设置其一。

    均未设置时，每个连接都是到服务器上游的原始流，目标地址被忽略，
    因此请将此出站用作其他出站的 `detour`。

### 字段

#### mode

隧道协议。

| 模式       | 服务器                                              |
|----------|--------------------------------------------------|
| `dnstt`  | `dnstt-server`，或 `vaydns-server -dnstt-compat` |
| `vaydns` | `vaydns-server`                                  |

默认使用 `dnstt`。

#### dnstt_compat

仅用于 `vaydns` 模式。

使用 dnstt 线路格式（8 字节客户端 ID 与填充），与 `vaydns-client -dnstt-compat` 相同。

#### domain

==必填==

委派给服务器的隧道域名。

#### public_key

==必填==

服务器公钥，64 位十六进制数字。

#### record_type

承载下行数据的记录类型，可选 `txt`、`null`、`cname`、`a`、`aaaa`、`mx`、`ns`、`srv` 与 `caa`。

`dnstt` 模式与 `dnstt_compat` 下仅可使用 `txt`；服务器必须使用相同类型。

默认使用 `txt`。

#### client_id_size

仅用于未启用 `dnstt_compat` 的 `vaydns` 模式。

客户端 ID 字节数，必须与服务器的 `-clientid-size` 一致。

默认使用 `2`。

#### max_qname_len

仅用于 `vaydns` 模式。

查询名称的最大长度，最大为 `253`。更长的名称携带更多数据，但部分解析器会丢弃它们。

默认使用 `101`，启用 `dnstt_compat` 时为 `253`。

#### rps

每秒最大查询数。默认不限制。

#### idle_timeout

在此期间未收到任何数据时关闭会话；应与服务器保持一致。

`dnstt` 模式与 `dnstt_compat` 下默认使用 `2m`，`vaydns` 模式下为 `10s`。

#### keepalive_interval

保活间隔，必须小于 `idle_timeout`。

`dnstt` 模式与 `dnstt_compat` 下默认使用 `10s`，`vaydns` 模式下为 `2s`。

#### handshake_timeout

会话握手超时。

默认使用 `15s`。

#### resolvers

==必填==

承载查询的解析器。

失败后会使用新的客户端 ID 重建会话，连续失败之间的等待从 1s 递增至 30s。

#### resolvers.type

| 类型       | 解析器                     |
|----------|-------------------------|
| `udp`    | DNS over UDP            |
| `tcp`    | DNS over TCP            |
| `tls`    | DNS over TLS            |
| `https`  | DNS over HTTPS          |
| `system` | 系统 DNS 服务器，Android 上为默认网络的 DNS 服务器 |

网络变化时会重新读取 `system` 服务器，位于 Tun 入站地址内的服务器会被跳过。

默认使用 `udp`。

`vaydns` 模式下 UDP 解析器为每个查询使用新的套接字，`dnstt` 模式或设置了 `detour` 时共用一个套接字。

#### resolvers.server

==必填==，`system` 除外。

解析器地址。

#### resolvers.server_port

解析器端口。

`udp` 与 `tcp` 默认使用 `53`，`tls` 为 `853`，`https` 为 `443`。

#### resolvers.path

仅用于 `https`。

HTTP 请求路径。

默认使用 `/dns-query`。

#### resolvers.tls

仅用于 `tls` 与 `https`。

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#outbound)。

#### resolvers.tcp_fallback

仅用于 `udp` 与 `system`。

通过 TCP 重新获取被截断的响应。

#### resolver_strategy

| 策略            | 查询发送至      |
|---------------|------------|
| `round_robin` | 依次轮流发送至各解析器 |
| `failover`    | 第一个可用的解析器  |
| `fanout`      | 所有可用的解析器   |

连续 8 个查询未获应答且 2s 内无响应的解析器会被跳过 1s，之后加倍，最长 30s。

默认使用 `round_robin`。

#### socks

通过隧道后方的 SOCKS5 服务器连接目标。

#### socks.username

SOCKS 用户名。

#### socks.password

SOCKS 密码。

#### socks.udp_over_tcp

UDP over TCP 配置，UDP 需要启用。

参阅 [UDP Over TCP](/zh/configuration/shared/udp-over-tcp/)。

#### shadowsocks

通过隧道后方的 Shadowsocks 服务器连接目标。

#### shadowsocks.method

==必填==

加密方法，参阅 [Shadowsocks](/zh/configuration/outbound/shadowsocks/#method)。

#### shadowsocks.password

==必填==

Shadowsocks 密码。

#### shadowsocks.udp_over_tcp

UDP over TCP 配置，UDP 需要启用。

参阅 [UDP Over TCP](/zh/configuration/shared/udp-over-tcp/)。

#### ssh

通过隧道后方的 SSH 服务器连接目标。

字段与 [SSH](/zh/configuration/outbound/ssh/) 相同。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
