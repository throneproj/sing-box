---
icon: material/new-box
---

!!! question "自 sing-box 1.15.0 起"

### 结构

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

  ... // 拨号字段
}
```

!!! info ""

    用于 MasterDnsVPN 与 StormDNS 服务器。仅支持 TCP。

    会话在第一个连接时建立，此前会先完成解析器的 MTU 测试。

!!! warning ""

    仅查询被加密：服务器的响应从不加密也不认证，`xor` 仅作混淆，`chacha20` 不提供认证，
    因此请在隧道内使用加密协议。

### 字段

#### domain

==必填==

委派给服务器的隧道域名，即服务器的 `DOMAIN`。

所有域名必须指向同一服务器。查询会分散到每一对域名与解析器上。

#### resolvers

==必填==

承载查询的解析器，使用 DNS over UDP。

| 格式       | 示例                                        |
|----------|-------------------------------------------|
| 地址       | `8.8.8.8`、`2001:4860:4860::8888`          |
| 地址与端口    | `1.1.1.1:53`、`[2001:4860:4860::8888]:53`  |
| 前缀       | `185.51.200.0/24`、`185.51.200.0/24:53`    |
| `system` | 系统 DNS 服务器，Android 上为默认网络的 DNS 服务器 |

默认使用端口 `53`。前缀会加入其中的每个主机地址，最多 65536 个；重复的地址保留首次出现时的端口。
空条目与以 `#` 开头的条目会被跳过。

网络变化时会重新读取 `system` 服务器，位于 Tun 入站地址内的服务器会被跳过。

未通过 MTU 测试的解析器会在后台重新测试，持续超时的解析器会被禁用，直到再次通过测试。

没有解析器通过测试时，每 5s 重新测试一次。失败后会重建会话，连续失败之间的等待从 1s 递增至 60s。

#### mode

| 模式       | 目标地址                                              |
|----------|---------------------------------------------------|
| `socks5` | 发送给服务器，由服务器连接，或交给其 SOCKS5 代理                    |
| `tcp`    | 被忽略，服务器连接到其 `FORWARD_IP` 与 `FORWARD_PORT`         |

必须与服务器的 `PROTOCOL_TYPE` 一致。

`socks5` 模式下，服务器会拒绝 `localhost` 与非公网 IP 地址。

`tcp` 模式下，每个连接都是到服务器转发目标的原始流，因此请将此出站用作其他出站的 `detour`。

默认使用 `socks5`。

#### encryption_method

| 方法            | 服务器的 `DATA_ENCRYPTION_METHOD` |
|---------------|------------------------------|
| `none`        | `0`                          |
| `xor`         | `1`                          |
| `chacha20`    | `2`                          |
| `aes-128-gcm` | `3`                          |
| `aes-192-gcm` | `4`                          |
| `aes-256-gcm` | `5`                          |

默认使用 `xor`。

#### encryption_key

==必填==，`encryption_method` 为 `none` 时除外。

服务器的密钥，即其 `ENCRYPTION_KEY_FILE` 中的文本。

#### base64_response

要求服务器以 base64 文本而非原始字节返回响应，用于会损坏二进制 TXT 记录的解析器。

base64 响应携带的数据少四分之一。

#### upload_compression

上传数据的压缩方式，可选 `off`、`zstd`、`lz4` 与 `zlib`。

服务器可能拒绝。仅压缩大于服务器最小长度（默认 `120` 字节）的负载，上传 MTU 不大于该长度时不压缩。

默认使用 `off`。

#### download_compression

下载数据的压缩方式，可选 `off`、`zstd`、`lz4` 与 `zlib`。

服务器可能拒绝。仅压缩大于服务器最小长度（默认 `120` 字节）的负载，下载 MTU 不大于该长度时不压缩。

默认使用 `off`。

#### balancing_strategy

| 策略                           | 查询发送至                    |
|------------------------------|--------------------------|
| `round_robin`                | 依次轮流发送至各解析器              |
| `random`                     | 随机的解析器                   |
| `least_loss`                 | 丢包最少的解析器                 |
| `lowest_latency`             | 延迟最低的解析器                 |
| `hybrid`                     | 丢包与延迟综合得分最佳的解析器          |
| `loss_then_latency`          | 丢包最少者中延迟最低的解析器，在接近最佳者间轮换 |
| `least_loss_top_random`      | 丢包最少的前 10% 中随机的解析器       |
| `least_loss_top_round_robin` | 依次轮流发送至丢包最少的前 10% 解析器    |

数据包持续重发的流会改用其他解析器，最多每 2.5s 一次。

默认使用 `least_loss`。

#### packet_duplication

每个数据包的副本数，各副本经由不同的解析器与域名组合发送，最大为 `10`。服务器可能将其调低。

默认使用 `3`。

#### setup_packet_duplication

流建立数据包的副本数，从 `packet_duplication` 到 `12`。服务器可能将其调低。

默认使用 `4`。

#### mtu

MTU 测试，在会话建立前对每一对域名与解析器进行。

上传 MTU 是一个查询携带的数据量，下载 MTU 是一个响应携带的数据量。会话使用通过测试的解析器中最低的 MTU。

#### mtu.min_upload

最小上传 MTU（字节），低于此值的解析器会被排除。

默认使用 `38`。

#### mtu.max_upload

最大上传 MTU（字节），同时受查询名称长度与服务器限制。

默认使用 `150`。

#### mtu.min_download

最小下载 MTU（字节），低于此值的解析器会被排除。

默认使用 `200`。

#### mtu.max_download

最大下载 MTU（字节），同时受服务器限制。

默认使用 `4000`。

#### mtu.test_retries

每个测试大小的尝试次数。

默认使用 `2`。

#### mtu.test_timeout

每次尝试的超时时间。

默认使用 `2s`。

#### mtu.test_parallelism

同时测试的解析器数量。

默认使用 `32`。

#### mtu.auto_remove_low

至少 5 个解析器通过测试时，排除少数拉低会话 MTU 的低 MTU 解析器。

默认启用。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
