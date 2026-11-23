---
icon: material/new-box
---

!!! question "自 sing-box 1.15.0 起"

### 结构

```json
{
  "type": "psiphon",
  "tag": "psiphon-out",

  "data_directory": "psiphon",
  "egress_region": "",
  "propagation_channel_id": "",
  "sponsor_id": "",
  "remote_server_list_urls": [],
  "remote_server_list_signature_public_key": "",

  ... // 拨号字段
}
```

!!! info ""

    默认安装不包含 Psiphon，需使用 `with_psiphon` 与 `PSIPHON_DISABLE_QUIC` 构建标记重新构建。

    UDP 通过 Psiphon 服务器的 udpgw 服务转发，仅支持 IP 目标。

### 字段

#### data_directory

Psiphon 保存服务器列表和其他状态的目录。

默认使用 `psiphon`。

#### egress_region

要使用的 Psiphon 服务器所在的两位国家代码。如未设置，由 Psiphon 选择。

#### propagation_channel_id

传播渠道 ID，16 位十六进制数。

默认使用公共 ID。

#### sponsor_id

赞助者 ID，16 位十六进制数。

默认使用公共 ID。

#### remote_server_list_urls

已签名并压缩的服务器列表的 HTTPS URL 列表，按顺序尝试。

默认使用公共服务器列表。

#### remote_server_list_signature_public_key

用于验证服务器列表的 Base64 公钥。

默认使用公共服务器列表的公钥。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。

设置 `detour` 时，Psiphon 通过该出站连接，并且只使用可经代理工作的协议。
