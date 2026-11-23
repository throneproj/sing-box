!!! quote "sing-box 1.15.0 中的更改"

    :material-plus: [geoip_file](#geoip_file)  
    :material-plus: [geoip6_file](#geoip6_file)  
    :material-plus: [bridges](#bridges)  
    :material-plus: [exit_countries](#exit_countries)

### 结构

```json
{
  "type": "tor",
  "tag": "tor-out",

  "executable_path": "/usr/bin/tor",
  "extra_args": [],
  "data_directory": "$HOME/.cache/tor",
  "geoip_file": "",
  "geoip6_file": "",
  "bridges": [],
  "exit_countries": [],
  "torrc": {
    "ClientOnly": 1
  },

  ... // 拨号字段
}
```

!!! info ""

    默认安装不包含嵌入式 Tor, 参阅 [安装](/zh/installation/build-from-source/#构建标记)。

### 字段

#### executable_path

Tor 可执行文件路径

如果设置，将覆盖嵌入式 Tor。

#### extra_args

启动 Tor 时传递的附加参数列表。

#### data_directory

==推荐==

Tor 的数据目录。

如未设置，每次启动都需要长时间。

#### geoip_file

!!! question "自 sing-box 1.15.0 起"

Tor 用于 IPv4 地址的 GeoIP 数据库路径。

如未设置或文件不存在，将使用数据目录中的 `geoip`，否则使用 Tor 的默认路径。

#### geoip6_file

!!! question "自 sing-box 1.15.0 起"

Tor 用于 IPv6 地址的 GeoIP 数据库路径。

如未设置或文件不存在，将使用数据目录中的 `geoip6`，否则使用 Tor 的默认路径。

#### bridges

!!! question "自 sing-box 1.15.0 起"

网桥行列表，可带或不带开头的 `Bridge` 关键字。

支持普通网桥以及 `obfs4`、`webtunnel`、`meek_lite`（或 `meek`）和 `snowflake` 网桥。

可插拔传输在 sing-box 内部运行，并通过此出站的拨号字段连接。

与 torrc 参数 `Bridge`、`UseBridges` 和 `ClientTransportPlugin` 冲突。

!!! info ""

    默认安装不包含可插拔传输，需使用 `with_tor_transports` 构建标记重新构建。

#### exit_countries

!!! question "自 sing-box 1.15.0 起"

两位国家代码列表，Tor 将仅使用位于这些国家的出口中继。

需要 GeoIP 数据库，参阅 [geoip_file](#geoip_file)。

与 torrc 参数 `ExitNodes` 冲突。

#### torrc

torrc 参数表。

参阅 [tor(1)](https://linux.die.net/man/1/tor)。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
