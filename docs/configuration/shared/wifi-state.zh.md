---
icon: material/new-box
---

# Wi-Fi 状态

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: macOS 支持

!!! quote "sing-box 1.13.0 中的更改"

    :material-plus: Linux 支持  
    :material-plus: Windows 支持

sing-box 可以监控 Wi-Fi 状态，以启用基于 `wifi_ssid` 和 `wifi_bssid` 的路由规则。

### 平台支持

| 平台            | 支持              | 备注           |
|-----------------|------------------|----------------|
| Android         | :material-check: | 仅图形客户端    |
| Apple 平台      | :material-check: | 图形客户端；macOS 亦可通过 `ipconfig` |
| Linux           | :material-check: | 需要支持的守护进程 |
| Windows         | :material-check: | WLAN API       |
| 其他            | :material-close: |                |

### Linux

!!! question "自 sing-box 1.13.0 起"

支持以下后端，将按优先级顺序自动探测：

| 后端              | 接口         |
|------------------|-------------|
| NetworkManager   | D-Bus       |
| IWD              | D-Bus       |
| wpa_supplicant   | Unix socket |
| ConnMan          | D-Bus       |

### Windows

!!! question "自 sing-box 1.13.0 起"

使用 Windows WLAN API。

### macOS

!!! question "自 sing-box 1.14.0 起"

在图形客户端之外，通过 `networksetup -listallhardwareports` 找到 Wi-Fi 接口，并从 `ipconfig getsummary` 读取 SSID 与 BSSID，无需定位权限。状态在接口变化时刷新，并每 15 秒轮询一次。
