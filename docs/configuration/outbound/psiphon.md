---
icon: material/new-box
---

!!! question "Since sing-box 1.15.0"

### Structure

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

  ... // Dial Fields
}
```

!!! info ""

    Psiphon is not included by default, rebuild with the `with_psiphon` and `PSIPHON_DISABLE_QUIC` build tags.

    UDP is relayed through the udpgw service of Psiphon servers, to IP destinations only.

### Fields

#### data_directory

The directory Psiphon keeps its server list and other state in.

`psiphon` is used by default.

#### egress_region

Two-letter country code of the Psiphon server to use. Psiphon chooses if empty.

#### propagation_channel_id

Propagation channel ID, 16 hex digits.

The public ID is used by default.

#### sponsor_id

Sponsor ID, 16 hex digits.

The public ID is used by default.

#### remote_server_list_urls

List of HTTPS URLs of the signed and compressed server list, tried in order.

The public server list is used by default.

#### remote_server_list_signature_public_key

Base64 public key that verifies the server list.

The key of the public server list is used by default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.

With `detour`, Psiphon connects through the detour outbound and only uses protocols that work over a proxy.
