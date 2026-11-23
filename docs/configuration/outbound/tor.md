!!! quote "Changes in sing-box 1.15.0"

    :material-plus: [geoip_file](#geoip_file)  
    :material-plus: [geoip6_file](#geoip6_file)  
    :material-plus: [bridges](#bridges)  
    :material-plus: [exit_countries](#exit_countries)

### Structure

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

  ... // Dial Fields
}
```

!!! info ""

    Embedded Tor is not included by default, see [Installation](/installation/build-from-source/#build-tags).

### Fields

#### executable_path

The path to the Tor executable.

Embedded Tor will be ignored if set.

#### extra_args

List of extra arguments passed to the Tor instance when started.

#### data_directory

==Recommended==

The data directory of Tor.

Each start will be very slow if not specified.

#### geoip_file

!!! question "Since sing-box 1.15.0"

The path to the GeoIP database Tor uses for IPv4 addresses.

`geoip` in the data directory will be used if empty or missing, otherwise the default path of Tor.

#### geoip6_file

!!! question "Since sing-box 1.15.0"

The path to the GeoIP database Tor uses for IPv6 addresses.

`geoip6` in the data directory will be used if empty or missing, otherwise the default path of Tor.

#### bridges

!!! question "Since sing-box 1.15.0"

List of bridge lines, with or without the leading `Bridge` keyword.

Vanilla, `obfs4`, `webtunnel`, `meek_lite` (or `meek`) and `snowflake` bridges are supported.

Pluggable transports run inside sing-box and connect through the dial fields of this outbound.

Conflicts with the `Bridge`, `UseBridges` and `ClientTransportPlugin` torrc options.

!!! info ""

    Pluggable transports are not included by default, rebuild with the `with_tor_transports` build tag.

#### exit_countries

!!! question "Since sing-box 1.15.0"

List of two-letter country codes, Tor will only use exit relays in these countries.

Requires a GeoIP database, see [geoip_file](#geoip_file).

Conflicts with the `ExitNodes` torrc option.

#### torrc

Map of torrc options.

See [tor(1)](https://linux.die.net/man/1/tor) for details.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
