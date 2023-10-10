# mod_prometheus

Prometheus exporter for FreeSWITCH

## Building

1. Build FreeSWITCH
2. Install mod_prometheus dependencies

```bash
# For CentOS/Redhat
yum install libmicrohttpd libmicrohttpd-devel

# For Debian/Ubuntu
apt-get install libmicrohttpd libmicrohttpd-dev
```

3. Build mod_prometheus from source

```bash
export PKG_CONFIG_PATH=/usr/local/freeswitch/lib/pkgconfig
./bootstrap.sh
./configure
make
make install
```

## Configuration

##### prometheus.conf.xml

```xml
<configuration name="prometheus.conf" description="PROMETHEUS Module">
  <settings>
    <param name="listen-ip" value="0.0.0.0"/>
    <param name="listen-port" value="8088"/>
    <param name="metrics-path" value="/metrics"/>
  </settings>
</configuration>
```

## Metrics

### Core

| Name                 | Description                       |
| -------------------- | --------------------------------- |
| `freeswitch_uptime`  | FreeSWITCH uptime in milliseconds |
| `freeswitch_version` | FreeSWITCH version                |
| `freeswitch_info`    | Information about the FreeSWITCH  |

### Sessions

| Name                         | Description                  |
| ---------------------------- | ---------------------------- |
| `freeswitch_sessions_total`  | Total sessions since startup |
| `freeswitch_sessions_active` | Number of active sessions    |
| `freeswitch_sessions_peak`   | Peak session count           |
| `freeswitch_sessions_max`    | Max sessions                 |

### Sofia

| Name                                           | Description                         |
| ---------------------------------------------- | ----------------------------------- |
| `freeswitch_sofia_profile_info`                | Information about the sofia profile |
| `freeswitch_sofia_profile_calls_total`         | Total number of profile calls       |
| `freeswitch_sofia_profile_registrations`       | Current registrations               |
| `freeswitch_sofia_profile_gateway_info`        | Information about the sofia gateway |
| `freeswitch_sofia_profile_gateway_calls_total` | Total number of gateway calls       |

### RTP

| Name                       | Description                                |
| -------------------------- | ------------------------------------------ |
| `freeswitch_rtp_in_bytes`  | Total number of incoming rtp size in bytes |
| `freeswitch_rtp_out_bytes` | Total number of outgoing rtp size in bytes |
