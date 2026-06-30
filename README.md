# Technology Add-on for VyOS

`TA-vyos` provides basic Splunk knowledge objects for VyOS syslog, with a focus on VyOS firewall logs emitted by the Linux kernel/netfilter path.

The add-on classifies:

- `vyos:netfilter` for kernel firewall records such as `kernel: [ipv4-NAME-900000-A]IN=... SRC=... DST=...`
- `vyos:kea:dhcp` for Kea DHCPv4, DHCPv6, and DHCP-DDNS logs
- `vyos:syslog` for regular VyOS daemon logs such as `bgpd[2622]: ...`

## Why this exists

VyOS firewall logs are close to Linux netfilter/iptables logs, but VyOS prefixes each record with useful rule metadata:

```text
kernel: [ipv4-NAM-LAN-to-DMZ-v4-900000-A]IN=br10 OUT=eth2 SRC=192.0.2.20 DST=198.51.100.53 PROTO=UDP SPT=43178 DPT=53
```

Generic syslog parsing leaves this as `sourcetype=syslog`. Generic netfilter parsing usually misses the VyOS rule name. This TA keeps the standard netfilter fields and adds VyOS-specific fields.

## Extracted fields

For `vyos:netfilter`:

- `vyos_rule`
- `ip_version`
- `vyos_ruleset`
- `vyos_rule_num`
- `action_code`
- `action`
- `IN`, `OUT`, `SRC`, `DST`, `PROTO`, `SPT`, `DPT`, `TTL`, `LEN`
- `tcp_flag`
- `ip_flag`
- Aliases: `src`, `dest`, `src_port`, `dest_port`, `transport`, `inbound_interface`, `outbound_interface`

For `vyos:kea:dhcp`:

- `process`
- `pid`
- `kea_time`
- `log_level`
- `kea_logger`
- `kea_pid`
- `kea_thread`
- `kea_message_id`
- `kea_message`
- `dhcp_version`
- `action`
- `hwtype`
- `mac`
- `client_id`
- `transaction_id`
- `dhcp_message`
- `dhcp_message_type`
- `src`, `src_port`, `dest`, `dest_port`, `interface`
- `lease_ip`, `lease_action`, `lease_duration`
- `request_id`, `ddns_change_type`, `ddns_change_type_num`
- `ddns_detail_key`, `ddns_detail_value`

For `vyos:syslog`:

- `syslog_time`
- `syslog_relay_host`
- `vyos_time`
- `vyos_host`
- `process`
- `pid`
- `log_level`
- `daemon_message_id`
- `daemon_message`
- quoted key/value pairs from structured daemon logs, such as PowerDNS Recursor `msg`, `subsystem`, `prio`, `qname`, and `remote`

## Installation

Copy this directory to Splunk:

```bash
$SPLUNK_HOME/etc/apps/TA-vyos
```

Restart Splunk or reload deploy-server-managed apps.

## Inputs

This TA expects VyOS logs to arrive as syslog, commonly from UDP/TCP `1514`.

Example input:

```ini
[udp://1514]
index = security
sourcetype = syslog
connection_host = ip
```

The TA rewrites matching VyOS records from `syslog` to `vyos:netfilter` or `vyos:syslog` at parse time for `source::udp:1514` and `source::tcp:1514`.

If your source name differs, copy the `TRANSFORMS-vyos_sourcetype` line from `default/props.conf` into a local source stanza matching your input.

## Example searches

```spl
index=security sourcetype=vyos:netfilter
| stats count by src dest dest_port transport action vyos_ruleset vyos_rule_num
```

```spl
index=security sourcetype=vyos:kea:dhcp
| stats count by process kea_logger kea_message_id action
```

```spl
index=security sourcetype=vyos:syslog process=bgpd
| table _time host process pid _raw
```

## Notes

- Existing indexed events keep their old sourcetype. Sourcetype rewriting applies to new events after installation.
- The TA is intentionally small and does not claim complete CIM compliance yet.
- Logs were modeled from VyOS syslog shaped like Linux netfilter firewall logs, Kea DHCP/DDNS logs, PowerDNS Recursor structured logs, and FRR/BGP daemon messages.

## Development

Run parser tests:

```bash
python3 -m unittest discover -s tests
```
