# Validation Notes

This add-on was initially modeled against live VyOS syslog with this shape:

```text
Jun 30 19:13:37 <relay-ip> Jun 30 19:13:36 vyos-rtr-n1 kernel: [ipv4-NAM-LAN-to-DMZ-v4-900000-A]IN=eth0 OUT=eth2 SRC=<src-ip> DST=<dest-ip> PROTO=TCP SPT=<src-port> DPT=<dest-port>
Jun 30 19:13:36 <relay-ip> Jun 30 19:13:36 vyos-rtr-n2 bgpd[2622]: [EC 100663299] Can't get remote address and port: Transport endpoint is not connected
```

Live classification check over a 30 minute window:

```text
class             count
vyos:netfilter     31336
vyos:kea:dhcp       3440
vyos:syslog          300
```

Top extracted netfilter combinations from the same window:

```text
ruleset              rule     action  proto  dest_port  count
NAM-LAN-to-DMZ-v4    900000   A       TCP    443        11100
NAM-LAN-to-DMZ-v4    99       A       UDP    53         5661
NAM-LAN-to-DMZ-v4    900000   A       UDP    443        2989
```

The public sample file is sanitized and uses documentation IP ranges.

Other daemon processes observed in the live stream and handled by `vyos:syslog`:

```text
pdns-recursor
bgpd
greenos-hostsd
vyos-hostsd
systemd
chronyd
greenos-http-api
```

Kea message families observed and handled by `vyos:kea:dhcp`:

```text
COMMAND_RECEIVED
DHCP4_PACKET_RECEIVED
DHCP4_PACKET_SEND
DHCP4_LEASE_ALLOC
DHCP4_LEASE_REUSE
DHCP4_LEASE_OFFER
DHCP4_INIT_REBOOT
DHCP6_PACKET_RECEIVED
DHCP6_PACKET_SEND
DHCP6_LEASE_RENEW
DHCP6_LEASE_ADVERT
DHCP6_LEASE_REUSE
DHCP6_ADDR_REG_INFORM_FAIL
DHCPSRV_MEMFILE_LFC_START
DHCPSRV_MEMFILE_LFC_EXECUTE
DHCP_DDNS_NO_MATCH
DHCP_DDNS_NO_FWD_MATCH_ERROR
```
