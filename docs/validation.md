# Validation Notes

This add-on was initially modeled against live VyOS syslog with this shape:

```text
Jun 30 19:13:37 <relay-ip> Jun 30 19:13:36 vyos-rtr-n1 kernel: [ipv4-NAM-LAN-to-DMZ-v4-900000-A]IN=eth0 OUT=eth2 SRC=<src-ip> DST=<dest-ip> PROTO=TCP SPT=<src-port> DPT=<dest-port>
Jun 30 19:13:36 <relay-ip> Jun 30 19:13:36 vyos-rtr-n2 bgpd[2622]: [EC 100663299] Can't get remote address and port: Transport endpoint is not connected
```

Live classification check over a 30 minute window:

```text
host            class             count
vyos-rtr-n1     vyos:netfilter     24984
vyos-rtr-n1     vyos:syslog         1412
vyos-rtr-n2     vyos:syslog         1464
```

Top extracted netfilter combinations from the same window:

```text
ruleset              rule     action  proto  dest_port  count
NAM-LAN-to-DMZ-v4    900000   A       TCP    443        11100
NAM-LAN-to-DMZ-v4    99       A       UDP    53         5661
NAM-LAN-to-DMZ-v4    900000   A       UDP    443        2989
```

The public sample file is sanitized and uses documentation IP ranges.
