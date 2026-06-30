import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LINES = (ROOT / "samples" / "vyos_syslog_sanitized.log").read_text().splitlines()

NETFILTER_RE = re.compile(
    r"\s(?:vyos-[A-Za-z0-9_.-]+|\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?"
    r"vyos-[A-Za-z0-9_.-]+\s+kernel:\s+\[ipv[46]-"
)
SYSLOG_RE = re.compile(
    r"^(?:<\d+>)?(?P<syslog_time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<syslog_relay_host>\S+)\s+"
    r"(?:(?P<vyos_time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+)?"
    r"(?P<vyos_host>\S+)\s+"
)
PROGRAM_RE = re.compile(
    r"^(?:<\d+>)?\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
    r"(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?\S+\s+"
    r"(?P<process>[A-Za-z0-9_./-]+)(?:\[(?P<pid>\d+)\])?:"
)
RULE_RE = re.compile(r"kernel:\s+\[(?P<vyos_rule>.+?)\](?P<vyos_netfilter_payload>.*)$")
RULE_PARTS_RE = re.compile(r"^(?P<ip_version>ipv[46])-(?P<vyos_ruleset>.+)-(?P<vyos_rule_num>\d+)-(?P<action_code>[A-Z])$")
KV_RE = re.compile(r"(?P<key>[A-Z_]+)=(?P<value>\"[^\"]*\"|[^ ]+)")
KEA_HEADER_RE = re.compile(
    r"(?P<kea_time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<log_level>[A-Z]+)\s+\[(?P<kea_logger>[^/\]]+)/(?P<kea_pid>\d+)\.(?P<kea_thread>\d+)\]\s+"
    r"(?P<kea_message_id>[A-Z0-9_]+)\s+(?P<kea_message>.*)$"
)
KEA_PACKET_RE = re.compile(
    r"\[hwtype=(?P<hwtype>\d+)\s+(?P<mac>[0-9a-f:]+)\],\s+"
    r"cid=\[(?P<client_id>[0-9a-f:]+)\],\s+tid=(?P<transaction_id>0x[0-9a-f]+):\s+"
    r".*?(?P<dhcp_message>DHCP[A-Z0-9_-]+)\s+\(type\s+(?P<dhcp_message_type>\d+)\)"
    r".*?from\s+(?P<src>\d{1,3}(?:\.\d{1,3}){3}):(?P<src_port>\d+)"
    r"\s+to\s+(?P<dest>\d{1,3}(?:\.\d{1,3}){3}):(?P<dest_port>\d+)"
    r"\s+on interface\s+(?P<interface>\S+)"
)
KEA_LEASE_RE = re.compile(r"lease\s+(?P<lease_ip>\d{1,3}(?:\.\d{1,3}){3})\s+has been (?P<lease_action>allocated|renewed|released)(?:\s+for\s+(?P<lease_duration>\d+)\s+seconds)?")
KEA_DDNS_RE = re.compile(r"(?P<log_level>ERROR|WARN)\s+(?P<kea_message_id>DHCP_DDNS_[A-Z0-9_]+)(?:\s+Request ID\s+(?P<request_id>[0-9A-F]+):)?\s+(?P<kea_message>.*?)(?:Type:\s+(?P<ddns_change_type_num>\d+)\s+\((?P<ddns_change_type>CHG_[A-Z]+)\))?$")
DDNS_DETAIL_RE = re.compile(r"(?P<ddns_detail_key>FQDN|IP Address|DHCID):\s+\[(?P<ddns_detail_value>[^\]]*)\]")
QUOTED_KV_RE = re.compile(r"(?P<key>[A-Za-z][A-Za-z0-9_-]+)=\"(?P<value>[^\"]*)\"")


def parse_netfilter(line):
    match = RULE_RE.search(line)
    assert match, line
    rule_parts = RULE_PARTS_RE.match(match.group("vyos_rule"))
    assert rule_parts, match.group("vyos_rule")
    fields = {item.group("key"): item.group("value") for item in KV_RE.finditer(match.group("vyos_netfilter_payload"))}
    fields.update(rule_parts.groupdict())
    return fields


class VyOSParsingTests(unittest.TestCase):
    def test_netfilter_sourcetype_detection(self):
        self.assertTrue(NETFILTER_RE.search(SAMPLE_LINES[0]))
        self.assertFalse(NETFILTER_RE.search(SAMPLE_LINES[1]))
        self.assertTrue(NETFILTER_RE.search(SAMPLE_LINES[2]))

    def test_syslog_header_extraction(self):
        parsed = SYSLOG_RE.search(SAMPLE_LINES[0]).groupdict()
        self.assertEqual(parsed["syslog_relay_host"], "192.0.2.3")
        self.assertEqual(parsed["vyos_host"], "vyos-rtr-n1")
        self.assertEqual(parsed["vyos_time"], "Jun 30 19:13:36")

    def test_daemon_program_extraction(self):
        parsed = PROGRAM_RE.search(SAMPLE_LINES[1]).groupdict()
        self.assertEqual(parsed, {"process": "bgpd", "pid": "2622"})

    def test_tcp_netfilter_fields(self):
        fields = parse_netfilter(SAMPLE_LINES[0])
        self.assertEqual(fields["ip_version"], "ipv4")
        self.assertEqual(fields["vyos_ruleset"], "NAM-LAN-to-DMZ-v4")
        self.assertEqual(fields["vyos_rule_num"], "900000")
        self.assertEqual(fields["action_code"], "A")
        self.assertEqual(fields["IN"], "eth0")
        self.assertEqual(fields["OUT"], "eth2")
        self.assertEqual(fields["SRC"], "192.0.2.10")
        self.assertEqual(fields["DST"], "203.0.113.10")
        self.assertEqual(fields["PROTO"], "TCP")
        self.assertEqual(fields["SPT"], "57723")
        self.assertEqual(fields["DPT"], "443")
        self.assertIn("DF", SAMPLE_LINES[0])
        self.assertIn("ACK", SAMPLE_LINES[0])
        self.assertIn("PSH", SAMPLE_LINES[0])
        self.assertIn("FIN", SAMPLE_LINES[0])

    def test_udp_netfilter_fields_with_duplicate_len_last_value_wins_like_common_kv_parsers(self):
        fields = parse_netfilter(SAMPLE_LINES[2])
        self.assertEqual(fields["vyos_rule_num"], "99")
        self.assertEqual(fields["PROTO"], "UDP")
        self.assertEqual(fields["SPT"], "43178")
        self.assertEqual(fields["DPT"], "53")
        self.assertEqual(fields["LEN"], "69")

    def test_kea_header_and_lease_extraction(self):
        header = KEA_HEADER_RE.search(SAMPLE_LINES[3]).groupdict()
        self.assertEqual(header["log_level"], "INFO")
        self.assertEqual(header["kea_logger"], "kea-dhcp4.leases")
        self.assertEqual(header["kea_message_id"], "DHCP4_LEASE_ALLOC")
        lease = KEA_LEASE_RE.search(SAMPLE_LINES[3]).groupdict()
        self.assertEqual(lease["lease_ip"], "192.0.2.227")
        self.assertEqual(lease["lease_action"], "allocated")
        self.assertEqual(lease["lease_duration"], "3600")

    def test_kea_packet_extraction(self):
        packet = KEA_PACKET_RE.search(SAMPLE_LINES[4]).groupdict()
        self.assertEqual(packet["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(packet["client_id"], "ff:00:11:22:33:44")
        self.assertEqual(packet["transaction_id"], "0xd8a1b766")
        self.assertEqual(packet["dhcp_message"], "DHCPACK")
        self.assertEqual(packet["src"], "192.0.2.4")
        self.assertEqual(packet["src_port"], "67")
        self.assertEqual(packet["dest"], "192.0.2.227")
        self.assertEqual(packet["dest_port"], "68")
        self.assertEqual(packet["interface"], "eth0")

    def test_kea_ddns_error_and_detail_extraction(self):
        ddns = KEA_DDNS_RE.search(SAMPLE_LINES[5]).groupdict()
        self.assertEqual(ddns["log_level"], "ERROR")
        self.assertEqual(ddns["kea_message_id"], "DHCP_DDNS_NO_FWD_MATCH_ERROR")
        self.assertEqual(ddns["request_id"], "0002016B0B18")
        self.assertEqual(ddns["ddns_change_type"], "CHG_ADD")
        detail = DDNS_DETAIL_RE.search(SAMPLE_LINES[6]).groupdict()
        self.assertEqual(detail["ddns_detail_key"], "FQDN")
        self.assertEqual(detail["ddns_detail_value"], "example-host.")

    def test_quoted_key_value_daemon_extraction(self):
        fields = {match.group("key").replace("-", "_"): match.group("value") for match in QUOTED_KV_RE.finditer(SAMPLE_LINES[7])}
        self.assertEqual(fields["msg"], "Sending SERVFAIL during resolve")
        self.assertEqual(fields["subsystem"], "syncres")
        self.assertEqual(fields["prio"], "Notice")
        self.assertEqual(fields["proto"], "udp")
        self.assertEqual(fields["qname"], "example.invalid")
        self.assertEqual(fields["remote"], "192.0.2.85:53811")


if __name__ == "__main__":
    unittest.main()
