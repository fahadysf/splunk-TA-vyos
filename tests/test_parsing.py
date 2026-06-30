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

    def test_udp_netfilter_fields_with_duplicate_len_last_value_wins_like_common_kv_parsers(self):
        fields = parse_netfilter(SAMPLE_LINES[2])
        self.assertEqual(fields["vyos_rule_num"], "99")
        self.assertEqual(fields["PROTO"], "UDP")
        self.assertEqual(fields["SPT"], "43178")
        self.assertEqual(fields["DPT"], "53")
        self.assertEqual(fields["LEN"], "69")


if __name__ == "__main__":
    unittest.main()
