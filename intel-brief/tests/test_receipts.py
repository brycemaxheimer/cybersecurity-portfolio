import ipaddress
import json
import os
import re
import unittest
from datetime import datetime, timezone

import yaml

from intel_brief.config import KQL_SCHEMA
from intel_brief.receipts import Bench, baseline, cases, summarize
from intel_brief.receipts.engine import Engine, datatable, literal, parse_columns
from intel_brief.receipts.oracle import Rule, Unsupported, wildcard_regex
from intel_brief.receipts.oracle import literal as sigma_literal

SCHEMA = json.loads(KQL_SCHEMA.read_text(encoding="utf-8"))
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)

RULE = """
title: Widget launched with the frobnicate flag
logsource: {product: windows, category: process_creation}
detection:
  selection_parent:
    ParentImage|endswith: '\\launcher.exe'
  selection_child:
    Image|endswith: ['\\widget.exe', '\\gadget.exe']
    CommandLine|contains: '--frobnicate'
  filter_main:
    CommandLine|contains: '--dry-run'
  condition: all of selection_* and not filter_main
"""
# What pySigma's kusto backend emits for RULE (shape, not a copy of its output).
KQL = ('DeviceProcessEvents\n| where InitiatingProcessFolderPath endswith "\\\\launcher.exe" and '
       '((FolderPath endswith "\\\\widget.exe" or FolderPath endswith "\\\\gadget.exe") and '
       'ProcessCommandLine contains "--frobnicate") and (not(ProcessCommandLine contains "--dry-run"))')


def rule(text=RULE) -> Rule:
    return Rule(yaml.safe_load(text))


class OracleTest(unittest.TestCase):
    def test_wildcards_and_escapes(self):
        self.assertTrue(re.fullmatch(wildcard_regex("C:\\\\*\\a?.exe"), "C:\\Tools\\ab.exe"))  # \\* = backslash, wildcard
        self.assertTrue(re.fullmatch(wildcard_regex("C:\\*"), "C:*"))  # \* = a literal asterisk
        self.assertFalse(re.fullmatch(wildcard_regex("C:\\*"), "C:\\Tools"))
        self.assertEqual(sigma_literal("a\\*b*c?"), "a*bcx")
        self.assertTrue(re.fullmatch(wildcard_regex("C:\\\\Temp"), "C:\\Temp"))

    def test_matches_case_insensitively(self):
        ev = {"ParentImage": "C:\\Apps\\LAUNCHER.EXE", "Image": "D:\\x\\Widget.exe", "CommandLine": "w --FROBNICATE"}
        self.assertTrue(rule().matches(ev))

    def test_filter_and_alternatives(self):
        ev = {"ParentImage": "C:\\launcher.exe", "Image": "C:\\gadget.exe", "CommandLine": "--frobnicate"}
        self.assertTrue(rule().matches(ev))
        self.assertFalse(rule().matches({**ev, "CommandLine": "--frobnicate --dry-run"}))
        self.assertFalse(rule().matches({**ev, "Image": "C:\\other.exe"}))

    def test_precedence_all_and_null(self):
        r = rule("""
logsource: {product: windows, category: process_creation}
detection:
  a: {CommandLine|contains|all: ['one', 'two']}
  b: {User: null}
  c: {Image|endswith: '\\x.exe'}
  condition: a or b and c
""")
        self.assertTrue(r.matches({"CommandLine": "two then one", "User": "u"}))
        self.assertFalse(r.matches({"CommandLine": "only one", "User": "u", "Image": "C:\\x.exe"}))
        self.assertTrue(r.matches({"CommandLine": "none", "Image": "C:\\x.exe"}))

    def test_unsupported_rules_say_so(self):
        for detection in ("a: {Image|base64offset: x}\n  condition: a", "a: [one, two]\n  condition: a",
                          "a: {Image: x}\n  condition: a | count() > 5", "a: {Image: x}\n  condition: a and missing"):
            with self.assertRaises(Unsupported, msg=detection):
                rule(f"logsource: {{product: windows, category: process_creation}}\ndetection:\n  {detection}\n")


class CasesTest(unittest.TestCase):
    def test_cases_cover_both_labels(self):
        built = {c.name: c for c in cases.build(rule())}
        self.assertTrue(built["every selection"].expected)
        self.assertTrue(built["letter case changed"].expected)
        self.assertFalse(built["filter_main applied"].expected)
        self.assertFalse(built["CommandLine broken"].expected)
        self.assertTrue(built["selection_child alternative 2"].expected)

    def test_same_field_constraints_are_combined(self):
        r = rule("""
logsource: {product: windows, category: process_creation}
detection:
  sel_a: {Image|endswith: '\\tool.exe'}
  sel_b: {Image|contains: '\\Temp\\'}
  condition: sel_a and sel_b
""")
        self.assertTrue(cases.build(r)[0].expected)

    def test_regex_sample_matches(self):
        for pattern in (r"^ab[0-9]{2}x$", r"(foo|bar)\d+", r"[A-Z]+\.log"):
            self.assertRegex(cases.regex_sample(pattern), pattern)

    def test_rows_map_to_xdr_columns(self):
        _table, mapping, defaults = cases.target(rule())
        row = cases.to_row({"Image": "C:\\Apps\\widget.exe"}, mapping, {}, defaults)
        self.assertEqual((row["FolderPath"], row["FileName"], row["ActionType"]), ("C:\\Apps\\widget.exe", "widget.exe", "ProcessCreated"))
        net = cases.TABLES["network_connection"][1]
        self.assertIsNone(cases.to_row({"DestinationPort": "zz"}, net, {"RemotePort": "int"}, {}))
        with self.assertRaises(Unsupported):
            cases.to_row({"CurrentDirectory": "C:\\"}, mapping, {}, {})

    def test_every_mapped_column_exists(self):
        for table, mapping, defaults in cases.TABLES.values():
            cols = {n for n, _ in parse_columns(SCHEMA[table])}
            self.assertLessEqual(set(mapping.values()) | set(defaults) | set(cases.NAME_OF.values()) & cols, cols, table)


class EngineLiteralTest(unittest.TestCase):
    def test_literals(self):
        self.assertEqual(literal('say "hi"', "string"), '@"say ""hi"""')
        self.assertEqual(literal("C:\\x", "string"), '@"C:\\x"')
        self.assertEqual(literal(None, "long"), "long(null)")
        self.assertEqual(literal(7, "int"), "int(7)")
        self.assertEqual(literal(NOW, "datetime"), "datetime(2026-11-10T12:00:00.000000Z)")
        self.assertTrue(datatable([("A", "string")], [{"A": "x"}]).startswith("datatable(['A']:string)["))


class BaselineTest(unittest.TestCase):
    def test_columns_exist_and_build_is_deterministic(self):
        rows = baseline.build(NOW)
        self.assertEqual(rows, baseline.build(NOW))
        for table, table_rows in rows.items():
            cols = {n for n, _ in parse_columns(SCHEMA[table])}
            for r in table_rows:
                self.assertLessEqual(set(r), cols, table)

    def test_only_documentation_and_private_addresses(self):
        nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "10.0.0.0/8")]
        for r in baseline.build(NOW)["DeviceNetworkEvents"]:
            self.assertTrue(any(ipaddress.ip_address(r["RemoteIP"]) in n for n in nets))
            self.assertTrue(r["RemoteUrl"].endswith((".example", ".example.com", ".example.org", ".example.net")))


ENGINE = Engine(timeout=30)


@unittest.skipUnless(ENGINE.ready(float(os.environ.get("KUSTO_EMULATOR_WAIT", "0"))),
                     "no Kusto emulator; set KUSTO_EMULATOR_URL to run")
class EngineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bench = Bench(ENGINE, SCHEMA, datetime.now(timezone.utc))

    def test_correct_conversion_passes(self):
        r = self.bench.sigma(RULE, KQL)
        self.assertEqual(r["engine"], "ran")
        self.assertEqual(r["cases"]["status"], "pass", r["cases"])
        self.assertEqual(r["baseline"]["hits"], 0)

    def test_broken_conversions_fail(self):
        for wrong in (KQL.replace("endswith", "startswith", 1), KQL.replace("not(", "(", 1),
                      KQL.replace("contains", "contains_cs", 1), KQL.replace(" or ", " and ", 1)):
            self.assertEqual(self.bench.sigma(RULE, wrong)["cases"]["status"], "fail", wrong)

    def test_hunting_query_on_baseline(self):
        r = self.bench.on_baseline('DeviceNetworkEvents | where RemotePort == 443 | summarize count() by RemoteUrl')
        self.assertEqual(r["engine"], "ran")
        self.assertGreater(r["baseline"]["events"], 0)
        self.assertGreater(r["baseline"]["hits"], 0)
        self.assertEqual(self.bench.on_baseline("DeviceNetworkEvents | where NoSuchColumn == 1")["engine"], "error")

    def test_summary_counts(self):
        det = {"sigma": {"yaml": RULE, "conversions": {"kql": {"query": KQL}}},
               "hunting_queries": [{"kql": "DeviceInfo | take 1"}]}
        det["sigma"]["conversions"]["kql"]["receipt"] = self.bench.sigma(RULE, KQL)
        det["hunting_queries"][0]["receipt"] = self.bench.on_baseline("DeviceInfo | take 1")
        s = summarize({"s": det})
        self.assertEqual((s["sigma_kql"], s["sigma_pass"], s["hunting"], s["baseline_hits"]), (1, 1, 1, 1))


if __name__ == "__main__":
    unittest.main()
