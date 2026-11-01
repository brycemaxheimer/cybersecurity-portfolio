import unittest

import yaml

from intel_brief.detections.schema import FieldCondition, Selection, SigmaRuleDraft
from intel_brief.detections.sigma_build import DraftError, to_yaml


def draft(**kw) -> SigmaRuleDraft:
    base = dict(
        title="Suspicious child of w3wp",
        description="IIS worker spawning a shell.",
        logsource_product="windows",
        logsource_category="process_creation",
        logsource_service="",
        selections=[
            Selection(name="selection_parent", conditions=[FieldCondition(field="ParentImage", modifiers=["endswith"], values=["\\w3wp.exe"])]),
            Selection(name="selection_child", conditions=[FieldCondition(field="Image", modifiers=["endswith"], values=["\\cmd.exe", "\\powershell.exe"])]),
            Selection(name="filter_main", conditions=[FieldCondition(field="CommandLine", modifiers=["contains"], values=["healthcheck"])]),
        ],
        condition="all of selection_* and not filter_main",
        falsepositives=["Admin scripts"],
        level="high",
        attack_tags=["attack.persistence", "attack.t1505.003", "bogus tag"],
    )
    base.update(kw)
    return SigmaRuleDraft(**base)


class SigmaBuildTest(unittest.TestCase):
    def test_builds_valid_yaml(self):
        out = yaml.safe_load(to_yaml(draft(), cves=["CVE-2026-1234"], references=["https://nvd.nist.gov/x"], date="2026-10-31"))
        self.assertEqual(out["detection"]["selection_child"]["Image|endswith"], ["\\cmd.exe", "\\powershell.exe"])
        self.assertIn("cve.2026-1234", out["tags"])
        self.assertNotIn("bogus tag", out["tags"])
        self.assertIn("AI-generated, untested", out["description"])
        self.assertEqual(out["status"], "experimental")

    def test_rejects_unknown_selection_in_condition(self):
        with self.assertRaises(DraftError):
            to_yaml(draft(condition="selection_parent and selection_missing"), cves=[], references=[], date="2026-10-31")

    def test_rejects_condition_injection(self):
        for cond in ["selection_parent | count() > 5", "selection_parent\n  evil: 1", "selection_parent and (", "{x}"]:
            with self.assertRaises(DraftError, msg=cond):
                to_yaml(draft(condition=cond), cves=[], references=[], date="2026-10-31")

    def test_rejects_bad_field_name(self):
        bad = Selection(name="selection_x", conditions=[FieldCondition(field="Image: !!python/object", modifiers=[], values=["a"])])
        with self.assertRaises(DraftError):
            to_yaml(draft(selections=[bad], condition="selection_x"), cves=[], references=[], date="2026-10-31")

    def test_yaml_values_are_quoted_data(self):
        evil = Selection(name="selection_x", conditions=[FieldCondition(field="CommandLine", modifiers=["contains"], values=["!!python/object/apply:os.system ['id']"])])
        text = to_yaml(draft(selections=[evil], condition="selection_x"), cves=[], references=[], date="2026-10-31")
        self.assertEqual(yaml.safe_load(text)["detection"]["selection_x"]["CommandLine|contains"], "!!python/object/apply:os.system ['id']")


if __name__ == "__main__":
    unittest.main()
