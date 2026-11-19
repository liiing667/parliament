import copy

from parliament import analyze_policy_string, enhance_finding, override_config
from parliament.cli import is_finding_filtered
from parliament.finding import Finding, dedupe_findings


TWO_BAD_PRINCIPALS = """{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "not-an-arn"}, "Action": "*", "Resource": "*"},
    {"Effect": "Allow", "Principal": {"AWS": "also-not-an-arn"}, "Action": "*", "Resource": "*"}
  ]
}"""


class TestFindingIdentity:
    def test_identity_ignores_severity_and_reporting_fields(self):
        first = Finding("ISSUE", "detail", {"filepath": "a.json", "line": 1})
        second = Finding("ISSUE", "detail", {"line": 1, "filepath": "a.json"})
        first.severity = "LOW"
        second.severity = "HIGH"
        second.title = "Different title"
        assert first.identity == second.identity
        assert first == second
        assert hash(first) == hash(second)

    def test_identity_distinguishes_distinct_locations(self):
        first = Finding("ISSUE", "detail", {"filepath": "a.json"})
        second = Finding("ISSUE", "detail", {"filepath": "b.json"})
        assert first.identity != second.identity
        assert first != second

    def test_identity_handles_nested_list_detail_and_location(self):
        finding = Finding(
            "RESOURCE_STAR", ["s3:GetObject"], {"actions": ["a", "b"], "line": 1}
        )
        assert hash(finding.identity) == hash(finding.identity)

    def test_dedupe_collapses_identical_findings(self):
        first = Finding("ISSUE", "detail", {"filepath": "a.json"})
        second = Finding("ISSUE", "detail", {"filepath": "a.json"})
        other = Finding("ISSUE", "detail", {"filepath": "b.json"})
        unique = dedupe_findings([first, second, other])
        assert unique == [first, other]


class TestSingleEnhancement:
    def test_severity_is_resolved_once_at_analysis_time(self):
        policy = analyze_policy_string(
            TWO_BAD_PRINCIPALS, "rp.json", ignore_private_auditors=True
        )
        assert len(policy.findings) == 2
        for finding in policy.findings:
            assert finding.severity == "MEDIUM"
            assert finding.title == "Unknown AWS principal"

    def test_malformed_json_findings_are_also_enhanced(self):
        policy = analyze_policy_string("not json")
        finding = policy.findings[0]
        assert finding.issue == "MALFORMED_JSON"
        assert finding.severity == "CRITICAL"

    def test_enhance_finding_does_not_mutate_the_source(self):
        policy = analyze_policy_string(
            TWO_BAD_PRINCIPALS, ignore_private_auditors=True
        )
        original = policy.findings[0]
        original_location = copy.deepcopy(original.location)
        enhanced = enhance_finding(original)
        assert enhanced is not original
        assert original.location == original_location
        assert original.severity == enhanced.severity

    def test_enhancement_is_idempotent(self):
        policy = analyze_policy_string(
            TWO_BAD_PRINCIPALS, ignore_private_auditors=True
        )
        before = [(finding.identity, finding.severity) for finding in policy.findings]
        policy.enhance_findings()
        after = [(finding.identity, finding.severity) for finding in policy.findings]
        assert before == after

    def test_unknown_issue_does_not_break_filtering(self):
        policy = analyze_policy_string(
            '{"Version": "2012-10-17", "Statement": '
            '{"Effect": "Allow", "Action": "*", "Resource": "*"}}',
            ignore_private_auditors=True,
        )
        policy.add_finding(
            "CUSTOM_ISSUE", detail="x", location={"filepath": "c.json"}
        )
        policy.enhance_findings()
        custom = [f for f in policy.findings if f.issue == "CUSTOM_ISSUE"][0]
        assert is_finding_filtered(custom, "HIGH") is True
        assert is_finding_filtered(custom, "LOW") is False


class TestIgnoreLocations:
    def test_string_ignore_location_suppresses_the_finding(self, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(
            '{"Version": "2012-10-17", "Statement": '
            '{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}'
        )
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "RESOURCE_STAR:\n"
            "  title: Resource star\n"
            "  severity: MEDIUM\n"
            "  group: BAD_PATTERN\n"
            "  ignore_locations:\n"
            '  - filepath: ".*policy\\\\.json"\n'
        )
        override_config(str(config_file))
        try:
            policy = analyze_policy_string(
                policy_file.read_text(),
                str(policy_file),
                ignore_private_auditors=True,
            )
            finding = policy.findings[0]
            assert finding.issue == "RESOURCE_STAR"
            assert is_finding_filtered(finding, "LOW") is True
        finally:
            import parliament

            del parliament.config["RESOURCE_STAR"]

    def test_list_ignore_location_suppresses_when_any_entry_matches(self, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(
            '{"Version": "2012-10-17", "Statement": '
            '{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}'
        )
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "RESOURCE_STAR:\n"
            "  title: Resource star\n"
            "  severity: MEDIUM\n"
            "  group: BAD_PATTERN\n"
            "  ignore_locations:\n"
            "  - filepath:\n"
            '    - ".*other\\\\.json"\n'
            '    - ".*policy\\\\.json"\n'
        )
        override_config(str(config_file))
        try:
            policy = analyze_policy_string(
                policy_file.read_text(),
                str(policy_file),
                ignore_private_auditors=True,
            )
            assert is_finding_filtered(policy.findings[0], "LOW") is True
        finally:
            import parliament

            del parliament.config["RESOURCE_STAR"]
