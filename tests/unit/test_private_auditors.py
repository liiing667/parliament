import sys

import pytest

from parliament import analyze_policy_string

VALID_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}
"""


@pytest.fixture
def auditor_dir(tmp_path):
    """Isolation fixture: a private auditor directory under our control.

    Provides a trusted auditor that records its execution, plus helpers to
    add hostile or broken auditors alongside it. Returns (directory, marker)
    where the trusted auditor appends its module __name__ to ``marker``.
    """
    directory = tmp_path / "private_auditors"
    directory.mkdir()
    marker = tmp_path / "trusted_ran.txt"
    (directory / "trusted.py").write_text(
        "def audit(policy):\n"
        "    with open({!r}, 'a') as f:\n"
        "        f.write(__name__ + '\\n')\n".format(str(marker))
    )
    return directory, marker


class TestPrivateAuditors:
    """Tests for the private auditor boundary and failure isolation."""

    def test_trusted_auditor_runs(self, auditor_dir):
        """A legitimate auditor from an explicit custom path stays usable."""
        directory, marker = auditor_dir
        policy = analyze_policy_string(
            VALID_POLICY, private_auditors_custom_path=str(directory)
        )
        assert "EXCEPTION" not in policy.finding_ids
        assert marker.read_text().strip() != ""

    def test_import_time_failure_is_isolated(self, auditor_dir):
        """An auditor that raises at import time must not abort analysis or
        prevent the other auditors from running."""
        directory, marker = auditor_dir
        (directory / "broken.py").write_text("raise RuntimeError('boom')\n")
        policy = analyze_policy_string(
            VALID_POLICY, private_auditors_custom_path=str(directory)
        )
        assert "EXCEPTION" in policy.finding_ids
        exception_findings = [f for f in policy.findings if f.issue == "EXCEPTION"]
        assert len(exception_findings) == 1
        assert exception_findings[0].location["private_auditor"] == "broken"
        assert "boom" in exception_findings[0].detail
        assert marker.read_text().strip() != ""

    def test_audit_time_failure_is_isolated(self, auditor_dir):
        """An auditor that raises during audit() is contained and reported."""
        directory, marker = auditor_dir
        (directory / "crasher.py").write_text(
            "def audit(policy):\n    raise ValueError('audit exploded')\n"
        )
        policy = analyze_policy_string(
            VALID_POLICY, private_auditors_custom_path=str(directory)
        )
        assert "EXCEPTION" in policy.finding_ids
        assert marker.read_text().strip() != ""

    def test_shared_import_state_not_polluted(self, auditor_dir):
        """Loading auditors must not leak entries into sys.path/sys.modules
        and must not let an auditor shadow a real module of the same name."""
        directory, _ = auditor_dir
        (directory / "json.py").write_text("def audit(policy):\n    pass\n")
        path_before = list(sys.path)
        modules_before = set(sys.modules)
        real_json = sys.modules["json"]
        analyze_policy_string(
            VALID_POLICY, private_auditors_custom_path=str(directory)
        )
        assert sys.path == path_before
        assert set(sys.modules) == modules_before
        assert sys.modules["json"] is real_json
        import json

        assert json is real_json

    def test_auditor_module_names_do_not_collide(self, auditor_dir):
        """Auditors load under a parliament-specific namespace, never under
        an importable 'private_auditors' package name."""
        directory, marker = auditor_dir
        analyze_policy_string(
            VALID_POLICY, private_auditors_custom_path=str(directory)
        )
        loaded_name = marker.read_text().strip()
        assert loaded_name == "_parliament_private_auditor_trusted"
        assert "private_auditors" not in sys.modules

    def test_empty_custom_path_still_raises(self, tmp_path):
        """Existing contract: an explicit path with no auditors is an error."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(Exception, match="No private auditors found"):
            analyze_policy_string(
                VALID_POLICY, private_auditors_custom_path=str(empty_dir)
            )

    def test_missing_custom_path_raises(self, tmp_path):
        """A non-existent explicit path is treated as 'no auditors found'."""
        with pytest.raises(Exception, match="No private auditors found"):
            analyze_policy_string(
                VALID_POLICY,
                private_auditors_custom_path=str(tmp_path / "does-not-exist"),
            )

    def test_default_analysis_without_private_auditors(self):
        """Built-in analysis is unaffected when no private auditors exist."""
        policy = analyze_policy_string(VALID_POLICY)
        assert "EXCEPTION" not in policy.finding_ids
