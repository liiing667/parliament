"""Regression tests for the shared security-identity boundaries.

These cover the three attack surfaces that must never fail open:
- custom (private) auditor loading and execution
- multi-policy / multi-file scanning
- exceptions raised while evaluating an individual rule
"""
import sys

from parliament import analyze_policy_string
from parliament.cli import analyze_policy_safely, main
from parliament.finding import Finding


POLICY = (
    '{"Version":"2012-10-17","Statement":['
    '{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'
)


def _write_auditor(directory, name, body):
    path = directory / "{}.py".format(name)
    path.write_text(body)
    return path


def test_private_auditor_exception_is_contained_as_finding(tmp_path):
    """A raising private auditor must not propagate; it becomes a finding."""
    _write_auditor(
        tmp_path,
        "boom",
        "def audit(policy):\n    raise RuntimeError('auditor exploded')\n",
    )
    policy = analyze_policy_string(
        POLICY, filepath="p.json", private_auditors_custom_path=str(tmp_path)
    )

    assert policy.error_occurred is True
    exception_findings = [f for f in policy.findings if f.issue == "EXCEPTION"]
    assert len(exception_findings) == 1
    finding = exception_findings[0]
    assert "boom" in finding.detail
    assert finding.location == {
        "private_auditor": "boom",
        "filepath": "p.json",
    }


def test_failing_auditor_does_not_block_other_auditors(tmp_path):
    _write_auditor(
        tmp_path,
        "boom",
        "def audit(policy):\n    raise RuntimeError('auditor exploded')\n",
    )
    _write_auditor(
        tmp_path,
        "good",
        "def audit(policy):\n"
        "    policy.add_finding('GOOD_AUDITOR_RAN', detail='ok', location={})\n",
    )
    policy = analyze_policy_string(
        POLICY, private_auditors_custom_path=str(tmp_path)
    )

    assert "GOOD_AUDITOR_RAN" in policy.finding_ids
    assert "EXCEPTION" in policy.finding_ids


def test_private_auditor_load_failure_is_contained(tmp_path):
    _write_auditor(tmp_path, "syntax_bad", "def audit(:\n")
    policy = analyze_policy_string(
        POLICY, private_auditors_custom_path=str(tmp_path)
    )

    assert policy.error_occurred is True
    assert "EXCEPTION" in policy.finding_ids
    load_failure = next(
        f for f in policy.findings if f.location.get("private_auditor") == "syntax_bad"
    )
    assert "could not be loaded" in load_failure.detail


def test_auditor_directories_keep_distinct_identities(tmp_path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write_auditor(
        dir_a, "same_name", "def audit(p):\n    p.add_finding('FROM_A', location={})\n"
    )
    _write_auditor(
        dir_b, "same_name", "def audit(p):\n    p.add_finding('FROM_B', location={})\n"
    )

    policy_a = analyze_policy_string(
        POLICY, private_auditors_custom_path=str(dir_a)
    )
    policy_b = analyze_policy_string(
        POLICY, private_auditors_custom_path=str(dir_b)
    )

    assert "FROM_A" in policy_a.finding_ids
    assert "FROM_B" in policy_b.finding_ids
    assert "FROM_B" not in policy_a.finding_ids
    assert "FROM_A" not in policy_b.finding_ids
    assert not [
        name for name in sys.modules if "parliament_private_auditor" in name
    ]


def test_findings_have_independent_identities():
    finding_a = Finding("X", "a", {"filepath": "a.json"})
    finding_b = Finding("X", "b", {"filepath": "b.json"})
    finding_a.location["injected"] = True

    assert "injected" not in finding_b.location
    assert finding_b.location == {"filepath": "b.json"}


def test_policies_do_not_share_finding_state():
    policy_a = analyze_policy_string(POLICY, filepath="a.json")
    policy_b = analyze_policy_string(POLICY, filepath="b.json")

    assert {f.location["filepath"] for f in policy_a.findings} == {"a.json"}
    assert {f.location["filepath"] for f in policy_b.findings} == {"b.json"}


def test_statement_exception_does_not_abort_other_statements(monkeypatch):
    import parliament.statement as statement_module

    original = statement_module.get_privilege_info
    calls = {"count": 0}

    def flaky(service, action):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("rule exploded")
        return original(service, action)

    monkeypatch.setattr(statement_module, "get_privilege_info", flaky)
    policy_text = (
        '{"Version":"2012-10-17","Statement":['
        '{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},'
        '{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'
    )
    policy = analyze_policy_string(policy_text, filepath="multi.json")

    assert policy.error_occurred is True
    assert "EXCEPTION" in policy.finding_ids
    assert "RESOURCE_STAR" in policy.finding_ids


def test_safe_wrapper_never_raises_and_flags_error(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("unexpected crash")

    import parliament.cli as cli_module

    monkeypatch.setattr(cli_module, "analyze_policy_string", boom)
    policy, error_occurred = analyze_policy_safely(POLICY, "broken.json")

    assert error_occurred is True
    assert policy.error_occurred is True
    assert policy.findings[0].issue == "EXCEPTION"
    assert policy.findings[0].location["filepath"] == "broken.json"


def test_cli_multifile_scan_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        type(
            "DummyStdin",
            (),
            {"name": "<stdin>", "isatty": lambda self: True},
        )(),
    )
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(POLICY)
    auditor_dir = tmp_path / "auditors"
    auditor_dir.mkdir()
    _write_auditor(
        auditor_dir,
        "boom",
        "def audit(policy):\n    raise RuntimeError('auditor exploded')\n",
    )

    argv = [
        "parliament",
        "--files",
        str(policy_file),
        "--private_auditors",
        str(auditor_dir),
    ]
    assert main(argv) == 1


def test_cli_clean_policy_still_passes(tmp_path, monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        type(
            "DummyStdin",
            (),
            {"name": "<stdin>", "isatty": lambda self: True},
        )(),
    )
    policy_file = tmp_path / "clean.json"
    policy_file.write_text(
        '{"Version":"2012-10-17","Statement":['
        '{"Effect":"Allow","Action":"s3:GetObject",'
        '"Resource":"arn:aws:s3:::bucket/*"}]}'
    )

    assert main(["parliament", "--files", str(policy_file)]) == 0


def test_cli_fails_closed_even_when_exception_muted(tmp_path, monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        type(
            "DummyStdin",
            (),
            {"name": "<stdin>", "isatty": lambda self: True},
        )(),
    )
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(POLICY)
    auditor_dir = tmp_path / "auditors"
    auditor_dir.mkdir()
    _write_auditor(
        auditor_dir,
        "boom",
        "def audit(policy):\n    raise RuntimeError('auditor exploded')\n",
    )
    config_file = tmp_path / "override.yaml"
    config_file.write_text(
        "EXCEPTION:\n  severity: MUTE\n"
        "  title: An exception occurred during the audit.\n"
    )

    argv = [
        "parliament",
        "--files",
        str(policy_file),
        "--private_auditors",
        str(auditor_dir),
        "--config",
        str(config_file),
    ]
    assert main(argv) == 1
