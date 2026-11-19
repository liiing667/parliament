import json

from parliament import analyze_policy_string


DANGEROUS_ACTIONS = [
    "s3:PutBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutLifecycleConfiguration",
    "s3:PutObject",
    "s3:GetObject",
    "s3:DeleteObject",
]


def _policy(statements):
    return analyze_policy_string(
        json.dumps({"Version": "2012-10-17", "Statement": statements}),
        ignore_private_auditors=True,
    )


class TestFullStatementEvaluation:
    """Allow, Deny, Condition and NotAction must all be evaluated so that no
    single statement can end the audit early."""

    def test_unconditional_deny_first_does_not_hide_other_dangerous_allows(self):
        deny_first = _policy(
            [
                {
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": DANGEROUS_ACTIONS,
                    "Resource": "*",
                },
            ]
        )

        # The explicitly denied privilege stays denied.
        assert deny_first.get_allowed_resources("s3", "GetObject") == []

        # Every other dangerous Allow is still surfaced and attributed.
        assert deny_first.get_allowed_resources("s3", "PutBucketPolicy") == ["*"]
        assert deny_first.get_allowed_resources("s3", "PutObject") == ["*"]
        assert deny_first.get_allowed_resources("s3", "DeleteObject") == ["*"]
        allowed_actions = deny_first.get_allowed_actions()
        assert "s3:putbucketpolicy" in allowed_actions
        assert "s3:getobject" not in allowed_actions
        assert "RESOURCE_POLICY_PRIVILEGE_ESCALATION" in deny_first.finding_ids

    def test_conclusion_is_independent_of_statement_order(self):
        deny_first = _policy(
            [
                {
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": DANGEROUS_ACTIONS,
                    "Resource": "*",
                },
            ]
        )
        allow_first = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": DANGEROUS_ACTIONS,
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                },
            ]
        )

        assert deny_first.get_allowed_actions() == allow_first.get_allowed_actions()
        assert (
            deny_first.get_allowed_resources("s3", "GetObject")
            == allow_first.get_allowed_resources("s3", "GetObject")
            == []
        )
        assert (
            deny_first.get_allowed_resources("s3", "PutBucketPolicy")
            == allow_first.get_allowed_resources("s3", "PutBucketPolicy")
            == ["*"]
        )
        assert deny_first.finding_ids == allow_first.finding_ids

    def test_conditional_deny_does_not_suppress_allow(self):
        policy = _policy(
            [
                {
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"aws:MultiFactorAuthPresent": "false"}
                    },
                },
                {
                    "Effect": "Allow",
                    "Action": DANGEROUS_ACTIONS,
                    "Resource": "*",
                },
            ]
        )

        # A conditioned Deny may not apply, so the Allow remains visible.
        assert policy.get_allowed_resources("s3", "GetObject") == ["*"]
        assert "s3:getobject" in policy.get_allowed_actions()

    def test_notaction_deny_does_not_hide_dangerous_allows(self):
        policy = _policy(
            [
                {
                    "Effect": "Deny",
                    "NotAction": "s3:GetObject",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": DANGEROUS_ACTIONS,
                    "Resource": "*",
                },
            ]
        )

        # The NotAction Deny does not explicitly deny any of the referenced
        # privileges, so all dangerous Allows must remain visible.
        assert policy.get_allowed_resources("s3", "PutBucketPolicy") == ["*"]
        assert policy.get_allowed_resources("s3", "PutObject") == ["*"]
        assert policy.get_allowed_resources("s3", "DeleteObject") == ["*"]
        assert policy.get_allowed_resources("s3", "GetObject") == ["*"]
        allowed_actions = policy.get_allowed_actions()
        for action in [
            "s3:putbucketpolicy",
            "s3:putbucketacl",
            "s3:putlifecycleconfiguration",
            "s3:putobject",
            "s3:getobject",
            "s3:deleteobject",
        ]:
            assert action in allowed_actions
        assert "RESOURCE_STAR" in policy.finding_ids

    def test_notaction_deny_alone_grants_nothing(self):
        policy = _policy(
            [
                {
                    "Effect": "Deny",
                    "NotAction": "s3:GetObject",
                    "Resource": "*",
                }
            ]
        )

        assert policy.get_allowed_actions() == []
        assert policy.get_allowed_resources("s3", "PutBucketPolicy") == []
        assert policy.finding_ids == set()

    def test_explicit_deny_on_star_still_denies_specific_resource_allow(self):
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "s3:PutBucketPolicy",
                    "Resource": "arn:aws:s3:::examplebucket",
                },
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                },
            ]
        )

        # Legitimate resource-policy semantics: the unconditional Deny on "*"
        # wins over the specific resource Allow, and no escalation is reported.
        assert policy.get_allowed_resources("s3", "PutBucketPolicy") == []
        assert policy.finding_ids == set()

    def test_notaction_deny_on_star_does_not_deny_specific_resource_allow(self):
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "s3:PutBucketPolicy",
                    "Resource": "arn:aws:s3:::examplebucket",
                },
                {
                    "Effect": "Deny",
                    "NotAction": "s3:GetObject",
                    "Resource": "*",
                },
            ]
        )

        # The NotAction Deny does not name PutBucketPolicy, so the specific
        # resource Allow must remain attributable rather than being swallowed.
        assert policy.get_allowed_resources("s3", "PutBucketPolicy") == [
            "arn:aws:s3:::examplebucket"
        ]
        assert "RESOURCE_POLICY_PRIVILEGE_ESCALATION" in policy.finding_ids
