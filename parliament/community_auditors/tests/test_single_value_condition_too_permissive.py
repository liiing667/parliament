from parliament import analyze_policy_string


def assert_equal(a, b):
    assert a == b


def assert_in(a, b):
    assert a in b


def assert_not_in(a, b):
    assert a not in b


class TestSensitiveAccess:
    """Test class for single value condition too permissive auditor"""

    example_policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "s3:GetObject"
              ],
              "Resource": "arn:aws:s3:::secretbucket/*",
              "Condition": {
                  "ForAllValues:StringEquals": {
                      "aws:ResourceTag/Tag": [
                          "Value"
                      ]

                  }
              }
            }
          ]
        }
    """
    policy = analyze_policy_string(
        example_policy_string, include_community_auditors=True
    )
    assert_equal(policy.finding_ids, set(["SINGLE_VALUE_CONDITION_TOO_PERMISSIVE"]))

    def test_statement_without_condition_does_not_stop_audit(self):
        policy = analyze_policy_string(
            """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "s3:ListBucket",
              "Resource": "arn:aws:s3:::secretbucket"
            },
            {
              "Effect": "Allow",
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::secretbucket/*",
              "Condition": {
                  "ForAllValues:StringEquals": {
                      "aws:ResourceTag/Tag": [
                          "Value"
                      ]
                  }
              }
            }
          ]
        }
        """,
            include_community_auditors=True,
        )
        assert_equal(policy.finding_ids, set(["SINGLE_VALUE_CONDITION_TOO_PERMISSIVE"]))

    def test_key_matching_is_case_insensitive(self):
        policy = analyze_policy_string(
            """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::secretbucket/*",
              "Condition": {
                  "ForAnyValues:StringEquals": {
                      "AWS:RESOURCETAG/TAG": [
                          "Value"
                      ]
                  }
              }
            }
          ]
        }
        """,
            include_community_auditors=True,
        )
        assert_in("SINGLE_VALUE_CONDITION_TOO_PERMISSIVE", policy.finding_ids)

    def test_similar_key_names_are_not_flagged(self):
        policy = analyze_policy_string(
            """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::secretbucket/*",
              "Condition": {
                  "ForAllValues:StringEquals": {
                      "aws:ResourceTaggy": [
                          "Value"
                      ]
                  }
              }
            }
          ]
        }
        """,
            include_community_auditors=True,
        )
        assert_not_in("SINGLE_VALUE_CONDITION_TOO_PERMISSIVE", policy.finding_ids)

    def test_empty_condition_is_ignored(self):
        policy = analyze_policy_string(
            """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::secretbucket/*",
              "Condition": {}
            }
          ]
        }
        """,
            include_community_auditors=True,
        )
        assert_not_in("SINGLE_VALUE_CONDITION_TOO_PERMISSIVE", policy.finding_ids)

    def test_single_value_operator_is_not_flagged(self):
        policy = analyze_policy_string(
            """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::secretbucket/*",
              "Condition": {
                  "StringEquals": {
                      "aws:ResourceTag/Tag": "Value"
                  }
              }
            }
          ]
        }
        """,
            include_community_auditors=True,
        )
        assert_not_in("SINGLE_VALUE_CONDITION_TOO_PERMISSIVE", policy.finding_ids)
