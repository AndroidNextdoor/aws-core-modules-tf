data "aws_caller_identity" "current" {}

# AssumeRole policies to enforce MFA when assuming these from either the same or a different account
data "aws_iam_policy_document" "devops_access_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${local.users_account_id}:root",
      ]
    }
  }
}

data "aws_iam_policy_document" "developer_access_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = [local.user_multi_factor_auth_age]
    }

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${local.users_account_id}:root",
      ]
    }
  }
}

data "aws_iam_policy_document" "limited_access_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${local.users_account_id}:root",
      ]
    }
  }
}

data "aws_iam_policy_document" "billing_access_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = [local.user_multi_factor_auth_age]
    }

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${local.users_account_id}:root",
      ]
    }
  }
}

data "aws_iam_policy_document" "owner_access_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = [local.user_multi_factor_auth_age]
    }

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${local.users_account_id}:root",
      ]
    }
  }
}

data "aws_iam_policy_document" "power_user_access_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${local.users_account_id}:root",
      ]
    }
  }
}

# This denies the passing of the Admin or Developer
# The Limited Role needs PassRole permissions to run CodeBuild and CodePipeline Functionality
# The limited role means that those users should have console access denied. Not limited in functionality or ability.
# In-fact, the limited-role is quite powerful and should only be used in a CI/CD pipeline.
data "aws_iam_policy_document" "user_access_policy_document" {
  statement {
    effect = "Allow"

    actions = [
      "iam:PassRole",
    ]

    not_resources = [
      aws_iam_role.developer_access_role.arn,
      aws_iam_role.devops_access_role.arn,
      aws_iam_role.power_user_access_role.arn,
      aws_iam_role.billing_access_role.arn,
      aws_iam_role.owner_access_role.arn,
    ]
  }
}

