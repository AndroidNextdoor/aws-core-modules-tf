data "aws_caller_identity" "current" {}

# This is a policy which lets you self-service your own access keys.
# The only condition is that you have a MFA enabled session
data "aws_iam_policy_document" "aws_access_key_self_service_policy" {
  statement {
    actions = [
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey",
    ]

    effect = "Allow"

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

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}",
    ]
  }
}

# This allows users without MFA to at least get a few details about their own account
data "aws_iam_policy_document" "aws_list_iam_users_policy" {
  statement {
    effect = "Allow"

    actions = [
      "iam:GetAccountSummary",
      "iam:List*",
    ]

    # We need to use * here since the API calls for these don't accept resources
    #tfsec:ignore:aws-iam-no-policy-wildcards
    resources = [
      "*",
    ]
  }

  statement {
    actions = ["iam:GetUser"]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}",
    ]

    effect = "Allow"
  }
}

data "aws_iam_policy_document" "aws_mfa_self_service_policy" {
  statement {
    effect = "Allow"

    actions = [
      "iam:DeactivateMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:ListVirtualMFADevices",
      "iam:ListMFADevices",
      "iam:ChangePassword",
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}",
    ]
  }

  statement {
    effect = "Allow"

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/*",
    ]

    actions = [
      "iam:CreateVirtualMFADevice",
      "iam:DeleteVirtualMFADevice",
    ]
  }

  statement {
    effect = "Allow"

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/*",
    ]

    actions = [
      "iam:ListVirtualMFADevices",
      "iam:ListMFADevices",
    ]
  }
}

# General Deny Policies
data "aws_iam_policy_document" "general_deny_iam_policy_document" {
  statement {
    effect = "Allow"
    actions = [
      "iam:CreateInstanceProfile",
      "iam:CreateServiceSpecificCredential",
      "iam:CreateGroup",
      "iam:CreateRole",
      "iam:CreateSAMLProvider",
      "iam:CreateUser",
      "iam:CreateOpenIDConnectProvider",
      "iam:CreateAccessKey",
      "iam:CreatePolicy",
      "iam:CreateLoginProfile",
      "iam:CreateServiceLinkedRole",
      "iam:CreateAccountAlias",
      "iam:Add*",
      "iam:CreatePolicyVersion",
      "iam:DeleteGroup",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:DeletePolicy",
      "iam:DeleteRolePermissionsBoundary",
      "iam:RemoveUserFromGroup",
      "iam:DeleteRolePolicy",
      "iam:DeleteServerCertificate",
      "iam:DeleteAccountAlias",
      "iam:DeleteOpenIDConnectProvider",
      "iam:DeleteLoginProfile",
      "iam:DeleteInstanceProfile",
      "iam:DeleteAccountPasswordPolicy",
      "iam:RemoveClientIDFromOpenIDConnectProvider",
      "iam:DeleteUserPolicy",
      "iam:DeleteRole",
      "iam:DeleteUser",
      "iam:DeleteUserPermissionsBoundary",
      "iam:DeleteSigningCertificate",
      "iam:DeleteVirtualMFADevice",
      "iam:DeleteServiceLinkedRole",
      "iam:DeleteGroupPolicy",
      "iam:DeleteServiceSpecificCredential",
      "iam:DeletePolicyVersion",
      "iam:DeleteSAMLProvider",
    ]

    not_resources = [
      "arn:aws:iam::*",
    ]
  }
}

# Group policies
data "aws_iam_policy_document" "assume_role_devops_access_group_policy_document" {
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

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_devops_role_name}",
    ]
  }
}


data "aws_iam_policy_document" "assume_role_developer_access_group_policy_document" {
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

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_developer_role_name}"
    ]
  }
}

data "aws_iam_policy_document" "assume_role_limited_access_group_policy_document" {
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

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_limited_role_name}"
    ]
  }
}

data "aws_iam_policy_document" "assume_role_owner_access_group_policy_document" {
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

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_owner_role_name}"
    ]
  }
}

data "aws_iam_policy_document" "assume_role_power_user_access_group_policy_document" {
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

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_power_user_role_name}"
    ]
  }
}

data "aws_iam_policy_document" "assume_role_billing_access_group_policy_document" {
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

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_billing_role_name}"
    ]
  }
}