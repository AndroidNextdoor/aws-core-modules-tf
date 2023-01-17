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
    actions = [
      "iam:GetAccountSummary",
      "iam:List*",
    ]

    effect = "Allow"

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
    actions = [
      "iam:DeactivateMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:ListVirtualMFADevices",
      "iam:ListMFADevices",
      "iam:ChangePassword",
    ]

    effect = "Allow"

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}",
    ]
  }

  statement {
    actions = [
      "iam:CreateVirtualMFADevice",
    ]

    effect = "Allow"

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/*",
    ]
  }
  statement {
    actions = [
      "iam:DeleteVirtualMFADevice",
    ]

    effect = "Allow"

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/$${aws:username}",
    ]
  }

}

# General Deny Policies
data "aws_iam_policy_document" "general_deny_iam_policy_document" {
  statement {
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

    effect = "Allow"

    not_resources = [
      "arn:aws:iam::*",
    ]
  }
}

# Group policies
data "aws_iam_policy_document" "assume_role_devops_access_group_policy_document" {
  statement {
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

    effect = "Allow"

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_devops_role_name}",
    ]
  }
}


data "aws_iam_policy_document" "assume_role_developer_access_group_policy_document" {
  statement {
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

    effect = "Allow"

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_developer_role_name}"
    ]
  }
}

data "aws_iam_policy_document" "assume_role_limited_access_group_policy_document" {
  statement {
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

    effect = "Allow"

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_limited_role_name}"
    ]
  }
}

data "aws_iam_policy_document" "assume_role_owner_access_group_policy_document" {
  statement {
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

    effect = "Allow"

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_owner_role_name}"
    ]
  }
}

data "aws_iam_policy_document" "assume_role_power_user_access_group_policy_document" {
  statement {

    actions = [
      "sts:AssumeRole",
    ]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    effect = "Allow"

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_power_user_role_name}"
    ]
  }
}

data "aws_iam_policy_document" "assume_role_billing_access_group_policy_document" {
  statement {

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

    effect = "Allow"

    resources = [
      "arn:aws:iam::${local.resources_account_id}:role/${var.resource_billing_role_name}"
    ]
  }
}


data "aws_iam_policy_document" "devops_policy" {
  statement {
    actions = [
      "*"
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
      "*",
    ]
  }
}

data "aws_iam_policy_document" "owner_billing_policy" {
  statement {
    actions = [
      "aws-portal:ModifyBilling",
      "aws-portal:ViewBilling",
      "aws-portal:ViewAccount",
      "aws-portal:ModifyAccount",
      "aws-portal:ViewPaymentMethods",
      "aws-portal:ModifyPaymentMethods",
      "aws-portal:ViewUsage",
      "purchase-orders:ViewPurchaseOrders",
      "purchase-orders:ModifyPurchaseOrders",
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

    effect = "Allow"

    resources = [
      "*"
    ]

  }
}

data "aws_iam_policy_document" "readonly_billing_policy" {
  statement {
    actions = [
      "aws-portal:ViewBilling",
      "aws-portal:ViewAccount",
      "aws-portal:ViewPaymentMethods",
      "aws-portal:ViewUsage",
      "purchase-orders:ViewPurchaseOrders",
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

    effect = "Allow"

    resources = [
      "*"
    ]
  }
}

## UPDATE THESE FOR YOUR DEVELOPERS NEEDS
data "aws_iam_policy_document" "developer_policy" {
  statement {
    actions = [
      "ec2:Describe*",
      "ec2:Get*",
      "ec2:CreateTags",
      "ec2:CreateLaunchTemplate",
      "ec2:ModifyLaunchTemplate",
      "ec2:CreateLaunchTemplateVersion",
      "elasticloadbalancing:Describe*",
      "apigateway:UpdateRestApiPolicy",
      "apigateway:SetWebACL",
      "apigateway:PUT",
      "apigateway:PATCH",
      "apigateway:POST",
      "apigateway:GET",
      "apigateway:DELETE",
      "cloudformation:DetectStackSetDrift",
      "cloudformation:DetectStackDrift",
      "cloudformation:DetectStackResourceDrift",
      "cloudformation:List*",
      "cloudformation:Describe*",
      "cloudformation:EstimateTemplateCost",
      "cloudformation:Get*",
      "cloudformation:TagResource",
      "cloudformation:UntagResource",
      "cloudformation:RegisterType",
      "cloudformation:CancelUpdateStack",
      "cloudformation:UpdateStackInstances",
      "cloudformation:SignalResource",
      "cloudformation:UpdateStackSet",
      "cloudformation:CreateChangeSet",
      "cloudformation:CreateStackInstances",
      "cloudformation:ContinueUpdateRollback",
      "cloudformation:UpdateStack",
      "cloudformation:ExecuteChangeSet",
      "cloudformation:CreateUploadBucket",
      "cloudformation:ValidateTemplate",
      "cloudtrail:Get*",
      "cloudtrail:Describe*",
      "cloudtrail:List*",
      "codebuild:List*",
      "codebuild:Batch*",
      "codebuild:Get*",
      "codebuild:Describe*",
      "codepipeline:List*",
      "codepipeline:Get*",
      "cognito-idp:Admin*",
      "cognito-idp:List*",
      "cognito-idp:Get*",
      "cognito-idp:Describe*",
      "cognito-idp:Update*",
      "cognito-idp:Create*",
      "cognito-idp:Set*",
      "cognito-idp:TagResource",
      "cognito-idp:ConfirmForgotPassword",
      "cognito-idp:AddCustomAttributes",
      "cognito-idp:ConfirmSignUp",
      "cognito-idp:SignUp",
      "cognito-idp:VerifyUserAttribute",
      "cognito-idp:StartUserImportJob",
      "cognito-idp:AssociateSoftwareToken",
      "cognito-idp:VerifySoftwareToken",
      "cognito-idp:RespondToAuthChallenge",
      "cognito-idp:UntagResource",
      "cognito-idp:StopUserImportJob",
      "cognito-idp:ChangePassword",
      "cognito-idp:InitiateAuth",
      "cognito-idp:ConfirmDevice",
      "cognito-idp:ResendConfirmationCode",
      "cognito-identity:LookupDeveloperIdentity",
      "cognito-identity:MergeDeveloperIdentities",
      "cognito-identity:UnlinkDeveloperIdentity",
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:CreateGrant",
      "kms:CreateAlias",
      "kms:CreateKey",
      "kms:DeleteAlias",
      "kms:Describe*",
      "kms:GenerateRandom",
      "kms:Get*",
      "kms:List*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:GenerateDataKey",
      "iam:Get*",
      "iam:List*",
      "logs:StartQuery",
      "logs:StopQuery",
      "logs:TestMetricFilter",
      "logs:FilterLogEvents",
      "logs:GetLogDelivery",
      "logs:Describe*",
      "logs:List*",
      "cloudwatch:List*",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:Enable*",
      "cloudwatch:Put*",
      "cloudwatch:Set*",
      "sms-voice:Get*",
      "sms-voice:List*",
      "ecr:Get*",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeRepositories",
      "ecr:List*",
      "ecr:DescribeImages",
      "ecr:DescribeImageScanFindings",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      "ecs:CreateService",
      "ecs:DeleteService",
      "ecs:DeregisterTaskDefinition",
      "ecs:DescribeClusters",
      "ecs:DescribeContainerInstances",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ecs:DescribeTasks",
      "ecs:Poll",
      "ecs:RegisterTaskDefinition",
      "ecs:RunTask",
      "ecs:StartTask",
      "ecs:StopTask",
      "ecs:UpdateService",
      "redshift:Describe*",
      "redshift:ViewQueriesInConsole",
      "sts:GetAccessKeyInfo",
      "sts:GetSessionToken",
      "dynamodb:*",
      "es:ESHttp*",
      "es:Describe*",
      "es:List*",
      "s3:GetBucketTagging",
      "s3:GetObjectVersionTagging",
      "s3:ListBucketVersions",
      "s3:GetObjectTagging",
      "s3:ListBucket",
      "s3:GetBucketVersioning",
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

    effect = "Allow"

    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "developer_cli_policy" {
  statement {
    actions = [
      "ec2:Describe*",
      "ec2:Get*",
      "ec2:CreateTags",
      "ec2:CreateLaunchTemplate",
      "ec2:ModifyLaunchTemplate",
      "ec2:CreateLaunchTemplateVersion",
      "elasticloadbalancing:Describe*",
      "apigateway:UpdateRestApiPolicy",
      "apigateway:SetWebACL",
      "apigateway:PUT",
      "apigateway:PATCH",
      "apigateway:POST",
      "apigateway:GET",
      "apigateway:DELETE",
      "cloudtrail:Get*",
      "cloudtrail:Describe*",
      "cloudtrail:List*",
      "codebuild:List*",
      "codebuild:Batch*",
      "codebuild:Get*",
      "codebuild:Describe*",
      "codepipeline:List*",
      "codepipeline:Get*",
      "cognito-idp:Admin*",
      "cognito-idp:List*",
      "cognito-idp:Get*",
      "cognito-idp:Describe*",
      "cognito-idp:Update*",
      "cognito-idp:Create*",
      "cognito-idp:Set*",
      "cognito-idp:TagResource",
      "cognito-idp:ConfirmForgotPassword",
      "cognito-idp:AddCustomAttributes",
      "cognito-idp:ConfirmSignUp",
      "cognito-idp:SignUp",
      "cognito-idp:VerifyUserAttribute",
      "cognito-idp:StartUserImportJob",
      "cognito-idp:AssociateSoftwareToken",
      "cognito-idp:VerifySoftwareToken",
      "cognito-idp:RespondToAuthChallenge",
      "cognito-idp:UntagResource",
      "cognito-idp:StopUserImportJob",
      "cognito-idp:ChangePassword",
      "cognito-idp:InitiateAuth",
      "cognito-idp:ConfirmDevice",
      "cognito-idp:ResendConfirmationCode",
      "cognito-identity:LookupDeveloperIdentity",
      "cognito-identity:MergeDeveloperIdentities",
      "cognito-identity:UnlinkDeveloperIdentity",
      "iam:Get*",
      "iam:List*",
      "logs:StartQuery",
      "logs:StopQuery",
      "logs:TestMetricFilter",
      "logs:FilterLogEvents",
      "logs:GetLogDelivery",
      "logs:Describe*",
      "logs:List*",
      "cloudwatch:List*",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:Enable*",
      "cloudwatch:Put*",
      "cloudwatch:Set*",
      "sms-voice:Get*",
      "sms-voice:List*",
      "ecr:Get*",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeRepositories",
      "ecr:List*",
      "ecr:DescribeImages",
      "ecr:DescribeImageScanFindings",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      "ecs:CreateService",
      "ecs:DeleteService",
      "ecs:DeregisterTaskDefinition",
      "ecs:DescribeClusters",
      "ecs:DescribeContainerInstances",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ecs:DescribeTasks",
      "ecs:Poll",
      "ecs:RegisterTaskDefinition",
      "ecs:RunTask",
      "ecs:StartTask",
      "ecs:StopTask",
      "ecs:UpdateService",
      "redshift:Describe*",
      "redshift:ViewQueriesInConsole",
      "sts:GetAccessKeyInfo",
      "sts:GetSessionToken",
      "dynamodb:*",
      "es:ESHttp*",
      "es:Describe*",
      "es:List*",
      "s3:GetBucketTagging",
      "s3:GetObjectVersionTagging",
      "s3:ListBucketVersions",
      "s3:GetObjectTagging",
      "s3:ListBucket",
      "s3:GetBucketVersioning",
    ]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    effect = "Allow"

    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "limited_policy" {
  statement {
    actions = [
      "iam:PassRole",
      "sts:AssumeRole",
      "codebuild:*",
      "codepipeline:*",
      "apigateway:*",
      "cloudformation:*",
      "logs:*",
      "kms:Decrypt",
      "secretsmanager:GetSecretValue",
      "iam:CreateServiceLinkedRole",
      "iam:GetRole",
      "s3:CreateBucket",
      "s3:PutObject",
      "s3:GetObject",
      "s3:GetBucketTagging",
      "s3:GetObjectVersionTagging",
      "s3:ListBucketVersions",
      "s3:GetObjectTagging",
      "s3:ListBucket",
      "s3:PutObjectTagging",
      "s3:GetBucketVersioning",
      "s3:PutBucketVersioning",
      "lambda:UpdateAlias",
      "lambda:CreateAlias",
      "lambda:UpdateFunctionCode",
      "lambda:GetAlias",
      "lambda:InvokeFunction",
      "lambda:PublishVersion",
      "lambda:ListVersionsByFunction",
      "lambda:GetFunction",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:ListTags",
      "lambda:UpdateFunctionConfiguration",
      "lambda:GetFunctionConfiguration",
      "lambda:CreateFunction",
      "lambda:DeleteFunction",
      "lambda:AddPermission",
      "lambda:RemovePermission",
      "lambda:TagResource",
      "ses:CreateReceiptFilter",
      "ses:CreateReceiptRule",
      "ses:CreateReceiptRuleSet",
      "ses:SendEmail",
      "ses:PutIdentityPolicy",
      "ses:SendBounce",
      "ses:SetIdentityNotificationTopic",
      "ses:SetIdentityFeedbackForwardingEnabled",
      "ses:GetIdentityPolicies",
      "ses:GetIdentityVerificationAttributes",
      "ses:SendRawEmail",
      "ses:VerifyDomainIdentity",
      "ses:VerifyEmailAddress",
      "ses:VerifyEmailIdentity",
      "sns:CreateTopic",
      "sns:GetTopicAttributes",
      "sns:List*",
      "sns:Publish",
      "sns:SetTopicAttributes",
      "sns:Subscribe",
      "events:*",
      "cognito-idp:AdminInitiateAuth",
      "dynamodb:Get*",
      "dynamodb:List*",
      "dynamodb:PutItem",
      "dynamodb:Query",
      #       TURN PERMISSIONS ON AS NEEDED ACCORDING TO BEST PRACTICES
      #      "ecr:GetAuthorizationToken",
      #      "ecr:BatchCheckLayerAvailability",
      #      "ecr:GetDownloadUrlForLayer",
      #      "ecr:GetRepositoryPolicy",
      #      "ecr:DescribeRepositories",
      #      "ecr:ListImages",
      #      "ecr:DescribeImages",
      #      "ecr:BatchGetImage",
      #      "ecr:GetLifecyclePolicy",
      #      "ecr:GetLifecyclePolicyPreview",
      #      "ecr:ListTagsForResource",
      #      "ecr:DescribeImageScanFindings",
      #      "ecr:PutImage",
      #      "ecr:InitiateLayerUpload",
      #      "ecr:UploadLayerPart",
      #      "ecr:CompleteLayerUpload",
    ]

    effect = "Allow"

    resources = [
      "*",
    ]
  }
}
