data "aws_caller_identity" "current" {}

# AssumeRole policies to enforce MFA when assuming these from either the same or a different account
data "aws_iam_policy_document" "admin_access_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = [local.admin_multi_factor_auth_age]
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
      "ec2:Describe*",
      "ec2:Get*",
      "ec2:CreateTags",
      "ec2:CreateLaunchTemplate",
      "ec2:ModifyLaunchTemplate",
      "ec2:CreateLaunchTemplateVersion",
      "elasticloadbalancing:Describe*",
      "autoscaling:Describe*",
      "autoscaling:CreateOrUpdateTags",
      "autoscaling:ExitStandby",
      "autoscaling:BatchPutScheduledUpdateGroupAction",
      "autoscaling:EnterStandby",
      "autoscaling:ExecutePolicy",
      "autoscaling:UpdateAutoScalingGroup",
      "autoscaling:SetInstanceHealth",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "autoscaling:AttachLoadBalancers",
      "autoscaling:DetachLoadBalancers",
      "autoscaling:BatchDeleteScheduledAction",
      "autoscaling:EnableMetricsCollection",
      "autoscaling:ResumeProcesses",
      "autoscaling:SetDesiredCapacity",
      "autoscaling:Put*",
      "autoscaling:DetachLoadBalancerTargetGroups",
      "autoscaling:SuspendProcesses",
      "autoscaling:StartInstanceRefresh",
      "autoscaling:AttachLoadBalancerTargetGroups",
      "autoscaling:CreateLaunchConfiguration",
      "autoscaling:AttachInstances",
      "autoscaling:CompleteLifecycleAction",
      "autoscaling:DisableMetricsCollection",
      "autoscaling:SetInstanceProtection",
      "autoscaling:CancelInstanceRefresh",
      "autoscaling:DetachInstances",
      "autoscaling:CreateAutoScalingGroup",
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
      "mobiletargeting:TagResource",
      "mobiletargeting:Get*",
      "mobiletargeting:UntagResource",
      "mobiletargeting:PhoneNumberValidate",
      "mobiletargeting:List*",
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
      "waf-regional:Get*",
      "waf-regional:TagResource",
      "waf-regional:UntagResource",
      "waf-regional:List*",
      "wafv2:CheckCapacity",
      "wafv2:TagResource",
      "wafv2:Describe*",
      "wafv2:UntagResource",
      "wafv2:AssociateWebACL",
      "wafv2:Get*",
      "wafv2:List*",
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
      "s3:GetBucketVersioning"
    ]

    resources = [
      "*"
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
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:DescribeImages",
      "ecr:BatchGetImage",
      "ecr:GetLifecyclePolicy",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:ListTagsForResource",
      "ecr:DescribeImageScanFindings",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
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
      "sts:AssumeRole",
      "iam:PassRole",
      "events:*",
      "cognito-idp:AdminInitiateAuth",
      "dynamodb:Get*",
      "dynamodb:List*",
      "dynamodb:PutItem",
      "dynamodb:Query",
    ]

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${local.users_account_id}:root",
      ]
    }
  }
}

data "aws_iam_policy_document" "general_deny_role_policy" {
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
      aws_iam_role.developer_access_role.arn,
      aws_iam_role.admin_access_role.arn,
      aws_iam_role.limited_access_role.arn,
    ]
  }
}


data "aws_iam_policy_document" "developer_access_policy_document" {
  statement {
    effect = "Allow"

    actions = [
      "iam:PassRole",
    ]

    not_resources = [
      aws_iam_role.developer_access_role.arn,
      aws_iam_role.admin_access_role.arn,
      aws_iam_role.limited_access_role.arn,
    ]
  }
}
