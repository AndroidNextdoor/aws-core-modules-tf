/**
*
* ## iam-resources
*
* A module to configure the "resources" account modelled after the common security principle of separating users from resource accounts through a MFA-enabled role-assumption bridge.
* Please see the [iam-users](https://github.com/AndroidNextdoor/aws-core-modules-tf/tree/main/iam-users) module for further explanation. It is generally assumed that this module isn't deployed on its own.
* 
* ### Usage example
* ```hcl
* module "iam_resources" {
*   source            = "git::https://github.com/AndroidNextdoor/aws-core-modules-tf.git//iam-resources"

    # Optional parameter for specifying a different AWS account, the default is to use the same account
*   users_account_id = "id-of-the-users-account"
* }
* 
* ``` 
*/

locals {
  administrator_access_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  administrator_full_access_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  iam_read_only_access_policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
  power_user_access_policy_arn    = "arn:aws:iam::aws:policy/PowerUserAccess"
  users_account_id                = var.users_account_id == null ? data.aws_caller_identity.current.account_id : var.users_account_id
  admin_multi_factor_auth_age     = var.admin_multi_factor_auth_age * 60
  user_multi_factor_auth_age      = var.user_multi_factor_auth_age * 60
}

resource "aws_iam_account_alias" "iam_account_alias" {
  count         = var.iam_account_alias == null ? 0 : 1
  account_alias = var.iam_account_alias
}

# Roles
resource "aws_iam_role" "devops_access_role" {
  name = var.devops_access_role_name

  assume_role_policy = data.aws_iam_policy_document.mfa_required_role_policy.json
}

resource "aws_iam_role" "devops_full_access_role" {
  name = var.devops_full_access_role_name

  assume_role_policy = data.aws_iam_policy_document.mfa_required_role_policy.json
}

resource "aws_iam_role" "developer_access_role" {
  name = var.developer_access_role_name

  assume_role_policy = data.aws_iam_policy_document.full_mfa_required_role_policy.json
}

resource "aws_iam_role" "pipeline_access_role" {
  name = var.pipeline_access_role_name

  assume_role_policy = data.aws_iam_policy_document.no_mfa_required_role_policy.json
}

resource "aws_iam_role" "power_user_access_role" {
  name = var.power_user_access_role_name

  assume_role_policy = data.aws_iam_policy_document.mfa_required_role_policy.json
}

resource "aws_iam_role" "owner_access_role" {
  name = var.owner_access_role_name

  assume_role_policy = data.aws_iam_policy_document.full_mfa_required_role_policy.json
}

resource "aws_iam_role" "billing_access_role" {
  name = var.billing_access_role_name

  assume_role_policy = data.aws_iam_policy_document.full_mfa_required_role_policy.json
}

resource "aws_iam_policy" "devops_access_policy" {
  name        = "devops_access_policy"
  description = "DevOps access for roles"

  policy = data.aws_iam_policy_document.mfa_required_role_policy.json
}

resource "aws_iam_policy" "devops_full_access_policy" {
  name        = "devops_full_access_policy"
  description = "DevOps Admin access for roles"

  policy = data.aws_iam_policy_document.admin_access_policy_document.json
}

resource "aws_iam_policy" "developer_access_policy" {
  name        = "developer_access_policy"
  description = "Developer access for roles"

  policy = data.aws_iam_policy_document.user_access_policy_document.json
}

resource "aws_iam_policy" "pipeline_access_policy" {
  name        = "pipeline_access_policy"
  description = "Pipeline access for roles"

  policy = data.aws_iam_policy_document.admin_access_policy_document.json
}

resource "aws_iam_policy" "billing_access_policy" {
  name        = "billing_access_policy"
  description = "Billing access for roles"

  policy = data.aws_iam_policy_document.user_access_policy_document.json
}

resource "aws_iam_policy" "power_user_access_policy" {
  name        = "power_user_access_policy"
  description = "Power User access for roles"

  policy = data.aws_iam_policy_document.user_access_policy_document.json
}

# Policy attachments for roles
resource "aws_iam_policy_attachment" "devops_access_policy_attachment" {
  name       = "devops_access_policy_attachment"
  roles      = [aws_iam_role.devops_access_role.name]
  policy_arn = local.administrator_access_policy_arn
}

resource "aws_iam_policy_attachment" "devops_full_access_policy_attachment" {
  name       = "devops_full_access_policy_attachment"
  roles      = [aws_iam_role.devops_full_access_role.name]
  policy_arn = aws_iam_policy.devops_full_access_policy.arn
}

resource "aws_iam_policy_attachment" "developer_access_policy_attachment" {
  name       = "developer_access_policy_attachment"
  roles      = [aws_iam_role.developer_access_role.name]
  policy_arn = aws_iam_policy.developer_access_policy.arn
}

resource "aws_iam_policy_attachment" "pipeline_access_policy_attachment" {
  name       = "pipeline_access_policy_attachment"
  roles      = [aws_iam_role.pipeline_access_role.name]
  policy_arn = aws_iam_policy.pipeline_access_policy.arn
}

resource "aws_iam_policy_attachment" "billing_policy_attachment" {
  name       = "billing_policy_attachment"
  roles      = [aws_iam_role.billing_access_role.name]
  policy_arn = aws_iam_policy.billing_access_policy.arn
}

resource "aws_iam_policy_attachment" "power_user_policy_attachment" {
  name       = "power_user_policy_attachment"
  roles      = [aws_iam_role.power_user_access_role.name]
  policy_arn = aws_iam_policy.power_user_access_policy.arn
}
