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
resource "aws_iam_role" "admin_access_role" {
  name = var.admin_access_role_name

  assume_role_policy = data.aws_iam_policy_document.admin_access_role_policy.json
}

resource "aws_iam_role" "developer_access_role" {
  name = var.developer_access_role_name

  assume_role_policy = data.aws_iam_policy_document.developer_access_role_policy.json
}

resource "aws_iam_role" "limited_access_role" {
  name = var.limited_access_role_name

  assume_role_policy = data.aws_iam_policy_document.limited_access_role_policy.json
}

resource "aws_iam_role" "power_user_access_role" {
  name = var.power_user_access_role_name

  assume_role_policy = data.aws_iam_policy_document.power_user_access_role_policy.json
}

resource "aws_iam_role" "owner_access_role" {
  name = var.owner_access_role_name

  assume_role_policy = data.aws_iam_policy_document.owner_access_role_policy.json
}

resource "aws_iam_role" "billing_access_role" {
  name = var.billing_access_role_name

  assume_role_policy = data.aws_iam_policy_document.billing_access_role_policy.json
}

resource "aws_iam_policy" "admin_access_policy" {
  name        = "admin_access_policy"
  description = "DevOps Admin access for roles"

  policy = data.aws_iam_policy_document.user_access_policy_document.json
}

resource "aws_iam_policy" "developer_access_policy" {
  name        = "developer_access_policy"
  description = "Developer access for roles"

  policy = data.aws_iam_policy_document.user_access_policy_document.json
}

resource "aws_iam_policy" "limited_access_policy" {
  name        = "limited_access_policy"
  description = "Pipeline access for roles"

  policy = data.aws_iam_policy_document.user_access_policy_document.json
}

# Policy attachments for roles
resource "aws_iam_policy_attachment" "admin_access_policy_attachment" {
  name       = "admin_access_policy_attachment"
  roles      = [aws_iam_role.admin_access_role.name]
  policy_arn = local.administrator_access_policy_arn
}

resource "aws_iam_policy_attachment" "developer_access_policy_attachment" {
  name       = "developer_access_policy_attachment"
  roles      = [aws_iam_role.developer_access_role.name]
  policy_arn = aws_iam_policy.developer_access_policy.arn
}

resource "aws_iam_policy_attachment" "limited_access_policy_attachment" {
  name       = "limited_access_policy_attachment"
  roles      = [aws_iam_role.limited_access_role.name]
  policy_arn = aws_iam_policy.limited_access_policy.arn
}

resource "aws_iam_policy_attachment" "user_access_iam_read_only_policy_attachment" {
  name       = "user_access_iam_read_only_policy_attachment"
  roles      = [aws_iam_role.developer_access_role.name]
  policy_arn = local.iam_read_only_access_policy_arn
}

resource "aws_iam_policy_attachment" "user_access_power_user_policy_attachment" {
  name       = "user_access_power_user_policy_attachment"
  roles      = [aws_iam_role.developer_access_role.name]
  policy_arn = local.power_user_access_policy_arn
}
