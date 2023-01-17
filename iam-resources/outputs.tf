output "resource_devops_admin_role_name" {
  value       = aws_iam_role.devops_access_role.name
  description = "The name of the role users are able to assume to attain admin privileges"
}

output "resource_devops_admin_role_arn" {
  value       = aws_iam_role.devops_access_role.arn
  description = "The ARN of the role users are able to assume to attain admin privileges"
}

output "resource_developer_role_name" {
  value       = aws_iam_role.developer_access_role.name
  description = "The name of the role users are able to assume to attain user privileges"
}

output "resource_developer_role_arn" {
  value       = aws_iam_role.developer_access_role.arn
  description = "The ARN of the role users are able to assume to attain user privileges"
}

output "resource_limited_role_name" {
  value       = aws_iam_role.limited_access_role.name
  description = "The name of the role users are able to assume to attain user privileges"
}

output "resource_limited_role_arn" {
  value       = aws_iam_role.limited_access_role.arn
  description = "The ARN of the role users are able to assume to attain user privileges"
}

output "resource_power_user_role_name" {
  value       = aws_iam_role.power_user_access_role.name
  description = "The name of the role users are able to assume to attain user privileges"
}

output "resource_power_user_role_arn" {
  value       = aws_iam_role.power_user_access_role.arn
  description = "The ARN of the role users are able to assume to attain user privileges"
}

output "resource_billing_role_name" {
  value       = aws_iam_role.billing_access_role.name
  description = "The name of the role users are able to assume to attain user privileges"
}

output "resource_billing_role_arn" {
  value       = aws_iam_role.billing_access_role.arn
  description = "The ARN of the role users are able to assume to attain user privileges"
}

output "resource_owner_role_name" {
  value       = aws_iam_role.owner_access_role.name
  description = "The name of the role users are able to assume to attain user privileges"
}

output "resource_owner_role_arn" {
  value       = aws_iam_role.owner_access_role.arn
  description = "The ARN of the role users are able to assume to attain user privileges"
}
