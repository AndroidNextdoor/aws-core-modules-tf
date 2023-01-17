output "devops_group_names" {
  value       = values(aws_iam_group.groups)[*].name
  description = "The names of the devops groups"
}

output "developer_group_names" {
  value       = values(aws_iam_group.groups)[*].name
  description = "The name of the developer groups"
}

output "power_user_group_names" {
  value       = values(aws_iam_group.groups)[*].name
  description = "The name of the power user groups"
}

output "owner_group_names" {
  value       = values(aws_iam_group.groups)[*].name
  description = "The name of the power user groups"
}

output "billing_group_names" {
  value       = values(aws_iam_group.groups)[*].name
  description = "The name of the power user groups"
}