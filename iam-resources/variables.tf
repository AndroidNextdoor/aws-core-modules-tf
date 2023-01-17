variable "iam_account_alias" {
  type        = string
  description = "A globally unique identifier, human-readable for your AWS account"
  default     = null
}

variable "users_account_id" {
  type        = string
  description = "The account ID of where the users are living in"
  default     = null
}

variable "admin_multi_factor_auth_age" {
  type        = number
  description = "The amount of time (in minutes) for a admin session to be valid"
  default     = 60 # 1 hour
}

variable "user_multi_factor_auth_age" {
  type        = number
  description = "The amount of time (in minutes) for a user session to be valid"
  default     = 240 # 4 hours
}

variable "devops_full_access_role_name" {
  type        = string
  description = "Name of the admin role"
  default     = "DevOps-Admin"
}

variable "devops_access_role_name" {
  type        = string
  description = "Name of the admin role"
  default     = "DevOps-Role"
}

variable "developer_access_role_name" {
  type        = string
  description = "Name of the user role"
  default     = "Developer-Role"
}

variable "pipeline_access_role_name" {
  type        = string
  description = "Name of the pipeline role"
  default     = "Pipeline-Role"
}

variable "owner_access_role_name" {
  type        = string
  description = "Name of the owner role"
  default     = "Owner-Role"
}

variable "billing_access_role_name" {
  type        = string
  description = "Name of the billing role"
  default     = "Billing-Role"
}

variable "power_user_access_role_name" {
  type        = string
  description = "Name of the power user role"
  default     = "PowerUser-Role"
}