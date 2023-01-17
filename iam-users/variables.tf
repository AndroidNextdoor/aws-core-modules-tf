variable "iam_account_alias" {
  type        = string
  description = "A globally unique, human-readable identifier for your AWS account"
  default     = null
}

variable "admin_multi_factor_auth_age" {
  type        = number
  description = "The amount of time (in minutes) for a admin session to be valid"
  default     = 120 # 2 hours
}

variable "user_multi_factor_auth_age" {
  type        = number
  description = "The amount of time (in minutes) for a user session to be valid"
  default     = 240 # 4 hours
}

variable "password_policy" {
  type        = map(string)
  description = "A map of password policy parameters you want to set differently from the defaults"
  default = {
    require_uppercase_chars   = "true"
    require_lowercase_chars   = "true"
    require_symbols           = "true"
    require_numbers           = "true"
    minimum_password_length   = "32"
    password_reuse_prevention = "5"
    max_password_age          = "90"
  }
}

variable "resources_account_id" {
  type        = string
  description = "The account ID of the AWS account you want to start resources in"
  default     = ""
}

variable "resource_devops_role_name" {
  type        = string
  description = "The name of the devops role one is supposed to assume in the resource account"
  default     = "DevOps"
}

variable "resource_owner_role_name" {
  type        = string
  description = "The name of the owner role one is supposed to assume in the resource account"
  default     = "Owner"
}

variable "resource_power_user_role_name" {
  type        = string
  description = "The name of the owner role one is supposed to assume in the resource account"
  default     = "PowerUser"
}

variable "resource_developer_role_name" {
  type        = string
  description = "The name of the developer role one is supposed to assume in the resource account"
  default     = "Developer"
}

variable "resource_limited_role_name" {
  type        = string
  description = "The name of the limited role one is supposed to assume in the resource account"
  default     = "CI-CD"
}

variable "resource_billing_role_name" {
  type        = string
  description = "The name of the read-only billing role one is supposed to assume in the resource account"
  default     = "Billing"
}

variable "owner_group_name" {
  type        = string
  description = "The name of the initial group created for ownership and billing"
  default     = "Owner"
}

variable "devops_group_name" {
  type        = string
  description = "The name of the initial group created for devops admins"
  default     = "DevOps"
}

variable "developer_group_name" {
  type        = string
  description = "The name of the initial group created for developers"
  default     = "Developers"
}

variable "power_user_group_name" {
  type        = string
  description = "The name of the initial group created for power users with cli access users"
  default     = "PowerUsers"
}

variable "limited_group_name" {
  type        = string
  description = "The name of the initial group created for limited console access users"
  default     = "Limited"
}

variable "billing_group_name" {
  type        = string
  description = "The name of the initial group created for billing users"
  default     = "Billing"
}

variable "additional_admin_groups" {
  type        = list(string)
  description = "A list of additional groups to create associated with administrative privileges"
  default     = []
}

variable "additional_user_groups" {
  type        = list(string)
  description = "A list of additional groups to create associated with regular users"
  default     = []
}

variable "additional_limited_groups" {
  type        = list(string)
  description = "A list of additional groups to create associated with limited users"
  default     = []
}

variable "iam_users" {
  type        = map(map(list(string)))
  description = "A list of maps of users and their groups. Default is to create no users."
  default     = {}
}
