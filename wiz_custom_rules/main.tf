# One Terraform workspace per service keeps deploys independent: each
# workspace has its own state, so applying one service never destroys
# another service's rules. The bundle directory is derived from the
# workspace name, so the two cannot be mismatched:
#   terraform workspace select -or-create aws-eks
#   terraform apply
# The default workspace keeps reading the legacy shared directory.
variable "base_dir" {
  description = "Override for the bundle directory; empty derives it from the workspace name"
  type        = string
  default     = ""
}

locals {
  base_dir = var.base_dir != "" ? var.base_dir : (
    terraform.workspace == "default"
    ? "./Cloud_Configuration_Rules"
    : "./${terraform.workspace}/Cloud_Configuration_Rules"
  )
}

module "custom-ccr" {
  source   = "https://downloads.wiz.io/customer-files/terraform/terraform-wiz-custom-ccr.zip//terraform-wiz-custom-ccr"
  base_dir = local.base_dir
}
