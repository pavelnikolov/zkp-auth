variable "aws_region" {
  description = "AWS region"
  default     = "eu-central-1"
  type        = string
}

variable "state_bucket" {
  description = "S3 bucket for Terraform state"
  type        = string
}