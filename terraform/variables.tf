variable "aws_region" {
  description = "AWS region"
  default     = "eu-central-1"
  type        = string
}

variable "cluster_addons" {
  type = list(object({
    name    = string
    version = string
  }))

  default = [
    {
      name    = "kube-proxy"
      version = "v1.30.0-eksbuild.3"
    },
    {
      name    = "vpc-cni"
      version = "v1.18.2-eksbuild.1"
    },
    {
      name    = "coredns"
      version = "v1.11.1-eksbuild.9"
    }
  ]
}