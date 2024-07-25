output "endpoint" {
  value     = aws_eks_cluster.default.endpoint
  sensitive = true
}

output "kubeconfig-certificate-authority-data" {
  value     = aws_eks_cluster.default.certificate_authority[0].data
  sensitive = true
}
