output "cluster_endpoint" {
  value     = aws_eks_cluster.demo.endpoint
  sensitive = true
}

output "cluster_name" {
  value     = aws_eks_cluster.demo.name
  sensitive = true
}
