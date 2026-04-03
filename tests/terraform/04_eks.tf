# ═══════════════════════════════════════════════
#  EKS: Cluster + Node Group + Addons
#  Demonstrates: full EKS lifecycle with
#  IAM roles, cluster, node group, addons.
# ═══════════════════════════════════════════════

resource "aws_iam_role" "eks_cluster" {
  name = "ministack-demo-eks-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role" "eks_nodes" {
  name = "ministack-demo-eks-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_eks_cluster" "main" {
  name     = "ministack-demo-cluster"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.31"

  vpc_config {
    subnet_ids = ["subnet-demo-a", "subnet-demo-b"]
  }

  tags = {
    Environment = "demo"
    ManagedBy   = "terraform"
  }
}

resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "ministack-demo-workers"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = ["subnet-demo-a", "subnet-demo-b"]
  instance_types  = ["t3.large"]

  scaling_config {
    desired_size = 3
    max_size     = 10
    min_size     = 1
  }

  tags = {
    Environment = "demo"
  }
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "vpc-cni"
}

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "coredns"
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "kube-proxy"
}
