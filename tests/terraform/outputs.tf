# ═══════════════════════════════════════════════
#  Outputs — verify Terraform state is consistent
# ═══════════════════════════════════════════════

# Storage
output "s3_data_bucket" {
  value = aws_s3_bucket.data.id
}

output "s3_logs_bucket" {
  value = aws_s3_bucket.logs.id
}

output "dynamodb_table_arn" {
  value = aws_dynamodb_table.sessions.arn
}

# Messaging
output "sqs_queue_url" {
  value = aws_sqs_queue.orders.url
}

output "sns_topic_arn" {
  value = aws_sns_topic.notifications.arn
}

# Security
output "kms_key_arn" {
  value = aws_kms_key.app_encryption.arn
}

output "secret_arn" {
  value = aws_secretsmanager_secret.db_credentials.arn
}

# EKS
output "eks_cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "eks_cluster_arn" {
  value = aws_eks_cluster.main.arn
}

output "eks_cluster_version" {
  value = aws_eks_cluster.main.version
}

# Serverless
output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

# Networking
output "route53_zone_id" {
  value = aws_route53_zone.main.zone_id
}
