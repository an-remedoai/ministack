# ═══════════════════════════════════════════════
#  Security: IAM + KMS + Secrets Manager + SSM
#  Demonstrates: roles, policies, encryption keys,
#  secrets, parameter store.
# ═══════════════════════════════════════════════

resource "aws_iam_role" "app_role" {
  name = "ministack-demo-app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "app_policy" {
  name = "ministack-demo-app-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
        ]
        Resource = "${aws_s3_bucket.data.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
        ]
        Resource = aws_dynamodb_table.sessions.arn
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.app_policy.arn
}

resource "aws_kms_key" "app_encryption" {
  description = "MiniStack demo - application encryption key"
}

resource "aws_kms_alias" "app_encryption" {
  name          = "alias/ministack-demo-app"
  target_key_id = aws_kms_key.app_encryption.key_id
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name = "ministack-demo/db-credentials"
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = "admin"
    password = "super-secret-123"
    host     = "db.example.internal"
    port     = 5432
  })
}

resource "aws_ssm_parameter" "api_url" {
  name  = "/ministack-demo/api/url"
  type  = "String"
  value = "https://api.example.com"
}

resource "aws_ssm_parameter" "db_password" {
  name  = "/ministack-demo/db/password"
  type  = "SecureString"
  value = "another-secret-456"
}
