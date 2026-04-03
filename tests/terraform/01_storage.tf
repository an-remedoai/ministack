# ═══════════════════════════════════════════════
#  Storage: S3 + DynamoDB
#  Demonstrates: bucket creation, versioning,
#  tags, DynamoDB with GSI, TTL.
# ═══════════════════════════════════════════════

resource "aws_s3_bucket" "data" {
  bucket = "ministack-demo-data"
  tags = {
    Environment = "demo"
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "ministack-demo-logs"
}

resource "aws_dynamodb_table" "sessions" {
  name         = "ministack-demo-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"
  range_key    = "created_at"

  attribute {
    name = "session_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "N"
  }

  attribute {
    name = "user_id"
    type = "S"
  }

  global_secondary_index {
    name            = "user-index"
    hash_key        = "user_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  tags = {
    Environment = "demo"
  }
}
