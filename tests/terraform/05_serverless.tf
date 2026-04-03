# ═══════════════════════════════════════════════
#  Serverless: ECR + EventBridge
#  Demonstrates: container registry, event rules.
# ═══════════════════════════════════════════════

resource "aws_ecr_repository" "app" {
  name                 = "ministack-demo/app"
  image_tag_mutability = "MUTABLE"

  tags = {
    Environment = "demo"
  }
}

resource "aws_cloudwatch_event_rule" "cron" {
  name                = "ministack-demo-cron"
  schedule_expression = "rate(5 minutes)"
  tags = {
    Environment = "demo"
  }
}
