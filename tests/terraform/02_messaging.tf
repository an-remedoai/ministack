# ═══════════════════════════════════════════════
#  Messaging: SQS + SNS
#  Demonstrates: queues, DLQ, topics,
#  subscriptions, FIFO queue.
# ═══════════════════════════════════════════════

resource "aws_sqs_queue" "orders" {
  name                       = "ministack-demo-orders"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400
  tags = {
    Environment = "demo"
  }
}

resource "aws_sqs_queue" "orders_dlq" {
  name = "ministack-demo-orders-dlq"
}

resource "aws_sns_topic" "notifications" {
  name = "ministack-demo-notifications"
  tags = {
    Environment = "demo"
  }
}

