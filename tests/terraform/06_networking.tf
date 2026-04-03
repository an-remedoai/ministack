# ═══════════════════════════════════════════════
#  Networking: Route53 + ACM
#  Demonstrates: hosted zones, DNS records,
#  SSL certificates.
# ═══════════════════════════════════════════════

resource "aws_route53_zone" "main" {
  name = "demo.ministack.local"
}

resource "aws_route53_record" "api" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "api.demo.ministack.local"
  type    = "A"
  ttl     = 300
  records = ["10.0.0.1"]
}

