# ===========================================================================
# WAF v2 — Rule evaluation engine test
# Creates a WebACL with real rules, associates with ALB, and configures logging.
# ===========================================================================

# --- S3 bucket for WAF logs ---
resource "aws_s3_bucket" "waf_logs" {
  bucket = "waf-logs"
}

# --- IP Set: blacklisted IPs ---
resource "aws_wafv2_ip_set" "blacklist" {
  name               = "ip-blacklist"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["10.0.0.99/32", "172.16.0.0/16"]
}

# --- Regex Pattern Set: invalid URLs ---
resource "aws_wafv2_regex_pattern_set" "bad_urls" {
  name  = "bad-urls"
  scope = "REGIONAL"

  regular_expression {
    regex_string = "\\.(php|env|bak|sql)$"
  }
  regular_expression {
    regex_string = "wp-admin|wp-login"
  }
}

# --- ALB for testing ---
resource "aws_lb" "waf_test" {
  name               = "waf-tf-lb"
  internal           = false
  load_balancer_type = "application"
}

resource "aws_lb_listener" "waf_test" {
  load_balancer_arn = aws_lb.waf_test.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK from ALB"
      status_code  = "200"
    }
  }
}

# --- WebACL with multiple rule types ---
resource "aws_wafv2_web_acl" "firewall" {
  name  = "waf-tf-firewall"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: Block blacklisted IPs (priority 1)
  rule {
    name     = "block-blacklisted-ips"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blacklist.arn
      }
    }

    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "block-ips"
    }
  }

  # Rule 2: Block bad URLs via regex (priority 2)
  rule {
    name     = "block-bad-urls"
    priority = 2

    action {
      block {}
    }

    statement {
      regex_pattern_set_reference_statement {
        arn = aws_wafv2_regex_pattern_set.bad_urls.arn

        field_to_match {
          uri_path {}
        }

        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "block-urls"
    }
  }

  # Rule 3: Block /admin except from trusted IPs (AND + NOT)
  rule {
    name     = "protect-admin"
    priority = 3

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            search_string         = "/admin"
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          not_statement {
            statement {
              geo_match_statement {
                country_codes = ["BR"]
              }
            }
          }
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "protect-admin"
    }
  }

  # Rule 4: Count foreign access (monitoring only)
  rule {
    name     = "monitor-foreign-access"
    priority = 10

    action {
      count {}
    }

    statement {
      not_statement {
        statement {
          geo_match_statement {
            country_codes = ["BR", "US"]
          }
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "foreign-access"
    }
  }

  visibility_config {
    sampled_requests_enabled   = false
    cloudwatch_metrics_enabled = false
    metric_name                = "waf-firewall"
  }
}

# --- Associate WAF with ALB ---
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.waf_test.arn
  web_acl_arn  = aws_wafv2_web_acl.firewall.arn
}

# --- WAF Logging to S3 ---
resource "aws_wafv2_web_acl_logging_configuration" "firewall" {
  resource_arn            = aws_wafv2_web_acl.firewall.arn
  log_destination_configs = [aws_s3_bucket.waf_logs.arn]
}

# ===========================================================================
# Production-pattern resources: managed rule overrides, label whitelists,
# CUSTOM_KEYS rate limiting, InsertHeader
# ===========================================================================

# --- Regex Pattern Set: XSS whitelist (paths allowed to have XSS-like content) ---
resource "aws_wafv2_regex_pattern_set" "xss_whitelist" {
  name  = "xss-whitelist"
  scope = "REGIONAL"

  regular_expression {
    regex_string = "/api/produtos"
  }
  regular_expression {
    regex_string = "/api/conteudo"
  }
}

# --- Regex Pattern Set: SQLi whitelist ---
resource "aws_wafv2_regex_pattern_set" "sqli_whitelist" {
  name  = "sqli-whitelist"
  scope = "REGIONAL"

  regular_expression {
    regex_string = "/api/query"
  }
}

# --- IP Set: trusted IPs (for bypass patterns) ---
resource "aws_wafv2_ip_set" "trusted_ips" {
  name               = "trusted-ips"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["10.10.10.0/24"]
}

# --- Production-like WebACL with managed rules + overrides ---
resource "aws_wafv2_web_acl" "production" {
  name  = "waf-prod-firewall"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 5: Managed Common Rules with rule_action_override (XSS→COUNT)
  rule {
    name     = "managed-common"
    priority = 5

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        rule_action_override {
          name = "CrossSiteScripting_BODY"
          action_to_use {
            count {}
          }
        }

        rule_action_override {
          name = "CrossSiteScripting_QUERYARGUMENTS"
          action_to_use {
            count {}
          }
        }

        rule_action_override {
          name = "CrossSiteScripting_URIPATH"
          action_to_use {
            count {}
          }
        }

        rule_action_override {
          name = "CrossSiteScripting_COOKIE"
          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "managed-common"
    }
  }

  # Rule 6: Managed Linux rules with override_action { none {} }
  rule {
    name     = "managed-linux"
    priority = 6

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesLinuxRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "managed-linux"
    }
  }

  # Rule 7: Managed SQLi with override_action { count {} }
  rule {
    name     = "managed-sqli-count"
    priority = 7

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "managed-sqli"
    }
  }

  # Rule 8: Label-based whitelist — XSS label + NOT(whitelisted path) → BLOCK
  rule {
    name     = "xss-label-whitelist"
    priority = 15

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          label_match_statement {
            scope = "LABEL"
            key   = "awswaf:managed:aws:core-rule-set:CrossSiteScripting_BODY"
          }
        }
        statement {
          not_statement {
            statement {
              regex_pattern_set_reference_statement {
                arn = aws_wafv2_regex_pattern_set.xss_whitelist.arn

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "xss-whitelist"
    }
  }

  # Rule 9: Count foreign access with InsertHeader
  rule {
    name     = "foreign-insert-header"
    priority = 20

    action {
      count {
        custom_request_handling {
          insert_header {
            name  = "x-acesso-estrangeiro"
            value = "1"
          }
        }
      }
    }

    statement {
      not_statement {
        statement {
          geo_match_statement {
            country_codes = ["BR"]
          }
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "foreign-header"
    }
  }

  visibility_config {
    sampled_requests_enabled   = false
    cloudwatch_metrics_enabled = false
    metric_name                = "waf-prod-firewall"
  }
}
