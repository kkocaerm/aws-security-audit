terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "terraform-state-security-audit"
    key            = "security-audit/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aws-security-audit"
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = var.owner
    }
  }
}

# ─── Modules ────────────────────────────────────────────────────────────────

module "iam" {
  source      = "../../modules/iam"
  environment = var.environment
  audit_role_name = "prowler-security-audit-${var.environment}"
}

module "s3" {
  source           = "../../modules/s3"
  environment      = var.environment
  bucket_name      = "${var.s3_report_bucket_prefix}-${var.environment}-${data.aws_caller_identity.current.account_id}"
  kms_key_arn      = module.kms.key_arn
  retention_days   = var.report_retention_days
}

module "networking" {
  source      = "../../modules/networking"
  environment = var.environment
  vpc_cidr    = var.vpc_cidr
}

module "ec2" {
  source             = "../../modules/ec2"
  environment        = var.environment
  subnet_id          = module.networking.private_subnet_id
  security_group_ids = [module.networking.audit_sg_id]
  iam_instance_profile = module.iam.instance_profile_name
  instance_type      = var.ec2_instance_type
  s3_report_bucket   = module.s3.bucket_name
}

module "kms" {
  source      = "../../modules/kms"
  environment = var.environment
}

# ─── SNS for Alerts ─────────────────────────────────────────────────────────

resource "aws_sns_topic" "security_alerts" {
  name              = "security-audit-alerts-${var.environment}"
  kms_master_key_id = module.kms.key_id

  tags = {
    Name = "security-audit-alerts-${var.environment}"
  }
}

resource "aws_sns_topic_subscription" "email_alerts" {
  count     = length(var.alert_emails)
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_emails[count.index]
}

# ─── EventBridge for Scheduled Audits ───────────────────────────────────────

resource "aws_cloudwatch_event_rule" "weekly_audit" {
  name                = "weekly-security-audit-${var.environment}"
  description         = "Haftalık otomatik güvenlik denetimi"
  schedule_expression = "cron(0 8 ? * MON *)"  # Her Pazartesi 08:00 UTC

  tags = {
    Name = "weekly-security-audit"
  }
}

resource "aws_cloudwatch_event_target" "audit_lambda" {
  rule      = aws_cloudwatch_event_rule.weekly_audit.name
  target_id = "TriggerAuditLambda"
  arn       = aws_lambda_function.trigger_audit.arn
}

# ─── Lambda to Trigger Audit ────────────────────────────────────────────────

resource "aws_lambda_function" "trigger_audit" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "trigger-security-audit-${var.environment}"
  role             = module.iam.lambda_role_arn
  handler          = "lambda_handler.handler"
  runtime          = "python3.11"
  timeout          = 60
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT       = var.environment
      S3_BUCKET         = module.s3.bucket_name
      SNS_TOPIC_ARN     = aws_sns_topic.security_alerts.arn
      EC2_INSTANCE_ID   = module.ec2.instance_id
    }
  }

  tags = {
    Name = "trigger-security-audit"
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../scripts/lambda"
  output_path = "${path.module}/lambda_function.zip"
}

data "aws_caller_identity" "current" {}

# ─── Outputs ─────────────────────────────────────────────────────────────────

output "audit_role_arn" {
  description = "Prowler denetim rolü ARN"
  value       = module.iam.audit_role_arn
}

output "report_bucket_name" {
  description = "Rapor S3 bucket adı"
  value       = module.s3.bucket_name
}

output "sns_topic_arn" {
  description = "Güvenlik uyarı SNS topic ARN"
  value       = aws_sns_topic.security_alerts.arn
}

output "audit_instance_id" {
  description = "Audit EC2 instance ID"
  value       = module.ec2.instance_id
}
