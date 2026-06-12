# ─── Prowler Audit Role ──────────────────────────────────────────────────────

data "aws_iam_policy_document" "prowler_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }

  # Cross-account audit desteği
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::*:role/prowler-caller-*"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "prowler_audit" {
  name               = var.audit_role_name
  assume_role_policy = data.aws_iam_policy_document.prowler_assume_role.json
  description        = "Prowler güvenlik denetimi için IAM rolü"

  tags = {
    Name        = var.audit_role_name
    Environment = var.environment
  }
}

# Prowler için gerekli okuma izinleri
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.prowler_audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.prowler_audit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# Ek Prowler gereksinimleri
data "aws_iam_policy_document" "prowler_extra_perms" {
  statement {
    sid    = "ProwlerExtraPermissions"
    effect = "Allow"
    actions = [
      "access-analyzer:ListAnalyzers",
      "account:GetAlternateContact",
      "cognito-idp:DescribeUserPool",
      "ds:ListAuthorizedApplications",
      "ds:DescribeDirectories",
      "ds:GetDirectoryLimits",
      "ec2:GetEbsEncryptionByDefault",
      "ecr:DescribeImages",
      "elasticfilesystem:DescribeBackupPolicy",
      "glue:GetConnections",
      "glue:GetSecurityConfigurations",
      "lambda:GetFunction",
      "macie2:GetMacieSession",
      "s3:GetAccountPublicAccessBlock",
      "shield:DescribeProtection",
      "shield:GetSubscriptionState",
      "support:DescribeTrustedAdvisorChecks",
      "tag:GetTagKeys",
      "wellarchitected:GetWorkload"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "S3ReportWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      "arn:aws:s3:::${var.report_bucket_name}",
      "arn:aws:s3:::${var.report_bucket_name}/*"
    ]
  }

  statement {
    sid    = "SNSPublish"
    effect = "Allow"
    actions = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }
}

resource "aws_iam_policy" "prowler_extra" {
  name        = "prowler-extra-permissions-${var.environment}"
  description = "Prowler için ek AWS izinleri"
  policy      = data.aws_iam_policy_document.prowler_extra_perms.json
}

resource "aws_iam_role_policy_attachment" "prowler_extra" {
  role       = aws_iam_role.prowler_audit.name
  policy_arn = aws_iam_policy.prowler_extra.arn
}

# ─── Instance Profile ────────────────────────────────────────────────────────

resource "aws_iam_instance_profile" "audit_profile" {
  name = "prowler-audit-profile-${var.environment}"
  role = aws_iam_role.prowler_audit.name
}

# ─── Lambda Execution Role ───────────────────────────────────────────────────

resource "aws_iam_role" "lambda_execution" {
  name = "security-audit-lambda-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ─── Outputs ─────────────────────────────────────────────────────────────────

output "audit_role_arn" {
  value = aws_iam_role.prowler_audit.arn
}

output "instance_profile_name" {
  value = aws_iam_instance_profile.audit_profile.name
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda_execution.arn
}
