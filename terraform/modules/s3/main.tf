resource "aws_s3_bucket" "reports" {
  bucket        = var.bucket_name
  force_destroy = var.environment != "prod"

  tags = {
    Name        = var.bucket_name
    Environment = var.environment
    Purpose     = "security-audit-reports"
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "archive-old-reports"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 60
      storage_class = "GLACIER"
    }

    expiration {
      days = var.retention_days
    }
  }
}

resource "aws_s3_bucket_notification" "new_report" {
  bucket = aws_s3_bucket.reports.id

  topic {
    topic_arn     = var.sns_topic_arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "reports/"
    filter_suffix = ".json"
  }
}

output "bucket_name" {
  value = aws_s3_bucket.reports.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.reports.arn
}
