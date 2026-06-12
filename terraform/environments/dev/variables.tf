variable "aws_region" {
  description = "AWS bölgesi"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Ortam adı (dev/staging/prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Ortam dev, staging veya prod olmalıdır."
  }
}

variable "owner" {
  description = "Proje sahibi (e-posta veya takım adı)"
  type        = string
  default     = "security-team"
}

variable "vpc_cidr" {
  description = "VPC CIDR bloğu"
  type        = string
  default     = "10.0.0.0/16"
}

variable "ec2_instance_type" {
  description = "Audit EC2 instance tipi"
  type        = string
  default     = "t3.medium"
}

variable "s3_report_bucket_prefix" {
  description = "Rapor bucket adı öneki"
  type        = string
  default     = "aws-security-audit-reports"
}

variable "report_retention_days" {
  description = "Raporların S3'te tutulacağı gün sayısı"
  type        = number
  default     = 90
}

variable "alert_emails" {
  description = "Güvenlik uyarılarının gönderileceği e-posta adresleri"
  type        = list(string)
  default     = []
  sensitive   = true
}

variable "prowler_services" {
  description = "Denetlenecek AWS servisleri (boş = hepsi)"
  type        = list(string)
  default     = []
}

variable "compliance_frameworks" {
  description = "Kontrol edilecek uyumluluk framework'leri"
  type        = list(string)
  default     = [
    "cis_aws_foundations_benchmark_v1.4",
    "aws_foundational_security_best_practices"
  ]
}
