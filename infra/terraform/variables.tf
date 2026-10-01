variable "aws_region" {
  description = "Region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "dlp"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.name_prefix))
    error_message = "name_prefix must be 2-21 characters: lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "environment" {
  description = "Environment name, part of resource names and tags."
  type        = string
  default     = "dev"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,12}$", var.environment))
    error_message = "environment must be 2-13 characters: lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "lambda_package_path" {
  description = "Path to the Lambda deployment package. Build it first with `make package`."
  type        = string
  default     = "../../build/lambda.zip"
}

variable "lambda_memory_mb" {
  description = "Memory of the detector function."
  type        = number
  default     = 256
}

variable "lambda_timeout_seconds" {
  description = "Timeout of the detector function."
  type        = number
  default     = 60
}

variable "max_scan_bytes" {
  description = "The detector scans at most this many bytes of each object."
  type        = number
  default     = 10485760
}

variable "additional_monitored_buckets" {
  description = "Names of existing buckets to monitor besides the one created here. Their event notification configuration is replaced by this module."
  type        = list(string)
  default     = []
}

variable "enable_quarantine" {
  description = "Create a quarantine bucket and move offending objects there. When false, the quarantine action blocks the object in place (tag plus bucket policy deny) instead."
  type        = bool
  default     = true
}

variable "quarantine_retention_days" {
  description = "Quarantined objects are expired after this many days."
  type        = number
  default     = 90
}

variable "incident_retention_days" {
  description = "Incident journal items expire after this many days. 0 keeps them forever."
  type        = number
  default     = 365
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention of the detector function."
  type        = number
  default     = 90
}

variable "alert_email" {
  description = "Email address subscribed to the alert topic. Leave empty to subscribe nothing; the subscription must be confirmed by the recipient."
  type        = string
  default     = ""
}

variable "webhook_url" {
  description = "Optional Slack/Discord/generic incoming webhook for alerts. Stored as a Lambda environment variable, which is readable by anyone who can read the function configuration; prefer an SNS subscription for sensitive setups."
  type        = string
  default     = ""
  sensitive   = true
}

variable "sns_kms_key_id" {
  description = "Optional customer managed KMS key (ID, ARN or alias) to encrypt the alert topic. The detector is granted use of it."
  type        = string
  default     = null
}

variable "enforce_tls" {
  description = "Deny S3 and SNS requests that do not use TLS. Set to false only for local testing against LocalStack, which serves plain HTTP."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Allow `terraform destroy` to delete non-empty buckets. Keep false outside of demos."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Extra tags for every resource."
  type        = map(string)
  default     = {}
}
